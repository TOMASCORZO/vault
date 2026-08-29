//! Opt-in H1-A2 wallet history, backup, restore, and compaction harness.
//!
//! All keys and blocks are deterministic synthetic fixtures. This executable
//! must never be used with real seed material or a live wallet directory.

use std::{env, fs, path::PathBuf, process, time::Instant};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use rusqlite::{Connection, OpenFlags};
use vault_wallet::{EncryptedWalletDb, FinalizedWalletStore};

mod support;

use support::{MAX_BLOCKS, SyntheticWalletFixture, chain_id, create_database, root_key, wallet_id};

struct Config {
    directory: PathBuf,
    blocks: u64,
    max_checkpoints: usize,
    actions_per_block: usize,
    owns_outputs: bool,
}

impl Config {
    fn parse() -> Result<Self, &'static str> {
        let mut directory = None;
        let mut blocks = 10_000;
        let mut max_checkpoints = 100;
        let mut actions_per_block = 2;
        let mut owns_outputs = false;
        let mut args = env::args().skip(1);
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--directory" => {
                    directory = Some(PathBuf::from(
                        args.next().ok_or("--directory requires a value")?,
                    ));
                }
                "--blocks" => {
                    blocks = args
                        .next()
                        .ok_or("--blocks requires a value")?
                        .parse()
                        .map_err(|_| "invalid --blocks")?;
                }
                "--max-checkpoints" => {
                    max_checkpoints = args
                        .next()
                        .ok_or("--max-checkpoints requires a value")?
                        .parse()
                        .map_err(|_| "invalid --max-checkpoints")?;
                }
                "--actions-per-block" => {
                    actions_per_block = args
                        .next()
                        .ok_or("--actions-per-block requires a value")?
                        .parse()
                        .map_err(|_| "invalid --actions-per-block")?;
                }
                "--ownership" => {
                    owns_outputs = match args.next().as_deref() {
                        Some("unrelated") => false,
                        Some("owned") => true,
                        _ => return Err("--ownership must be unrelated or owned"),
                    };
                }
                _ => return Err("unknown argument"),
            }
        }
        if blocks == 0
            || blocks > MAX_BLOCKS
            || max_checkpoints == 0
            || max_checkpoints > 4_096
            || ![2, 4, 8, 16].contains(&actions_per_block)
        {
            return Err("history parameters outside fixed bounds");
        }
        Ok(Self {
            directory: directory.ok_or("--directory is required")?,
            blocks,
            max_checkpoints,
            actions_per_block,
            owns_outputs,
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn main() {
    let config = Config::parse().unwrap_or_else(|error| {
        eprintln!(
            "{error}; usage: h1_a2_wallet_history --directory ABSOLUTE [--blocks 1..1000000] [--max-checkpoints 1..4096] [--actions-per-block 2|4|8|16] [--ownership unrelated|owned]"
        );
        process::exit(2);
    });
    let directory = fs::canonicalize(&config.directory).unwrap_or_else(|_| {
        eprintln!("history directory must exist and be canonical");
        process::exit(2);
    });
    let database_path = directory.join("wallet-history.sqlite3");
    let backup_path = directory.join("wallet-history.vwb");
    let copy_path = directory.join("wallet-history-copy.vwb");
    if [&database_path, &backup_path, &copy_path]
        .iter()
        .any(|path| path.exists())
    {
        eprintln!("history harness refuses to overwrite existing artifacts");
        process::exit(2);
    }

    println!(
        "h1_a2_wallet_history blocks={} max_checkpoints={} actions_per_block={} ownership={} synthetic_keys=true",
        config.blocks,
        config.max_checkpoints,
        config.actions_per_block,
        if config.owns_outputs {
            "owned"
        } else {
            "unrelated"
        }
    );
    let mut database = create_database(&database_path, config.max_checkpoints);
    let fixture = SyntheticWalletFixture::new(config.owns_outputs);
    let started = Instant::now();
    let progress_interval = (config.blocks / 100).max(1);
    for height in 1..=config.blocks {
        let tip = database.load_tip().unwrap();
        let update = fixture.next_update(&tip, height, config.actions_per_block);
        database.commit_finalized_block(update).unwrap();
        if height % progress_interval == 0 || height == config.blocks {
            println!(
                "progress height={height} elapsed_seconds={:.3} database_bytes={}",
                started.elapsed().as_secs_f64(),
                fs::metadata(&database_path).unwrap().len()
            );
        }
    }
    let history_seconds = started.elapsed().as_secs_f64();
    let tip = database.load_tip().unwrap();
    assert_eq!(tip.height(), config.blocks);

    let backup_started = Instant::now();
    let receipt = database.export_backup(&backup_path, root_key()).unwrap();
    println!(
        "backup id={} digest={} height={} snapshot_bytes={} backup_bytes={} elapsed_seconds={:.3}",
        hex(&receipt.backup_id()),
        hex(&receipt.backup_digest()),
        receipt.finalized_height(),
        receipt.snapshot_bytes(),
        receipt.backup_bytes(),
        backup_started.elapsed().as_secs_f64()
    );
    fs::copy(&backup_path, &copy_path).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&copy_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(receipt.verify_copy(&copy_path).unwrap());

    let drill_started = Instant::now();
    let drill = EncryptedWalletDb::drill_backup_restore(
        &copy_path,
        &directory,
        root_key(),
        chain_id(),
        wallet_id(),
        config.blocks,
    )
    .unwrap();
    println!(
        "restore_drill height={} restored_database_bytes={} elapsed_seconds={:.3}",
        drill.finalized_height(),
        drill.restored_database_bytes(),
        drill_started.elapsed().as_secs_f64()
    );

    let compact_started = Instant::now();
    let compaction = database.compact().unwrap();
    println!(
        "compaction before_bytes={} after_bytes={} before_pages={} after_pages={} reclaimed_pages={} elapsed_seconds={:.3}",
        compaction.before_bytes(),
        compaction.after_bytes(),
        compaction.before_pages(),
        compaction.after_pages(),
        compaction.reclaimed_pages(),
        compact_started.elapsed().as_secs_f64()
    );
    assert_eq!(database.load_tip().unwrap(), tip);
    drop(database);

    let metrics =
        Connection::open_with_flags(&database_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let checkpoint_rows: i64 = metrics
        .query_row("SELECT count(*) FROM tree_checkpoints", [], |row| {
            row.get(0)
        })
        .unwrap();
    let retained_rows: i64 = metrics
        .query_row(
            "SELECT count(*) FROM tree_retained_checkpoints",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let shard_rows: i64 = metrics
        .query_row("SELECT count(*) FROM tree_shards", [], |row| row.get(0))
        .unwrap();
    let note_rows: i64 = metrics
        .query_row("SELECT count(*) FROM wallet_notes", [], |row| row.get(0))
        .unwrap();
    let page_count: i64 = metrics
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .unwrap();
    let freelist_count: i64 = metrics
        .query_row("PRAGMA freelist_count", [], |row| row.get(0))
        .unwrap();
    drop(metrics);
    assert_eq!(
        checkpoint_rows,
        i64::try_from(config.blocks.min(config.max_checkpoints as u64)).unwrap()
    );
    assert_eq!(retained_rows, 0);
    assert_eq!(
        note_rows,
        if config.owns_outputs {
            i64::try_from(config.blocks).unwrap() * i64::try_from(config.actions_per_block).unwrap()
        } else {
            0
        }
    );
    assert_eq!(freelist_count, 0);
    println!(
        "final history_seconds={history_seconds:.3} database_bytes={} checkpoint_rows={checkpoint_rows} retained_checkpoint_rows={retained_rows} shard_rows={shard_rows} note_rows={note_rows} page_count={page_count} freelist_count={freelist_count}",
        fs::metadata(&database_path).unwrap().len()
    );
    let reopened = EncryptedWalletDb::open(
        &database_path,
        root_key(),
        chain_id(),
        wallet_id(),
        config.blocks,
    )
    .unwrap();
    assert_eq!(reopened.load_tip().unwrap(), tip);
}
