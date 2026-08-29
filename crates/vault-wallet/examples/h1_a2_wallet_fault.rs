//! Opt-in black-box process-crash worker for H1-A2 wallet durability tests.
//!
//! The companion shell controller kills this process only after observing the
//! SQLite rollback journal. All keys and blocks are public synthetic fixtures.

use std::{env, fs, path::PathBuf, process};

use vault_wallet::{EncryptedWalletDb, FinalizedWalletStore};

mod support;

use support::{MAX_BLOCKS, SyntheticWalletFixture, chain_id, create_database, root_key, wallet_id};

const DATABASE_NAME: &str = "wallet-fault.sqlite3";

enum Command {
    Init { max_checkpoints: usize },
    WriteLoop { blocks: u64, actions: usize },
    Validate,
    Backup { pressure_target: bool },
    Restore,
    Compact,
}

fn parse() -> Result<(PathBuf, Command), &'static str> {
    let mut args = env::args().skip(1);
    let operation = args.next().ok_or("operation is required")?;
    let mut directory = None;
    let mut blocks = 1_000_000;
    let mut actions = 16;
    let mut max_checkpoints = 100;
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
            "--actions-per-block" => {
                actions = args
                    .next()
                    .ok_or("--actions-per-block requires a value")?
                    .parse()
                    .map_err(|_| "invalid --actions-per-block")?;
            }
            "--max-checkpoints" => {
                max_checkpoints = args
                    .next()
                    .ok_or("--max-checkpoints requires a value")?
                    .parse()
                    .map_err(|_| "invalid --max-checkpoints")?;
            }
            _ => return Err("unknown argument"),
        }
    }
    if blocks == 0
        || blocks > MAX_BLOCKS
        || max_checkpoints == 0
        || max_checkpoints > 4_096
        || ![2, 4, 8, 16].contains(&actions)
    {
        return Err("fault parameters outside fixed bounds");
    }
    let command = match operation.as_str() {
        "init" => Command::Init { max_checkpoints },
        "write-loop" => Command::WriteLoop { blocks, actions },
        "validate" => Command::Validate,
        "backup" => Command::Backup {
            pressure_target: false,
        },
        "backup-pressure" => Command::Backup {
            pressure_target: true,
        },
        "restore" => Command::Restore,
        "compact" => Command::Compact,
        _ => return Err("unknown operation"),
    };
    Ok((directory.ok_or("--directory is required")?, command))
}

fn main() {
    let (directory, command) = parse().unwrap_or_else(|error| {
        eprintln!(
            "{error}; usage: h1_a2_wallet_fault init|write-loop|validate|backup|backup-pressure|restore|compact --directory ABSOLUTE [--blocks 1..1000000] [--max-checkpoints 1..4096] [--actions-per-block 2|4|8|16]"
        );
        process::exit(2);
    });
    let directory = fs::canonicalize(directory).unwrap_or_else(|_| {
        eprintln!("fault directory must exist and be canonical");
        process::exit(2);
    });
    let database_path = directory.join(DATABASE_NAME);
    match command {
        Command::Init { max_checkpoints } => {
            if database_path.exists() {
                eprintln!("fault worker refuses to overwrite its database");
                process::exit(2);
            }
            let database = create_database(&database_path, max_checkpoints);
            println!(
                "initialized height={}",
                database.load_tip().unwrap().height()
            );
        }
        Command::WriteLoop { blocks, actions } => {
            let mut database =
                EncryptedWalletDb::open(&database_path, root_key(), chain_id(), wallet_id(), 0)
                    .unwrap();
            let fixture = SyntheticWalletFixture::new(false);
            for _ in 0..blocks {
                let tip = database.load_tip().unwrap();
                let height = tip.height().checked_add(1).unwrap();
                let update = fixture.next_update(&tip, height, actions);
                database.commit_finalized_block(update).unwrap();
            }
            println!(
                "write_complete height={}",
                database.load_tip().unwrap().height()
            );
        }
        Command::Validate => {
            let database =
                EncryptedWalletDb::open(&database_path, root_key(), chain_id(), wallet_id(), 0)
                    .unwrap();
            println!("validated height={}", database.load_tip().unwrap().height());
        }
        Command::Backup { pressure_target } => {
            let database =
                EncryptedWalletDb::open(&database_path, root_key(), chain_id(), wallet_id(), 0)
                    .unwrap();
            let name = if pressure_target {
                "wallet-fault-pressure.vwb"
            } else {
                "wallet-fault.vwb"
            };
            let summary = database
                .export_backup(&directory.join(name), root_key())
                .unwrap();
            println!(
                "backup_complete height={} bytes={}",
                summary.finalized_height(),
                summary.backup_bytes()
            );
        }
        Command::Restore => {
            let restored = EncryptedWalletDb::restore_backup(
                &directory.join("wallet-fault.vwb"),
                &directory.join("wallet-fault-restored.sqlite3"),
                root_key(),
                chain_id(),
                wallet_id(),
                0,
            )
            .unwrap();
            println!(
                "restore_complete height={}",
                restored.load_tip().unwrap().height()
            );
        }
        Command::Compact => {
            let mut database =
                EncryptedWalletDb::open(&database_path, root_key(), chain_id(), wallet_id(), 0)
                    .unwrap();
            let summary = database.compact().unwrap();
            println!(
                "compact_complete before_bytes={} after_bytes={}",
                summary.before_bytes(),
                summary.after_bytes()
            );
        }
    }
}
