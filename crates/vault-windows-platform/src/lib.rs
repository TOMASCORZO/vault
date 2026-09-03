//! Narrow, reviewed Windows FFI boundary for Vault.
//!
//! Higher-level crates remain `unsafe`-free. This crate exposes only bounded
//! TPM Base Services submission, non-exportable Platform Crypto Provider keys,
//! TPM device discovery, and write-through replacement.

#![cfg_attr(not(target_os = "windows"), allow(dead_code))]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::{
    TbsContext, TbsDeviceInfo, TpmRsaKey, WindowsPlatformError, replace_file_write_through,
    tbs_device_info,
};
