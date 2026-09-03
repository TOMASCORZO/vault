use core::{ffi::c_void, mem::size_of, ptr};
use std::{io, os::windows::ffi::OsStrExt, path::Path};
use zeroize::{Zeroize, Zeroizing};

use windows_sys::Win32::{
    Security::Cryptography::{
        BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
        MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_KEY_HANDLE,
        NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_OAEP_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
        NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey,
        NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty,
    },
    Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW},
    System::TpmBaseServices::{
        TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS,
        TBS_CONTEXT_VERSION_TWO, TBS_OWNERAUTH_TYPE_STORAGE_20, TBS_SUCCESS, TPM_DEVICE_INFO,
        TPM_VERSION_20, Tbsi_Context_Create, Tbsi_Get_OwnerAuth, Tbsi_GetDeviceInfo,
        Tbsip_Context_Close, Tbsip_Submit_Command,
    },
};

const TBS_INCLUDE_TPM20: u32 = 1 << 2;
const MAX_TPM_RESPONSE_BYTES: usize = 4_096;
const MAX_OWNER_AUTH_BYTES: usize = 64;
const RSA_KEY_BITS: u32 = 2_048;

/// Opaque failure at the Windows system boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsPlatformError;

/// TPM device properties returned by TBS without exposing native layouts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TbsDeviceInfo {
    /// TBS reports a TPM 2.0 device.
    pub is_tpm20: bool,
    /// Native TPM interface type.
    pub interface_type: u32,
    /// Native implementation revision.
    pub implementation_revision: u32,
}

/// Owned TPM Base Services context.
pub struct TbsContext {
    handle: *mut c_void,
}

impl TbsContext {
    /// Opens a TPM 2.0-only TBS context.
    pub fn open() -> Result<Self, WindowsPlatformError> {
        // TBS_CONTEXT_PARAMS2 is ABI-equivalent to these two u32 values. Using
        // a plain array avoids reading or writing the generated union.
        let parameters = [TBS_CONTEXT_VERSION_TWO, TBS_INCLUDE_TPM20];
        let mut handle = ptr::null_mut();
        // SAFETY: `parameters` has the documented TBS_CONTEXT_PARAMS2 layout,
        // `handle` is a valid out pointer, and both live for the call.
        let result = unsafe {
            Tbsi_Context_Create(
                parameters.as_ptr().cast::<TBS_CONTEXT_PARAMS>(),
                &mut handle,
            )
        };
        if result != TBS_SUCCESS || handle.is_null() {
            return Err(WindowsPlatformError);
        }
        Ok(Self { handle })
    }

    /// Submits one complete TPM command and returns one bounded response.
    pub fn submit(&mut self, command: &[u8]) -> Result<Vec<u8>, WindowsPlatformError> {
        let command_length = u32::try_from(command.len()).map_err(|_| WindowsPlatformError)?;
        let mut response = vec![0_u8; MAX_TPM_RESPONSE_BYTES];
        let mut response_length =
            u32::try_from(response.len()).map_err(|_| WindowsPlatformError)?;
        // SAFETY: the context is owned and live; both slices provide valid
        // pointers for their declared lengths; TBS writes at most the supplied
        // bounded response length.
        let result = unsafe {
            Tbsip_Submit_Command(
                self.handle,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                command_length,
                response.as_mut_ptr(),
                &mut response_length,
            )
        };
        if result != TBS_SUCCESS {
            return Err(WindowsPlatformError);
        }
        let response_length = usize::try_from(response_length).map_err(|_| WindowsPlatformError)?;
        if response_length > response.len() {
            return Err(WindowsPlatformError);
        }
        response.truncate(response_length);
        Ok(response)
    }

    /// Retrieves Windows-managed storage hierarchy authorization.
    ///
    /// Windows restricts this operation to an elevated provisioning process.
    /// The returned allocation is zeroized on drop and must never be logged.
    pub fn storage_owner_auth(&mut self) -> Result<Zeroizing<Vec<u8>>, WindowsPlatformError> {
        let mut authorization = Zeroizing::new(vec![0_u8; MAX_OWNER_AUTH_BYTES]);
        let mut length = u32::try_from(authorization.len()).map_err(|_| WindowsPlatformError)?;
        // SAFETY: the context is live and the writable allocation is valid for
        // the declared bounded length.
        let result = unsafe {
            Tbsi_Get_OwnerAuth(
                self.handle,
                TBS_OWNERAUTH_TYPE_STORAGE_20,
                authorization.as_mut_ptr(),
                &mut length,
            )
        };
        if result != TBS_SUCCESS {
            return Err(WindowsPlatformError);
        }
        let length = usize::try_from(length).map_err(|_| WindowsPlatformError)?;
        if length == 0 || length > authorization.len() {
            return Err(WindowsPlatformError);
        }
        authorization.truncate(length);
        Ok(authorization)
    }
}

impl Drop for TbsContext {
    fn drop(&mut self) {
        // SAFETY: this handle was returned by `Tbsi_Context_Create`, remains
        // owned by this value, and is closed exactly once here.
        let _ = unsafe { Tbsip_Context_Close(self.handle) };
    }
}

/// Non-exportable RSA key held by the Microsoft Platform Crypto Provider.
pub struct TpmRsaKey {
    provider: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
}

impl TpmRsaKey {
    /// Creates and finalizes a new user-scoped TPM key without overwrite.
    pub fn create(name: &str) -> Result<Self, WindowsPlatformError> {
        let provider = open_platform_provider()?;
        let key_name = wide_string(name)?;
        let mut key = 0;
        // SAFETY: provider, key output, and the NUL-terminated strings are valid.
        let create_result = unsafe {
            NCryptCreatePersistedKey(
                provider,
                &mut key,
                BCRYPT_RSA_ALGORITHM,
                key_name.as_ptr(),
                0,
                NCRYPT_SILENT_FLAG,
            )
        };
        if create_result != 0 || key == 0 {
            // SAFETY: provider was returned by NCryptOpenStorageProvider.
            let _ = unsafe { NCryptFreeObject(provider) };
            return Err(WindowsPlatformError);
        }

        let mut key_bits = RSA_KEY_BITS.to_ne_bytes();
        // SAFETY: key is valid and the property value points to one u32.
        let length_result = unsafe {
            NCryptSetProperty(
                key,
                NCRYPT_LENGTH_PROPERTY,
                key_bits.as_ptr(),
                u32::try_from(key_bits.len()).map_err(|_| WindowsPlatformError)?,
                NCRYPT_SILENT_FLAG,
            )
        };
        key_bits.zeroize();
        let mut export_policy = 0_u32.to_ne_bytes();
        // SAFETY: key is valid and zero explicitly forbids private-key export.
        let export_result = unsafe {
            NCryptSetProperty(
                key,
                NCRYPT_EXPORT_POLICY_PROPERTY,
                export_policy.as_ptr(),
                u32::try_from(export_policy.len()).map_err(|_| WindowsPlatformError)?,
                NCRYPT_SILENT_FLAG,
            )
        };
        export_policy.zeroize();
        // SAFETY: key is a live unfinalized key owned by this function.
        let finalize_result = unsafe { NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG) };
        if length_result != 0 || export_result != 0 || finalize_result != 0 {
            // SAFETY: deleting the failed new key prevents a partial key from
            // being reopened; the provider is independently freed.
            let _ = unsafe { NCryptDeleteKey(key, 0) };
            let _ = unsafe { NCryptFreeObject(provider) };
            return Err(WindowsPlatformError);
        }
        Ok(Self { provider, key })
    }

    /// Opens an existing user-scoped TPM key.
    pub fn open(name: &str) -> Result<Self, WindowsPlatformError> {
        let provider = open_platform_provider()?;
        let key_name = wide_string(name)?;
        let mut key = 0;
        // SAFETY: provider and output are valid and key_name is NUL-terminated.
        let result =
            unsafe { NCryptOpenKey(provider, &mut key, key_name.as_ptr(), 0, NCRYPT_SILENT_FLAG) };
        if result != 0 || key == 0 {
            // SAFETY: provider was returned by NCryptOpenStorageProvider.
            let _ = unsafe { NCryptFreeObject(provider) };
            return Err(WindowsPlatformError);
        }
        Ok(Self { provider, key })
    }

    /// Encrypts a short secret with RSA-OAEP-SHA256 inside the TPM provider.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, WindowsPlatformError> {
        crypt_with_key(self.key, plaintext, true)
    }

    /// Decrypts a short secret with RSA-OAEP-SHA256 inside the TPM provider.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, WindowsPlatformError> {
        crypt_with_key(self.key, ciphertext, false).map(Zeroizing::new)
    }

    /// Deletes this exact key after failed provisioning or isolated test use.
    pub fn delete(mut self) -> Result<(), WindowsPlatformError> {
        // SAFETY: the key is valid and exclusively owned. Success invalidates
        // the handle, which is cleared to prevent a second free in Drop.
        let result = unsafe { NCryptDeleteKey(self.key, 0) };
        if result != 0 {
            return Err(WindowsPlatformError);
        }
        self.key = 0;
        Ok(())
    }
}

impl Drop for TpmRsaKey {
    fn drop(&mut self) {
        if self.key != 0 {
            // SAFETY: key remains owned and is freed exactly once.
            let _ = unsafe { NCryptFreeObject(self.key) };
        }
        if self.provider != 0 {
            // SAFETY: provider remains owned and is freed exactly once.
            let _ = unsafe { NCryptFreeObject(self.provider) };
        }
    }
}

fn open_platform_provider() -> Result<NCRYPT_PROV_HANDLE, WindowsPlatformError> {
    let mut provider = 0;
    // SAFETY: provider output is valid and the provider constant is static.
    let result = unsafe {
        NCryptOpenStorageProvider(
            &mut provider,
            MS_PLATFORM_CRYPTO_PROVIDER,
            NCRYPT_SILENT_FLAG,
        )
    };
    if result != 0 || provider == 0 {
        return Err(WindowsPlatformError);
    }
    Ok(provider)
}

fn crypt_with_key(
    key: NCRYPT_KEY_HANDLE,
    input: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>, WindowsPlatformError> {
    let input_length = u32::try_from(input.len()).map_err(|_| WindowsPlatformError)?;
    let padding = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: ptr::null_mut(),
        cbLabel: 0,
    };
    let mut required = 0;
    // SAFETY: key and input are valid; null output performs the size query.
    let size_result = unsafe {
        if encrypt {
            NCryptEncrypt(
                key,
                input.as_ptr(),
                input_length,
                ptr::from_ref(&padding).cast(),
                ptr::null_mut(),
                0,
                &mut required,
                NCRYPT_PAD_OAEP_FLAG,
            )
        } else {
            NCryptDecrypt(
                key,
                input.as_ptr(),
                input_length,
                ptr::from_ref(&padding).cast(),
                ptr::null_mut(),
                0,
                &mut required,
                NCRYPT_PAD_OAEP_FLAG,
            )
        }
    };
    if size_result != 0 || required == 0 || required > 4_096 {
        return Err(WindowsPlatformError);
    }
    let mut output = vec![0_u8; usize::try_from(required).map_err(|_| WindowsPlatformError)?];
    let mut written = required;
    // SAFETY: input/output buffers and padding are valid for the call.
    let result = unsafe {
        if encrypt {
            NCryptEncrypt(
                key,
                input.as_ptr(),
                input_length,
                ptr::from_ref(&padding).cast(),
                output.as_mut_ptr(),
                required,
                &mut written,
                NCRYPT_PAD_OAEP_FLAG,
            )
        } else {
            NCryptDecrypt(
                key,
                input.as_ptr(),
                input_length,
                ptr::from_ref(&padding).cast(),
                output.as_mut_ptr(),
                required,
                &mut written,
                NCRYPT_PAD_OAEP_FLAG,
            )
        }
    };
    if result != 0 || written > required {
        output.zeroize();
        return Err(WindowsPlatformError);
    }
    output.truncate(usize::try_from(written).map_err(|_| WindowsPlatformError)?);
    Ok(output)
}

/// Queries the local TPM without opening a long-lived context.
pub fn tbs_device_info() -> Result<TbsDeviceInfo, WindowsPlatformError> {
    let mut native = TPM_DEVICE_INFO::default();
    // SAFETY: `native` is a valid writable TPM_DEVICE_INFO buffer and its exact
    // size is supplied to TBS.
    let result = unsafe {
        Tbsi_GetDeviceInfo(
            u32::try_from(size_of::<TPM_DEVICE_INFO>()).map_err(|_| WindowsPlatformError)?,
            ptr::from_mut(&mut native).cast(),
        )
    };
    if result != TBS_SUCCESS {
        return Err(WindowsPlatformError);
    }
    Ok(TbsDeviceInfo {
        is_tpm20: native.tpmVersion == TPM_VERSION_20,
        interface_type: native.tpmInterfaceType,
        implementation_revision: native.tpmImpRevision,
    })
}

/// Atomically replaces `destination` and requests write-through metadata.
pub fn replace_file_write_through(
    source: &Path,
    destination: &Path,
) -> Result<(), WindowsPlatformError> {
    let source = wide_path(source)?;
    let destination = wide_path(destination)?;
    // SAFETY: both vectors are NUL-terminated and live for the call. The flags
    // request replacement plus write-through completion from the filesystem.
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        let _ = io::Error::last_os_error();
        return Err(WindowsPlatformError);
    }
    Ok(())
}

fn wide_path(path: &Path) -> Result<Vec<u16>, WindowsPlatformError> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(WindowsPlatformError);
    }
    wide.push(0);
    Ok(wide)
}

fn wide_string(value: &str) -> Result<Vec<u16>, WindowsPlatformError> {
    let mut wide: Vec<u16> = value.encode_utf16().collect();
    if wide.contains(&0) {
        return Err(WindowsPlatformError);
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn real_tpm_key_round_trip_and_exact_cleanup() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("Vault-A1-CP1-WIN-test-{}-{nonce}", std::process::id());
        let key = TpmRsaKey::create(&name).unwrap();
        let plaintext = [0xA1; 32];
        let ciphertext = key.encrypt(&plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);
        assert_eq!(key.decrypt(&ciphertext).unwrap().as_slice(), plaintext);
        drop(key);

        let reopened = TpmRsaKey::open(&name).unwrap();
        assert_eq!(reopened.decrypt(&ciphertext).unwrap().as_slice(), plaintext);
        reopened.delete().unwrap();
        assert!(TpmRsaKey::open(&name).is_err());
    }

    #[test]
    fn tbs_reports_real_tpm20_and_accepts_read_only_command() {
        let info = tbs_device_info().unwrap();
        assert!(info.is_tpm20);
        let mut context = TbsContext::open().unwrap();
        let get_capability = [
            0x80, 0x01, 0, 0, 0, 0x16, 0, 0, 0x01, 0x7A, 0, 0, 0, 0x01, 0x01, 0, 0, 0, 0, 0, 0, 1,
        ];
        let response = context.submit(&get_capability).unwrap();
        assert!(response.len() >= 10);
        assert_eq!(&response[6..10], &[0, 0, 0, 0]);
    }
}
