extern crate libsodium_sys;

use libsodium_sys::*;
use std::mem;

#[test]
fn test_crypto_generichash_bytes_min() {
    assert_eq!(unsafe { crypto_generichash_bytes_min() },
                        crypto_generichash_BYTES_MIN as usize)
}

#[test]
fn test_crypto_generichash_bytes_max() {
    assert_eq!(unsafe { crypto_generichash_bytes_max() },
                        crypto_generichash_BYTES_MAX as usize)
}

#[test]
fn test_crypto_generichash_bytes() {
    assert_eq!(unsafe { crypto_generichash_bytes() },
                        crypto_generichash_BYTES as usize)
}

#[test]
fn test_crypto_generichash_keybytes_min() {
    assert_eq!(unsafe { crypto_generichash_keybytes_min() },
                        crypto_generichash_KEYBYTES_MIN as usize)
}

#[test]
fn test_crypto_generichash_keybytes_max() {
    assert_eq!(unsafe { crypto_generichash_keybytes_max() },
                        crypto_generichash_KEYBYTES_MAX as usize)
}

#[test]
fn test_crypto_generichash_keybytes() {
    assert_eq!(unsafe { crypto_generichash_keybytes() },
                        crypto_generichash_KEYBYTES as usize)
}
#[test]
fn test_crypto_generichash_primitive() {
    unsafe {
        let s = crypto_generichash_primitive();
        let s = std::ffi::CStr::from_ptr(s);
        let b = std::ffi::CStr::from_bytes_with_nul(crypto_generichash_PRIMITIVE).unwrap();
        assert_eq!(s, b);
    }
}

#[test]
fn test_crypto_generichash_statebytes() {
    assert!(unsafe { crypto_generichash_statebytes() } > 0);
}

#[test]
fn test_crypto_generichash() {
    let mut out = [0u8; crypto_generichash_BYTES as usize];
    let m = [0u8; 64];
    let key = [0u8; crypto_generichash_KEYBYTES as usize];

    assert_eq!(unsafe {
        crypto_generichash(
            out.as_mut_ptr(),
            out.len(),
            m.as_ptr(),
            m.len() as u64,
            key.as_ptr(),
            key.len()
        )
    }, 0);
}

#[test]
fn test_crypto_generichash_multipart() {
    let mut out = [0u8; crypto_generichash_BYTES as usize];
    let m = [0u8; 64];
    let key = [0u8; crypto_generichash_KEYBYTES as usize];

    let mut st = vec![0u8; (unsafe { crypto_generichash_statebytes() })];
    let pst = unsafe { mem::transmute::<*mut u8, *mut crypto_generichash_state>(st.as_mut_ptr()) };

    assert_eq!(unsafe {
        crypto_generichash_init(
            pst,
            key.as_ptr(),
            key.len(),
            out.len()
        )
    }, 0);

    assert_eq!(unsafe {
        crypto_generichash_update(
            pst,
            m.as_ptr(),
            m.len() as u64
        )
    }, 0);

    assert_eq!(unsafe {
        crypto_generichash_update(
            pst,
            m.as_ptr(),
            m.len() as u64
        )
    }, 0);

    assert_eq!(unsafe {
        crypto_generichash_final(
            pst,
            out.as_mut_ptr(),
            out.len()
        )
    }, 0);
}
