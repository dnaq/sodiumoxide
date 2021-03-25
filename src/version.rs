//! Libsodium version functions

use ffi;

use std::slice;
use std::str;

/// `version_string()` returns the version string from libsodium.
pub fn version_string() -> &'static str {
    // Use custom strlen because CStr isn't available with #![no_std] :(
    let version = unsafe {
        let version_ptr = ffi::sodium_version_string() as *const u8;
        let version_len = strlen(version_ptr);
        slice::from_raw_parts(version_ptr as *const u8, version_len as usize)
    };
    str::from_utf8(version).unwrap()
}

unsafe fn strlen(d: *const u8) -> usize {
    let mut c = 0;

    while *d.offset(c) != b'\0' {
        c += 1;
    }

    c as usize
}

/// `version_major()` returns the major version from libsodium.
pub fn version_major() -> usize {
    unsafe { ffi::sodium_library_version_major() as usize }
}

/// `version_minor()` returns the minor version from libsodium.
pub fn version_minor() -> usize {
    unsafe { ffi::sodium_library_version_minor() as usize }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_version_string() {
        use version::version_string;
        assert!(!version_string().is_empty());
    }
}
