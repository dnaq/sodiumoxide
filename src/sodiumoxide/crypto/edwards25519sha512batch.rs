/*!
WARNING: This signature software is a prototype. It has been replaced by the final system
[Ed25519](http://ed25519.cr.yp.to/). It is only kept here for compatibility reasons.
*/
use libc::{c_ulonglong, c_int, c_void};
use libc::types::os::arch::c95::size_t;

#[link(name = "sodium")]
extern {
    fn crypto_sign_edwards25519sha512batch_keypair(pk: *mut u8,
                                                   sk: *mut u8) -> c_int;
    fn crypto_sign_edwards25519sha512batch(sm: *mut u8,
                                           smlen: *mut c_ulonglong,
                                           m: *const u8,
                                           mlen: c_ulonglong,
                                           sk: *const u8) -> c_int;
    fn crypto_sign_edwards25519sha512batch_open(m: *mut u8,
                                                mlen: *mut c_ulonglong,
                                                sm: *const u8,
                                                smlen: c_ulonglong,
                                                pk: *const u8) -> c_int;
    fn sodium_memzero(pnt: *const c_void, size: size_t);
}

pub static SECRETKEYBYTES: uint = 64;
pub static PUBLICKEYBYTES: uint = 32;
pub static SIGNATUREBYTES: uint = 64;

/**
 * `SecretKey` for signatures
 *
 * When a `SecretKey` goes out of scope its contents
 * will be zeroed out
 */
pub struct SecretKey(pub [u8, ..SECRETKEYBYTES]);
impl Drop for SecretKey {
    fn drop(&mut self) {
        let &SecretKey(ref mut buf) = self;
        unsafe {
            sodium_memzero(buf.as_ptr() as *const c_void,
                           buf.len() as size_t);
        }
    }
}
/**
 * `PublicKey` for signatures
 */
pub struct PublicKey(pub [u8, ..PUBLICKEYBYTES]);

/**
 * `gen_keypair()` randomly generates a secret key and a corresponding public
 * key.
 *
 * THREAD SAFETY: `gen_keypair()` is thread-safe provided that you have
 * called `sodiumoxide::init()` once before using any other function
 * from sodiumoxide.
 */
pub fn gen_keypair() -> (PublicKey, SecretKey) {
    unsafe {
        let mut pk = [0u8, ..PUBLICKEYBYTES];
        let mut sk = [0u8, ..SECRETKEYBYTES];
        crypto_sign_edwards25519sha512batch_keypair(pk.as_mut_ptr(),
                                                    sk.as_mut_ptr());
        (PublicKey(pk), SecretKey(sk))
    }
}

/**
 * `sign()` signs a message `m` using the signer's secret key `sk`.
 * `sign()` returns the resulting signed message `sm`.
 */
pub fn sign(m: &[u8],
            &SecretKey(sk): &SecretKey) -> Vec<u8> {
    unsafe {
        let mut sm = Vec::from_elem(m.len() + SIGNATUREBYTES, 0u8);
        let mut smlen = 0;
        crypto_sign_edwards25519sha512batch(sm.as_mut_ptr(),
                                            &mut smlen,
                                            m.as_ptr(),
                                            m.len() as c_ulonglong,
                                            sk.as_ptr());
        sm.truncate(smlen as uint);
        sm
    }
}

/**
 * `verify()` verifies the signature in `sm` using the signer's public key `pk`.
 * `verify()` returns the message `Some(m)`.
 * If the signature fails verification, `verify()` returns `None`.
 */
pub fn verify(sm: &[u8],
              &PublicKey(pk): &PublicKey) -> Option<Vec<u8>> {
    unsafe {
        let mut m = Vec::from_elem(sm.len(), 0u8);
        let mut mlen = 0;
        if crypto_sign_edwards25519sha512batch_open(m.as_mut_ptr(),
                                                    &mut mlen,
                                                    sm.as_ptr(),
                                                    sm.len() as c_ulonglong,
                                                    pk.as_ptr()) == 0 {
            m.truncate(mlen as uint);
            Some(m)
        } else {
            None
        }
    }
}

#[test]
fn test_sign_verify() {
    use randombytes::randombytes;
    for i in range(0, 256u) {
        let (pk, sk) = gen_keypair();
        let m = randombytes(i);
        let sm = sign(m.as_slice(), &sk);
        let m2 = verify(sm.as_slice(), &pk);
        assert!(Some(m) == m2);
    }
}

#[test]
fn test_sign_verify_tamper() {
    use randombytes::randombytes;
    for i in range(0, 32u) {
        let (pk, sk) = gen_keypair();
        let m = randombytes(i);
        let mut smv = sign(m.as_slice(), &sk);
        let sm = smv.as_mut_slice();
        for j in range(0, sm.len()) {
            sm[j] ^= 0x20;
            assert!(None == verify(sm, &pk));
            sm[j] ^= 0x20;
        }
    }
}
