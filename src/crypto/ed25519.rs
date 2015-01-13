/*!
`ed25519`, a signature scheme specified in
[Ed25519](http://ed25519.cr.yp.to/). This function is conjectured to meet the
standard notion of unforgeability for a public-key signature scheme under
chosen-message attacks.
*/
#[cfg(test)]
extern crate serialize;
use ffi;
use libc::c_ulonglong;
use std::intrinsics::volatile_set_memory;
use std::iter::repeat;

pub const SEEDBYTES: usize = ffi::crypto_sign_ed25519_SEEDBYTES as usize;
pub const SECRETKEYBYTES: usize = ffi::crypto_sign_ed25519_SECRETKEYBYTES as usize;
pub const PUBLICKEYBYTES: usize = ffi::crypto_sign_ed25519_PUBLICKEYBYTES as usize;
pub const SIGNATUREBYTES: usize = ffi::crypto_sign_ed25519_BYTES as usize;


/**
 * `Seed` that can be used for keypair generation
 *
 * The `Seed` is used by `keypair_from_seed()` to generate
 * a secret and public signature key.
 *
 * When a `Seed` goes out of scope its contents
 * will be zeroed out
 */
pub struct Seed(pub [u8; SEEDBYTES]);

newtype_drop!(Seed);
newtype_clone!(Seed);
newtype_impl!(Seed, SEEDBYTES);

/**
 * `SecretKey` for signatures
 *
 * When a `SecretKey` goes out of scope its contents
 * will be zeroed out
 */
pub struct SecretKey(pub [u8; SECRETKEYBYTES]);

newtype_drop!(SecretKey);
newtype_clone!(SecretKey);
newtype_impl!(SecretKey, SECRETKEYBYTES);

/**
 * `PublicKey` for signatures
 */
#[derive(Copy)]
pub struct PublicKey(pub [u8; PUBLICKEYBYTES]);

newtype_clone!(PublicKey);
newtype_impl!(PublicKey, PUBLICKEYBYTES);

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
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        ffi::crypto_sign_ed25519_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        (PublicKey(pk), SecretKey(sk))
    }
}

/**
 * `keypair_from_seed()` computes a secret key and a corresponding public key
 * from a `Seed`.
 */
pub fn keypair_from_seed(&Seed(seed): &Seed) -> (PublicKey, SecretKey) {
    unsafe {
        let mut pk = [0u8; PUBLICKEYBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        ffi::crypto_sign_ed25519_seed_keypair(pk.as_mut_ptr(),
                                         sk.as_mut_ptr(),
                                         seed.as_ptr());
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
        let mut sm: Vec<u8> = repeat(0u8).take(m.len() + SIGNATUREBYTES).collect();
        let mut smlen = 0;
        ffi::crypto_sign_ed25519(sm.as_mut_ptr(),
                                 &mut smlen,
                                 m.as_ptr(),
                                 m.len() as c_ulonglong,
                                 sk.as_ptr());
        sm.truncate(smlen as usize);
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
        let mut m: Vec<u8> = repeat(0u8).take(sm.len()).collect();
        let mut mlen = 0;
        if ffi::crypto_sign_ed25519_open(m.as_mut_ptr(),
                                         &mut mlen,
                                         sm.as_ptr(),
                                         sm.len() as c_ulonglong,
                                         pk.as_ptr()) == 0 {
            m.truncate(mlen as usize);
            Some(m)
        } else {
            None
        }
    }
}

/**
 * `sign_detached()` signs a message `m` using the signer's secret key `sk`.
 * `sign_detached()` returns the resulting signature `sig`.
 */
pub fn sign_detached(m: &[u8],
                     &SecretKey(sk): &SecretKey) -> Vec<u8> {
    unsafe {
        let mut sig: Vec<u8> = repeat(0u8).take(SIGNATUREBYTES).collect();
        let mut siglen = 0;
        ffi::crypto_sign_ed25519_detached(sig.as_mut_ptr(),
                                          &mut siglen,
                                          m.as_ptr(),
                                          m.len() as c_ulonglong,
                                          sk.as_ptr());
        sig.truncate(siglen as usize);
        sig
    }
}

/**
 * `verify_detached()` verifies the signature in `sig` against the message `m`
 * and the signer's public key `pk`.
 * `verify_detached()` returns true if the signature is valid, false otherwise.
 */
pub fn verify_detached(sig: &[u8],
                       m: &[u8],
                       &PublicKey(pk): &PublicKey) -> bool {
    if sig.len() != SIGNATUREBYTES {
        return false;
    }

    unsafe {
        0 == ffi::crypto_sign_ed25519_verify_detached(sig.as_ptr(),
                                                      m.as_ptr(),
                                                      m.len() as c_ulonglong,
                                                      pk.as_ptr())
    }
}

#[test]
fn test_sign_verify() {
    use randombytes::randombytes;
    for i in (0..256us) {
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
    for i in (0..32us) {
        let (pk, sk) = gen_keypair();
        let m = randombytes(i);
        let mut smv = sign(m.as_slice(), &sk);
        let sm = smv.as_mut_slice();
        for j in (0..sm.len()) {
            sm[j] ^= 0x20;
            assert!(None == verify(sm, &pk));
            sm[j] ^= 0x20;
        }
    }
}

#[test]
fn test_sign_verify_detached() {
    use randombytes::randombytes;
    for i in (0..256us) {
        let (pk, sk) = gen_keypair();
        let m = randombytes(i);
        let sig = sign_detached(m.as_slice(), &sk);
        assert!(verify_detached(sig.as_slice(), m.as_slice(), &pk));
    }
}

#[test]
fn test_sign_verify_detached_tamper() {
    use randombytes::randombytes;
    for i in (0..32us) {
        let (pk, sk) = gen_keypair();
        let m = randombytes(i);
        let mut sigv = sign_detached(m.as_slice(), &sk);
        let sig = sigv.as_mut_slice();
        for j in (0..sig.len()) {
            sig[j] ^= 0x20;
            assert!(!verify_detached(sig, m.as_slice(), &pk));
            sig[j] ^= 0x20;
        }
    }
}

#[test]
fn test_sign_verify_seed() {
    use randombytes::{randombytes, randombytes_into};
    for i in (0..256us) {
        let mut seedbuf = [0; 32];
        randombytes_into(&mut seedbuf);
        let seed = Seed(seedbuf);
        let (pk, sk) = keypair_from_seed(&seed);
        let m = randombytes(i);
        let sm = sign(m.as_slice(), &sk);
        let m2 = verify(sm.as_slice(), &pk);
        assert!(Some(m) == m2);
    }
}

#[test]
fn test_sign_verify_tamper_seed() {
    use randombytes::{randombytes, randombytes_into};
    for i in (0..32us) {
        let mut seedbuf = [0; 32];
        randombytes_into(&mut seedbuf);
        let seed = Seed(seedbuf);
        let (pk, sk) = keypair_from_seed(&seed);
        let m = randombytes(i);
        let mut smv = sign(m.as_slice(), &sk);
        let sm = smv.as_mut_slice();
        for j in (0..sm.len()) {
            sm[j] ^= 0x20;
            assert!(None == verify(sm, &pk));
            sm[j] ^= 0x20;
        }
    }
}

#[test]
fn test_vectors() {
    // test vectors from the Python implementation
    // from the [Ed25519 Homepage](http://ed25519.cr.yp.to/software.html)
    use self::serialize::hex::{FromHex, ToHex};
    use std::io::BufferedReader;
    use std::io::File;
    use std::path::Path;

    let p = &Path::new("testvectors/ed25519.input");
    let mut r = BufferedReader::new(File::open(p).unwrap());
    loop {
        let line = match r.read_line() {
            Err(_) => break,
            Ok(line) => line
        };
        let mut x = line.as_slice().split(':');
        let x0 = x.next().unwrap();
        let x1 = x.next().unwrap();
        let x2 = x.next().unwrap();
        let x3 = x.next().unwrap();
        let seed_bytes = x0.slice(0, 64).from_hex().unwrap();
        assert!(seed_bytes.len() == SEEDBYTES);
        let mut seedbuf = [0u8; SEEDBYTES];
        for (s, b) in seedbuf.iter_mut().zip(seed_bytes.iter()) {
            *s = *b
        }
        let seed = Seed(seedbuf);
        let (pk, sk) = keypair_from_seed(&seed);
        let m = x2.from_hex().unwrap();
        let sm = sign(m.as_slice(), &sk);
        verify(sm.as_slice(), &pk).unwrap();
        let PublicKey(pkbuf) = pk;
        assert!(x1 == pkbuf.as_slice().to_hex().as_slice());
        assert!(x3 == sm.as_slice().to_hex().as_slice());
    }
}

#[cfg(test)]
mod bench {
    extern crate test;
    use randombytes::randombytes;
    use super::*;

    const BENCH_SIZES: [usize; 14] = [0, 1, 2, 4, 8, 16, 32, 64,
                                      128, 256, 512, 1024, 2048, 4096];

    #[bench]
    fn bench_sign(b: &mut test::Bencher) {
        let (_, sk) = gen_keypair();
        let ms: Vec<Vec<u8>> = BENCH_SIZES.iter().map(|s| {
            randombytes(*s)
        }).collect();
        b.iter(|| {
            for m in ms.iter() {
                sign(m.as_slice(), &sk);
            }
        });
    }

    #[bench]
    fn bench_verify(b: &mut test::Bencher) {
        let (pk, sk) = gen_keypair();
        let sms: Vec<Vec<u8>> = BENCH_SIZES.iter().map(|s| {
            let m = randombytes(*s);
            sign(m.as_slice(), &sk)
        }).collect();
        b.iter(|| {
            for sm in sms.iter() {
                verify(sm.as_slice(), &pk);
            }
        });
    }
}
