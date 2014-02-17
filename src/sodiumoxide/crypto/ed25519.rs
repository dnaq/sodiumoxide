/*!
`ed25519`, a signature scheme specified in
[Ed25519](http://ed25519.cr.yp.to/). This function is conjectured to meet the
standard notion of unforgeability for a public-key signature scheme under
chosen-message attacks.
*/
extern crate extra;
use std::libc::{c_ulonglong, c_int};
use std::vec::{from_elem};

#[link(name = "sodium")]
extern {
    fn crypto_sign_ed25519_keypair(pk: *mut u8,
                                   sk: *mut u8) -> c_int;
    fn crypto_sign_ed25519_seed_keypair(pk: *mut u8,
                                        sk: *mut u8,
                                        seed: *u8) -> c_int;
    fn crypto_sign_ed25519(sm: *mut u8,
                           smlen: *mut c_ulonglong,
                           m: *u8,
                           mlen: c_ulonglong,
                           sk: *u8) -> c_int;
    fn crypto_sign_ed25519_open(m: *mut u8,
                                mlen: *mut c_ulonglong,
                                sm: *u8,
                                smlen: c_ulonglong,
                                pk: *u8) -> c_int;
}

pub static SEEDBYTES: uint = 32;
pub static SECRETKEYBYTES: uint = 64;
pub static PUBLICKEYBYTES: uint = 32;
pub static SIGNATUREBYTES: uint = 64;

/**
 * `Seed` that can be used for keypair generation
 *
 * The `Seed` is used by `keypair_from_seed()` to generate
 * a secret and public signature key.
 *
 * When a `Seed` goes out of scope its contents
 * will be zeroed out
 */
pub struct Seed([u8, ..SEEDBYTES]);
impl Drop for Seed {
    fn drop(&mut self) {
        let &Seed(ref mut s) = self;
        for e in s.mut_iter() { *e = 0 }
    }
}

/**
 * `SecretKey` for signatures
 *
 * When a `SecretKey` goes out of scope its contents
 * will be zeroed out
 */
pub struct SecretKey([u8, ..SECRETKEYBYTES]);
impl Drop for SecretKey {
    fn drop(&mut self) {
        let &SecretKey(ref mut sk) = self;
        for e in sk.mut_iter() { *e = 0 }
    }
}
/**
 * `PublicKey` for signatures
 */
pub struct PublicKey([u8, ..PUBLICKEYBYTES]);

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
        crypto_sign_ed25519_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        (PublicKey(pk), SecretKey(sk))
    }
}

/**
 * `keypair_from_seed()` computes a secret key and a corresponding public key
 * from a `Seed`.
 */
pub fn keypair_from_seed(&Seed(seed): &Seed) -> (PublicKey, SecretKey) {
    unsafe {
        let mut pk = [0u8, ..PUBLICKEYBYTES];
        let mut sk = [0u8, ..SECRETKEYBYTES];
        crypto_sign_ed25519_seed_keypair(pk.as_mut_ptr(),
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
            &SecretKey(sk): &SecretKey) -> ~[u8] {
    unsafe {
        let mut sm = from_elem(m.len() + SIGNATUREBYTES, 0u8);
        let mut smlen = 0;
        crypto_sign_ed25519(sm.as_mut_ptr(),
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
              &PublicKey(pk): &PublicKey) -> Option<~[u8]> {
    unsafe {
        let mut m = from_elem(sm.len(), 0u8);
        let mut mlen = 0;
        if crypto_sign_ed25519_open(m.as_mut_ptr(),
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
    for i in range(0, 256) {
        let (pk, sk) = gen_keypair();
        let m = randombytes(i as uint);
        let sm = sign(m, &sk);
        let m2 = verify(sm, &pk);
        assert!(Some(m) == m2);
    }
}

#[test]
fn test_sign_verify_tamper() {
    use randombytes::randombytes;
    for i in range(0, 32) {
        let (pk, sk) = gen_keypair();
        let m = randombytes(i as uint);
        let mut sm = sign(m, &sk);
        for j in range(0, sm.len()) {
            sm[j] ^= 0x20;
            assert!(None == verify(sm, &pk));
            sm[j] ^= 0x20;
        }
    }
}

#[test]
fn test_sign_verify_seed() {
    use randombytes::{randombytes, randombytes_into};
    for i in range(0, 256) {
        let mut seedbuf = [0, ..32];
        randombytes_into(seedbuf);
        let seed = Seed(seedbuf);
        let (pk, sk) = keypair_from_seed(&seed);
        let m = randombytes(i as uint);
        let sm = sign(m, &sk);
        let m2 = verify(sm, &pk);
        assert!(Some(m) == m2);
    }
}

#[test]
fn test_sign_verify_tamper_seed() {
    use randombytes::{randombytes, randombytes_into};
    for i in range(0, 32) {
        let mut seedbuf = [0, ..32];
        randombytes_into(seedbuf);
        let seed = Seed(seedbuf);
        let (pk, sk) = keypair_from_seed(&seed);
        let m = randombytes(i as uint);
        let mut sm = sign(m, &sk);
        for j in range(0, sm.len()) {
            sm[j] ^= 0x20;
            assert!(None == verify(sm, &pk));
            sm[j] ^= 0x20;
        }
    }
}

#[test]
fn test_vectors() {
    // test vectors from the Python implementation
    // form the [Ed25519 Homepage](http://ed25519.cr.yp.to/software.html)
    use self::serialize::hex::{FromHex, ToHex};
    use std::io::buffered::BufferedReader;
    use std::io::File;
    use std::path::Path;

    let p = &Path::new("testvectors/ed25519.input");
    let mut r = BufferedReader::new(File::open(p).unwrap());
    loop {
        let line = match r.read_line() {
            None => break,
            Some(line) => line
        };
        let mut x = line.split(':');
        let x0 = x.next().unwrap();
        let x1 = x.next().unwrap();
        let x2 = x.next().unwrap();
        let x3 = x.next().unwrap();
        let seed_bytes = x0.slice(0, 64).from_hex().unwrap();
        assert!(seed_bytes.len() == SEEDBYTES);
        let mut seedbuf = [0u8, ..SEEDBYTES];
        for (s, b) in seedbuf.mut_iter().zip(seed_bytes.iter()) {
            *s = *b
        }
        let seed = Seed(seedbuf);
        let (pk, sk) = keypair_from_seed(&seed);
        let m = x2.from_hex().unwrap();
        let sm = sign(m, &sk);
        verify(sm, &pk).unwrap();
        let PublicKey(pkbuf) = pk;
        assert!(x1 == pkbuf.to_hex());
        assert!(x3 == sm.to_hex());
    }
}
