#![macro_escape]
macro_rules! auth_module (($auth_name:ident, 
                           $verify_name:ident, 
                           $verify_fn:ident, 
                           $keybytes:expr, 
                           $tagbytes:expr) => (

#[link(name = "sodium")]
extern {
    fn $auth_name(a: *mut u8,
                  m: *const u8,
                  mlen: c_ulonglong,
                  k: *const u8) -> c_int;
    fn $verify_name(a: *const u8,
                    m: *const u8,
                    mlen: c_ulonglong,
                    k: *const u8) -> c_int;
    fn sodium_memzero(pnt: *const c_void, size: size_t);
}

pub static KEYBYTES: uint = $keybytes;
pub static TAGBYTES: uint = $tagbytes;

/**
 * Authentication `Key`
 *
 * When a `Key` goes out of scope its contents
 * will be zeroed out
 */
pub struct Key(pub [u8, ..KEYBYTES]);

impl Drop for Key {
    fn drop(&mut self) {
        let &Key(ref mut k) = self;
        unsafe {
            sodium_memzero(k.as_ptr() as *const c_void,
                           k.len() as size_t);
        }
    }
}

/**
  * Authentication `Tag`
  *
  * The tag implements the traits `PartialEq` and `Eq` using constant-time
  * comparison functions. See `sodiumoxide::crypto::verify::verify_32`
  */
pub struct Tag(pub [u8, ..TAGBYTES]);
impl Eq for Tag {}
impl PartialEq for Tag {
    fn eq(&self, &Tag(other): &Tag) -> bool {
        let &Tag(ref tag) = self;
        $verify_fn(tag, &other)
    }
}

/**
 * `gen_key()` randomly generates a key for authentication
 *
 * THREAD SAFETY: `gen_key()` is thread-safe provided that you have
 * called `sodiumoxide::init()` once before using any other function
 * from sodiumoxide.
 */
pub fn gen_key() -> Key {
    let mut k = [0, ..KEYBYTES];
    randombytes_into(k);
    Key(k)
}

/**
 * `authenticate()` authenticates a message `m` using a secret key `k`.
 * The function returns an authenticator tag.
 */
pub fn authenticate(m: &[u8],
                    &Key(k): &Key) -> Tag {
    unsafe {
        let mut tag = [0, ..TAGBYTES];
        $auth_name(tag.as_mut_ptr(),
                   m.as_ptr(),
                   m.len() as c_ulonglong,
                   k.as_ptr());
        Tag(tag)
    }
}

/**
 * `verify()` returns `true` if `tag` is a correct authenticator of message `m`
 * under a secret key `k`. Otherwise it returns false.
 */
pub fn verify(&Tag(tag): &Tag, m: &[u8],
              &Key(k): &Key) -> bool {
    unsafe {
        $verify_name(tag.as_ptr(),
                     m.as_ptr(),
                     m.len() as c_ulonglong,
                     k.as_ptr()) == 0
    }
}

#[test]
fn test_auth_verify() {
    use randombytes::randombytes;
    for i in range(0, 256u) {
        let k = gen_key();
        let m = randombytes(i);
        let tag = authenticate(m.as_slice(), &k);
        assert!(verify(&tag, m.as_slice(), &k));
    }
}

#[test]
fn test_auth_verify_tamper() {
    use randombytes::randombytes;
    for i in range(0, 32u) {
        let k = gen_key();
        let mut mv = randombytes(i);
        let m = mv.as_mut_slice();
        let Tag(mut tagbuf) = authenticate(m.as_slice(), &k);
        for j in range(0, m.len()) {
            m[j] ^= 0x20;
            assert!(!verify(&Tag(tagbuf), m.as_slice(), &k));
            m[j] ^= 0x20;
        }
        for j in range(0, tagbuf.len()) {
            tagbuf[j] ^= 0x20;
            assert!(!verify(&Tag(tagbuf), m, &k));
            tagbuf[j] ^= 0x20;
        }
    }
}

))
