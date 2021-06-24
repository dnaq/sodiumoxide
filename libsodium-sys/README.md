> libsodium-sys

# Build output ENV Variables
This is the possible build metadata for the crate.
* `DEP_SODIUM_INCLUDE` is the directory which contains the `sodium.h` header.
    It is only available if the header was installed.
* `DEP_SODIUM_LIB` is the directory containing the compiled library.

See [`link build metadata`] for more information about build metadata.

[`link build metadata`]: https://doc.rust-lang.org/cargo/reference/build-scripts.html#the-links-manifest-key
