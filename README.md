# sodiumoxide

|Crate|Documentation|Gitter|
|:---:|:-----------:|:--------:|:-----:|:------:|:----:|
|[![Crates.io][crates-badge]][crates-url]|[![Docs][doc-badge]][doc-url]|[![Gitter][gitter-badge]][gitter-url]|

[crates-badge]: https://img.shields.io/crates/v/sodiumoxide.svg
[crates-url]: https://crates.io/crates/sodiumoxide
[doc-badge]: https://docs.rs/sodiumoxide/badge.svg
[doc-url]: https://docs.rs/sodiumoxide
[gitter-badge]: https://badges.gitter.im/rust-sodiumoxide/Lobby.svg
[gitter-url]: https://gitter.im/rust-sodiumoxide/Lobby

> [NaCl](http://nacl.cr.yp.to) (pronounced "salt") is a new easy-to-use high-speed software library for network communication, encryption, decryption, signatures, etc. NaCl's goal is to provide all of the core operations needed to build higher-level cryptographic tools.
> Of course, other libraries already exist for these core operations. NaCl advances the state of the art by improving security, by improving usability, and by improving speed.

> [Sodium](https://github.com/jedisct1/libsodium) is a portable, cross-compilable, installable, packageable fork of NaCl (based on the latest released upstream version nacl-20110221), with a compatible API.

This package aims to provide a type-safe and efficient Rust binding that's just
as easy to use.
Rust >= 1.36.0 is required because of mem::MaybeUninit.

## Basic usage

### Cloning
```
git clone https://github.com/sodiumoxide/sodiumoxide.git
cd sodiumoxide
git submodule update --init --recursive
```

### Building
```
cargo build
```

### Testing
```
cargo test
```

### Documentation
```
cargo doc
```

Documentation will be generated in target/doc/...

Most documentation is taken from NaCl, with minor modification where the API
differs between the C and Rust versions.

### Support for the AES AEAD Variant

The AES AEAD variant `crypto_aead_aes256gcm` requires hardware support for the
`AES` and `CLMUL` instruction set extensions to x86; you can read why that's the
case
[here](https://doc.libsodium.org/secret-key_cryptography/aead/aes-256-gcm#limitations). These instruction set extensions were first made
available in Intel Westmere (early 2010) and at the time of writing x86 hardware
support for them is near universal.

Libsodium exposes an API for runtime feature detection and doesn't prevent
you from calling `crypto_aead_aes256gcm` on a machine lacking `AES` and
`CMUL` expressions; doing so will result in a runtime `SIGILL` (illegal
instruction). By contrast sodiumoxide exposes an API that precludes the use of
the `crypto_aead_aes256gcm_*` family of functions without performing the runtime
check. It's important to note that the use of `sodiumoxide::init()` is mandatory
when using AES; unless you call `init` calls `aead::aes256gcm::Aes256Gcm::new()`
will always return `Err(_)` even if your runtime hardware supports AES.

## Dependencies

C compiler (`cc`, `clang`, ...) must be installed in order to build libsodium from source.

## Extended usage

By default this project will try to find libsodium on your system and dynamically link to it.

There are several other ways you may want to use this crate:
* statically link it against an internally build snapshot of libsodium
* link it against a precompiled library that you built on your own

You can do this by setting environment variables.

|Name|Description|Example value|Notes|
| :- | :-------- | :---------- | :-- |
|`SODIUM_LIB_DIR`|Where to find a precompiled library|`/usr/lib/x86_64-linux-gnu/`|The value should be set to the directory containing `.so`,`.a`,`.la`,`.dll` or `.lib`|
|`SYSTEM_DEPS_LIBSODIUM_BUILD_INTERNAL`|Build the internal snapshot of libsodium and statically link to it|`always`||
|`SODIUM_DISABLE_PIE`|Build with `--disable-pie`|`1`|Certain situations may require building libsodium configured with `--disable-pie`. Useful for !Windows only and when building libsodium from source. We check only the presence|

### Examples on *nix

#### Using pkg-config

(Ubuntu: `apt install pkg-config`, OSX: `brew install pkg-config`, ...)

```
cargo build
```

#### Using precompiled library

See https://download.libsodium.org/doc/installation.

```
export SODIUM_LIB_DIR=/home/user/libsodium-1.0.18/release/lib/
cargo build
```

#### Using static snapshot

```
SYSTEM_DEPS_LIBSODIUM_BUILD_INTERNAL=always cargo build
```

## Optional features

Several [optional features](http://doc.crates.io/manifest.html#usage-in-end-products) are available:

* `std` (default: **enabled**). When this feature is disabled,
  sodiumoxide builds using `#![no_std]`. Some functionality may be lost.

* `serde` (default: **enabled**). Allows serialization and deserialization of
  keys, authentication tags, etc. using the
  [serde library](https://crates.io/crates/serde).

* `benchmarks` (default: **disabled**). Compile benchmark tests. Requires a
  nightly build of Rust.

## Cross-Compiling

### Cross-Compiling for armv7-unknown-linux-gnueabihf

1. Install dependencies and toolchain:

```
sudo apt update
sudo apt install build-essential gcc-arm-linux-gnueabihf libc6-armhf-cross libc6-dev-armhf-cross -y
rustup target add armv7-unknown-linux-gnueabihf
```

2. Add the following to a [.cargo/config file](http://doc.crates.io/config.html):

```
[target.armv7-unknown-linux-gnueabihf]
linker = "arm-linux-gnueabihf-gcc"
```

3. Build by running:

```
cargo build --release --target armv7-unknown-linux-gnueabihf
```

### Cross-Compiling for armv7-unknown-linux-musleabihf via docker

1. cargo.config:

```
[target.armv7-unknown-linux-musleabihf]
linker = "arm-buildroot-linux-musleabihf-gcc"
```

2. Dockerfile:

```
FROM rust:1.36.0

ENV TARGET="armv7-unknown-linux-musleabihf"

ARG TOOLCHAIN_ARM7="armv7-eabihf--musl--stable-2018.02-2"
ARG TC_ARM7_URL="https://toolchains.bootlin.com/downloads/releases/toolchains/armv7-eabihf/tarballs/${TOOLCHAIN_ARM7}.tar.bz2"

RUN rustup target add ${TARGET}
COPY cargo.config "${CARGO_HOME}/config"

WORKDIR /opt
RUN curl -o- ${TC_ARM7_URL} | tar -xjf -

ENV PATH="${PATH}:/opt/${TOOLCHAIN_ARM7}/bin"
ENV CC_armv7_unknown_linux_musleabihf=arm-buildroot-linux-musleabihf-gcc
ENV CXX_armv7_unknown_linux_musleabihf=arm-buildroot-linux-musleabihf-g++
ENV LD_armv7_unknown_linux_musleabihf=arm-buildroot-linux-musleabihf-ld

WORKDIR /work
RUN git clone https://github.com/sodiumoxide/sodiumoxide

WORKDIR /work/sodiumoxide
RUN cargo build --target=${TARGET}
```

### Cross-Compiling for 32-bit Linux

1. Install dependencies and toolchain:

```
sudo apt update
sudo apt install build-essential gcc-multilib -y
rustup target add i686-unknown-linux-gnu
```

2. Build by running:

```
cargo build --release --target i686-unknown-linux-gnu
```

## Examples

TBD

## Platform Compatibiility

Sodiumoxide has been tested on:

- Linux: Yes
- Windows: Yes (MSVC)
- Mac OS: Yes
- IOS: TODO
- Android: Yes


# Join in

File bugs in the issue tracker

Master git repository

    git clone https://github.com/sodiumoxide/sodiumoxide.git

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Go through the [CONTRIBUTING.md](https://github.com/sodiumoxide/sodiumoxide/blob/master/CONTRIBUTING.md) document to know more about how to contribute to this project.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

### Code of Conduct

We believe in creating an enabling community for developers and have laid out a general [code of conduct](https://github.com/sodiumoxide/sodiumoxide/blob/master/CODE_OF_CONDUCT.md). Please read and adopt it to help us achieve and maintain the desired community standards.
