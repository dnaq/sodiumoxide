use std::{env, fs};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    for (key, value) in std::env::vars() {
        println!("{}: {}", key, value);
    }

    let target = env::var("TARGET").unwrap();

    // Skip the test when `SODIUM_LIB_DIR` is set since there is no
    // build metadata.
    if env::var("SODIUM_LIB_DIR").is_ok() {
        return;
    }

    let include = env::var("DEP_SODIUM_INCLUDE").unwrap();

    let header = fs::read_dir(include)
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name() == "sodium.h");
    assert!(
        header.is_some(),
        "sodium.h not found in DEP_SODIUM_INCLUDE dir"
    );

    let lib = env::var("DEP_SODIUM_LIB").unwrap();

    let file_name = if target.contains("msvc") {
        "libsodium.lib"
    } else {
        "libsodium.a"
    };

    let compiled_lib = fs::read_dir(lib)
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.file_name() == file_name);

    assert!(
        compiled_lib.is_some(),
        "compiled lib not found in DEP_SODIUM_LIB dir"
    );
}
