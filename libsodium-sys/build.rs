extern crate cc;

#[cfg(not(target_env = "msvc"))]
extern crate pkg_config;

#[cfg(target_env = "msvc")]
extern crate vcpkg;

use std::env;
use std::fs;
use std::str;
use std::path::{Path, PathBuf};
use std::process::Command;

static VERSION: &'static str = "1.0.16";

fn main() {
    println!("cargo:rerun-if-env-changed=SODIUM_LIB_DIR");
    println!("cargo:rerun-if-env-changed=SODIUM_SHARED");
    println!("cargo:rerun-if-env-changed=SODIUM_USE_PKG_CONFIG");

    if cfg!(target_env = "msvc") {
        // vcpkg requires to set env VCPKGRS_DYNAMIC
        println!("cargo:rerun-if-env-changed=VCPKGRS_DYNAMIC");
    }
    if cfg!(not(windows)) {
        println!("cargo:rerun-if-env-changed=SODIUM_DISABLE_PIE");
    }

    if env::var("SODIUM_STATIC").is_ok() {
        panic!("SODIUM_STATIC is deprecated. Use SODIUM_SHARED instead.");
    }

    let lib_dir_isset = env::var("SODIUM_LIB_DIR").is_ok();
    let use_pkg_isset = env::var("SODIUM_USE_PKG_CONFIG").is_ok();
    let shared_isset = env::var("SODIUM_SHARED").is_ok();

    if lib_dir_isset && use_pkg_isset {
        panic!("SODIUM_LIB_DIR is incompatible with SODIUM_USE_PKG_CONFIG. Set the only one env variable");
    }

    if lib_dir_isset {
        find_libsodium_env();
    } else if use_pkg_isset {
        if shared_isset {
            println!("cargo:warning=SODIUM_SHARED has no effect with SODIUM_USE_PKG_CONFIG");
        }

        find_libsodium_pkg();
    } else {
        if shared_isset {
            println!(
                "cargo:warning=SODIUM_SHARED has no effect for building libsodium from source"
            );
        }

        build_libsodium();
    }
}

/* Must be called when SODIUM_LIB_DIR is set to any value
This function will set `cargo` flags.
*/
fn find_libsodium_env() {
    let lib_dir = env::var("SODIUM_LIB_DIR").unwrap(); // cannot fail

    println!("cargo:rustc-link-search=native={}", lib_dir);
    let mode = if env::var("SODIUM_SHARED").is_ok() {
        "dylib"
    } else {
        "static"
    };
    let name = if cfg!(target_env = "msvc") {
        "libsodium"
    } else {
        "sodium"
    };
    println!("cargo:rustc-link-lib={}={}", mode, name);
    println!(
        "cargo:warning=Using unknown libsodium version.  This crate is tested against \
         {} and may not be fully compatible with other versions.",
        VERSION
    );
}

/* Must be called when no SODIUM_USE_PKG_CONFIG env var is set
This function will set `cargo` flags.
*/
#[cfg(target_env = "msvc")]
fn find_libsodium_pkg() {
    match vcpkg::probe_package("libsodium") {
        Ok(_) => {
            println!(
                "cargo:warning=Using unknown libsodium version.  This crate is tested against \
                 {} and may not be fully compatible with other versions.",
                VERSION
            );
        }
        Err(e) => {
            panic!(format!("Error: {:?}", e));
        }
    };
}

/* Must be called when SODIUM_USE_PKG_CONFIG env var is set
This function will set `cargo` flags.
*/
#[cfg(not(target_env = "msvc"))]
fn find_libsodium_pkg() {
    match pkg_config::Config::new().probe("libsodium") {
        Ok(lib) => {
            if lib.version != VERSION {
                println!(
                    "cargo:warning=Using libsodium version {}.  This crate is tested against {} \
                     and may not be fully compatible with {}.",
                    lib.version, VERSION, lib.version
                );
            }
        }
        Err(e) => {
            panic!(format!("Error: {:?}", e));
        }
    }
}

fn get_cur_dir() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
}

fn get_install_dir() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").unwrap()).join("installed/")
}


fn build_libsodium() {

    // Download sources
    let source_dir = get_cur_dir().join("libsodium/");
    if !source_dir.join(".git").exists() {
        let _ = Command::new("git").args(&["submodule", "update", "--init"])
                                   .status();
    }

    // Determine build target triple
    let target = env::var("TARGET").unwrap();

    // Determine and create install dir
    let install_dir = get_install_dir();
    fs::create_dir_all(&install_dir).unwrap();

    // See https://github.com/jedisct1/libsodium/issues/207
    /*
    if install_dir.contains(" ") {
        panic!("The path to the usual build directory contains spaces and hence \
                can't be used to build libsodium."
        );
    }
    */

    // Decide on CC, CFLAGS and the --host configure argument
    let build = cc::Build::new();
    let mut compiler = build.get_compiler().path().to_str().unwrap().to_string();
    let mut cflags = env::var("CFLAGS").unwrap_or(String::default());
    cflags += " -O2";
    let host_arg;
    let cross_compiling;
    let help;
    if target.contains("-ios") {
        // Determine Xcode directory path
        let xcode_select_output = Command::new("xcode-select").arg("-p").output().unwrap();
        if !xcode_select_output.status.success() {
            panic!("Failed to run xcode-select -p");
        }
        let xcode_dir = str::from_utf8(&xcode_select_output.stdout)
            .unwrap()
            .trim()
            .to_string();

        // Determine SDK directory paths
        let sdk_dir_simulator = Path::new(&xcode_dir)
            .join("Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk")
            .to_str()
            .unwrap()
            .to_string();
        let sdk_dir_ios = Path::new(&xcode_dir)
            .join("Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk")
            .to_str()
            .unwrap()
            .to_string();

        // Min versions
        let ios_simulator_version_min = "6.0.0";
        let ios_version_min = "6.0.0";

        // Roughly based on `dist-build/ios.sh` in the libsodium sources
        match &*target {
            "aarch64-apple-ios" => {
                cflags += " -arch arm64";
                cflags += &format!(" -isysroot {}", sdk_dir_ios);
                cflags += &format!(" -mios-version-min={}", ios_version_min);
                cflags += " -fembed-bitcode";
                host_arg = "--host=arm-apple-darwin10".to_string();
            }
            "armv7-apple-ios" => {
                cflags += " -arch armv7";
                cflags += &format!(" -isysroot {}", sdk_dir_ios);
                cflags += &format!(" -mios-version-min={}", ios_version_min);
                cflags += " -mthumb";
                host_arg = "--host=arm-apple-darwin10".to_string();
            }
            "armv7s-apple-ios" => {
                cflags += " -arch armv7s";
                cflags += &format!(" -isysroot {}", sdk_dir_ios);
                cflags += &format!(" -mios-version-min={}", ios_version_min);
                cflags += " -mthumb";
                host_arg = "--host=arm-apple-darwin10".to_string();
            }
            "i386-apple-ios" => {
                cflags += " -arch i386";
                cflags += &format!(" -isysroot {}", sdk_dir_simulator);
                cflags += &format!(" -mios-simulator-version-min={}", ios_simulator_version_min);
                host_arg = "--host=i686-apple-darwin10".to_string();
            }
            "x86_64-apple-ios" => {
                cflags += " -arch x86_64";
                cflags += &format!(" -isysroot {}", sdk_dir_simulator);
                cflags += &format!(" -mios-simulator-version-min={}", ios_simulator_version_min);
                host_arg = "--host=x86_64-apple-darwin10".to_string();
            }
            _ => panic!("Unknown iOS build target: {}", target),
        }
        cross_compiling = true;
        help = "";
    } else {
        if target.contains("i686") {
            compiler += " -m32 -maes";
            cflags += " -march=i686";
        }
        let host = env::var("HOST").unwrap();
        host_arg = format!("--host={}", target);
        cross_compiling = target != host;
        help = if cross_compiling {
            "***********************************************************\n\
             Possible missing dependencies.\n\
             See https://github.com/sodiumoxide/sodiumoxide#cross-compiling\n\
             ***********************************************************\n\n"
        } else {
            ""
        };
    }

    // Run ./autogen.sh
    let mut autogen_cmd = Command::new("./autogen.sh");
    let autogen_cmd_output = autogen_cmd
        .current_dir(&source_dir)
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run './configure': {}\n{}", error, help);
        });
    if !autogen_cmd_output.status.success() {
        panic!(
            "\n{:?}\nCFLAGS={}\n{}\n{}\n",
            autogen_cmd,
            String::from_utf8_lossy(&autogen_cmd_output.stdout),
            String::from_utf8_lossy(&autogen_cmd_output.stderr),
            help
        );
    }

    // Run `./configure`
    let prefix_arg = format!("--prefix={}", install_dir.display());
    let mut configure_cmd = Command::new("./configure");
    if !compiler.is_empty() {
        configure_cmd.env("CC", &compiler);
    }
    if !cflags.is_empty() {
        configure_cmd.env("CFLAGS", &cflags);
    }
    if env::var("SODIUM_DISABLE_PIE").is_ok() {
        configure_cmd.arg("--disable-pie");
    }
    let configure_output = configure_cmd
        .current_dir(&source_dir)
        .arg(&prefix_arg)
        .arg(&host_arg)
        .arg("--enable-shared=no")
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run './configure': {}\n{}", error, help);
        });
    if !configure_output.status.success() {
        panic!(
            "\n{:?}\nCFLAGS={}\nCC={}\n{}\n{}\n{}\n",
            configure_cmd,
            cflags,
            compiler,
            String::from_utf8_lossy(&configure_output.stdout),
            String::from_utf8_lossy(&configure_output.stderr),
            help
        );
    }

    // Run `make check`, or `make all` if we're cross-compiling
    let j_arg = format!("-j{}", env::var("NUM_JOBS").unwrap());
    let make_arg = if cross_compiling { "all" } else { "check" };
    let mut make_cmd = Command::new("make");
    let make_output = make_cmd
        .current_dir(&source_dir)
        .env("V", "1")
        .arg(make_arg)
        .arg(&j_arg)
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run 'make {}': {}\n{}", make_arg, error, help);
        });
    if !make_output.status.success() {
        panic!(
            "\n{:?}\n{}\n{}\n{}\n{}",
            make_cmd,
            String::from_utf8_lossy(&configure_output.stdout),
            String::from_utf8_lossy(&make_output.stdout),
            String::from_utf8_lossy(&make_output.stderr),
            help
        );
    }

    // Run `make install`
    let mut install_cmd = Command::new("make");
    let install_output = install_cmd
        .current_dir(&source_dir)
        .arg("install")
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run 'make install': {}", error);
        });
    if !install_output.status.success() {
        panic!(
            "\n{:?}\n{}\n{}\n{}\n{}\n",
            install_cmd,
            String::from_utf8_lossy(&configure_output.stdout),
            String::from_utf8_lossy(&make_output.stdout),
            String::from_utf8_lossy(&install_output.stdout),
            String::from_utf8_lossy(&install_output.stderr)
        );
    }

    println!("cargo:rustc-link-lib=static=sodium");
    println!("cargo:rustc-link-search=native={}/lib", install_dir.display());
}
