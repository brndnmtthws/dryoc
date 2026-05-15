use std::env;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(dryoc_native_tests)");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if !(target_arch == "wasm32" && target_os == "unknown") {
        println!("cargo::rustc-cfg=dryoc_native_tests");
    }
}
