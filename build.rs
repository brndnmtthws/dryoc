use std::env;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(dryoc_native_tests)");
    println!("cargo::rustc-check-cfg=cfg(dryoc_stream_kernel)");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_endian = env::var("CARGO_CFG_TARGET_ENDIAN").unwrap_or_default();

    if !(target_arch == "wasm32" && target_os == "unknown") {
        println!("cargo::rustc-cfg=dryoc_native_tests");
    }

    // Targets with an architecture-specific stream-cipher kernel module
    // (`chacha20_*`/`salsa20_*` NEON or AVX): the drivers in `chacha20` and
    // `salsa20` and the shared `stream::Dest` plumbing are compiled for these.
    if target_arch == "x86_64" || (target_arch == "aarch64" && target_endian == "little") {
        println!("cargo::rustc-cfg=dryoc_stream_kernel");
    }
}
