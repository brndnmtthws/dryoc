use std::env;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(dryoc_native_tests)");
    println!("cargo::rustc-check-cfg=cfg(dryoc_stream_kernel)");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_endian = env::var("CARGO_CFG_TARGET_ENDIAN").unwrap_or_default();
    let miri = env::var_os("CARGO_CFG_MIRI").is_some();
    println!("cargo::rerun-if-env-changed=CARGO_CFG_MIRI");

    // Miri cannot execute the C libraries used by native compatibility tests.
    if !miri && !(target_arch == "wasm32" && target_os == "unknown") {
        println!("cargo::rustc-cfg=dryoc_native_tests");
    }

    // Targets with an architecture-specific stream-cipher kernel module
    // (`chacha20_*`/`salsa20_*` NEON, AVX or WebAssembly `simd128`): the
    // drivers in `chacha20` and `salsa20` and the shared `stream::Dest`
    // plumbing are compiled for these. Miri cannot interpret the NEON
    // shift-insert intrinsics used on AArch64. WebAssembly has no runtime
    // feature detection, so its kernels need `simd128` at compile time.
    let target_features = env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    let wasm_simd128 = target_arch == "wasm32"
        && target_features
            .split(',')
            .any(|feature| feature == "simd128");
    if target_arch == "x86_64"
        || (target_arch == "aarch64" && target_endian == "little" && !miri)
        || wasm_simd128
    {
        println!("cargo::rustc-cfg=dryoc_stream_kernel");
    }
}
