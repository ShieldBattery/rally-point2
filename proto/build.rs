//! Compiles the protobuf wire schema (`proto/*.proto`) into Rust.
//!
//! Uses [`protox`] (a pure-Rust protobuf compiler) to produce a descriptor set,
//! then hands it to `prost-build`. This means no `protoc` binary is required on
//! the build machine or in CI, and the build script stays `unsafe`-free (the
//! vendored-`protoc` approach would require `unsafe { env::set_var("PROTOC") }`
//! under edition 2024).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const PROTOS: &[&str] = &["proto/wire.proto"];

    for proto in PROTOS {
        println!("cargo:rerun-if-changed={proto}");
    }

    let file_descriptors = protox::compile(PROTOS, ["proto"])?;
    prost_build::Config::new()
        // Generate `bytes::Bytes` for `bytes` fields instead of `Vec<u8>` so the
        // hot path can forward command bytes without copying.
        .bytes(["."])
        .compile_fds(file_descriptors)?;

    Ok(())
}
