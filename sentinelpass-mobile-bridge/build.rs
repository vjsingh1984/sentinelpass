use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Generate C header for iOS
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Generate header for iOS
    let out_path = PathBuf::from(&crate_dir).join("include");
    fs::create_dir_all(&out_path).expect("Failed to create include directory");

    let config =
        cbindgen::Config::from_file("cbindgen.toml").expect("Unable to find cbindgen.toml");

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("sentinelpass_bridge.h"));

    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src/ffi.rs");

    // For Android, JNI doesn't need header generation
    // The JNI functions are exported directly
}
