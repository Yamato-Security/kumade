// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
fn main() {
    bundle_rules();
    println!("cargo:rerun-if-changed=native/vss.cpp");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // The SDK declares IVssBackupComponents as a C++ interface, absent from
        // Win32 metadata bindings. Keep the ABI in a small SDK-compiled bridge.
        cc::Build::new()
            .cpp(true)
            .file("native/vss.cpp")
            .static_crt(true)
            .cpp_link_stdlib(None)
            .warnings(true)
            .compile("kumade_vss");
        println!("cargo:rustc-link-lib=ole32");
        println!("cargo:rustc-link-lib=uuid");
    }
}

fn bundle_rules() {
    use sha2::{Digest, Sha256};
    use std::{env, fs, path::PathBuf};
    for name in [
        "KUMADE_YARA_FORGE_ZIP",
        "KUMADE_YARA_FORGE_RELEASE",
        "KUMADE_YARA_FORGE_SHA256",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let sets: Vec<_> = ["core", "extended", "full"]
        .into_iter()
        .filter(|s| {
            env::var_os(format!("CARGO_FEATURE_BUNDLED_YARA_{}", s.to_uppercase())).is_some()
        })
        .collect();
    assert!(sets.len() <= 1, "Choose only one bundled-yara feature");
    let Some(set) = sets.first() else {
        return;
    };
    let path = PathBuf::from(
        env::var_os("KUMADE_YARA_FORGE_ZIP")
            .expect("Set KUMADE_YARA_FORGE_ZIP to a verified Forge ZIP"),
    );
    let release = env::var("KUMADE_YARA_FORGE_RELEASE")
        .expect("Set KUMADE_YARA_FORGE_RELEASE to the exact Forge tag");
    assert!(
        release.len() == 8 && release.bytes().all(|b| b.is_ascii_digit()),
        "Forge tag must have eight digits"
    );
    let expected = env::var("KUMADE_YARA_FORGE_SHA256").expect("Set KUMADE_YARA_FORGE_SHA256");
    assert!(
        expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid archive SHA-256"
    );
    assert!(
        fs::metadata(&path).expect("Read bundle metadata").len() <= 64 * 1024 * 1024,
        "Forge ZIP exceeds 64 MiB"
    );
    let bytes = fs::read(&path).expect("Read bundle ZIP");
    assert_eq!(
        Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        expected.to_lowercase(),
        "Forge archive hash differs"
    );
    println!("cargo:rerun-if-changed={}", path.display());
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("yara-forge.zip"),
        bytes,
    )
    .expect("Embed Forge ZIP");
    println!("cargo:rustc-env=KUMADE_BUNDLED_YARA_SET={set}");
    println!("cargo:rustc-env=KUMADE_BUNDLED_YARA_RELEASE={release}");
    println!(
        "cargo:rustc-env=KUMADE_BUNDLED_YARA_SHA256={}",
        expected.to_lowercase()
    );
}
