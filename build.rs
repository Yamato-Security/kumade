// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
fn main() {
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
