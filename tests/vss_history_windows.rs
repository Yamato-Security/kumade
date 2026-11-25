// Copyright (C) 2026 Shirofune Security Co., Ltd.
// SPDX-License-Identifier: RPL-1.5
#![cfg(windows)]
#[test]
fn historical_snapshots_are_listed_collected_and_never_deleted_by_the_collector() {
    if let Err(error) = kumade::vss::check_host() {
        #[cfg(target_arch = "x86")]
        if error.to_string().contains("native") {
            return;
        }
        panic!("Native VSS test host required: {error:#}");
    }
    let temp = tempfile::tempdir().unwrap();
    let system = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap());
    let shell = ["Sysnative", "System32"]
        .into_iter()
        .map(|p| system.join(p).join("WindowsPowerShell/v1.0/powershell.exe"))
        .find(|p| p.is_file())
        .unwrap();
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/test_vss_history.ps1");
    let output = std::process::Command::new(shell)
        .args(["-NoProfile", "-NonInteractive", "-File"])
        .arg(script)
        .arg("-Binary")
        .arg(env!("CARGO_BIN_EXE_kumade"))
        .arg("-WorkDirectory")
        .arg(temp.path().join("history"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
