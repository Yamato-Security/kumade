//! An inert child process is the positive control; no malware is launched.
#![cfg(windows)]
use std::{io::Write, time::Duration};
#[cfg(not(target_arch = "x86"))]
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};
#[cfg(not(target_arch = "x86"))]
struct Child(std::process::Child);
#[cfg(not(target_arch = "x86"))]
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn process_control_child() {
    let Ok(marker) = std::env::var("KUMADE_YARA_CONTROL") else {
        return;
    };
    let bytes = marker.as_bytes().to_vec();
    let wide: Vec<u16> = marker.encode_utf16().collect();
    println!("KUMADE_CONTROL_READY");
    std::io::stdout().flush().unwrap();
    for _ in 0..120 {
        std::hint::black_box((&bytes, &wide));
        std::thread::sleep(Duration::from_secs(1));
    }
}
#[test]
#[cfg(not(target_arch = "x86"))]
fn native_cli_finds_ascii_and_wide_control_and_reports_missing_pid() {
    let temp = tempfile::tempdir().unwrap();
    let marker = format!(
        "KumadeHarmlessMemoryControl_{}",
        uuid::Uuid::new_v4().simple()
    );
    let mut child = Child(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "process_control_child", "--nocapture"])
            .env("KUMADE_YARA_CONTROL", &marker)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains("KUMADE_CONTROL_READY") {
                let _ = tx.send(());
                break;
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(15)).unwrap();
    let rules = temp.path().join("control.yar");
    std::fs::write(
        &rules,
        format!(
            r#"
rule ascii_control {{ strings: $x="{marker}" ascii condition: $x and not defined filesize }}
rule wide_control {{ strings: $x="{marker}" wide condition: $x and not defined filesize }}
rule negative_control {{ strings: $x="NeverPresent_{}" condition: $x }}
"#,
            uuid::Uuid::new_v4().simple()
        ),
    )
    .unwrap();
    let out = temp.path().join("out");
    let result = Command::new(env!("CARGO_BIN_EXE_kumade"))
        .args(["scan-processes", "--rules"])
        .arg(&rules)
        .args([
            "--pid",
            &child.0.id().to_string(),
            "--pid",
            "4294967295",
            "--format",
            "jsonl",
            "--output",
        ])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let detections = std::fs::read_to_string(out.join("YaraDetections.jsonl")).unwrap();
    let rows: Vec<serde_json::Value> = detections
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(rows.len(), 2, "{detections}");
    assert!(rows.iter().any(|r| r["Rule"] == "ascii_control"));
    assert!(rows.iter().any(|r| r["Rule"] == "wide_control"));
    assert!(rows.iter().all(
        |r| r["PID"] == child.0.id() && r["ImagePath"].as_str().is_some_and(|s| !s.is_empty())
    ));
    let processes = std::fs::read_to_string(out.join("YaraProcesses.jsonl")).unwrap();
    let rows: Vec<serde_json::Value> = processes
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .any(|r| r["PID"] == 4294967295u32 && r["Status"] == "Failed")
    );
    assert!(
        rows.iter()
            .any(|r| r["PID"] == child.0.id() && r["BytesRead"].as_u64().unwrap() > 0)
    );
}
