use super::*;
fn options(output: PathBuf) -> Options {
    Options {
        output,
        ruleset: RuleSet::Core,
        rules_release: "latest".into(),
        rules: None,
        format: Format::Csv,
        pids: vec![],
        threads: 2,
        timeout: 10,
        chunk_mib: 1,
        quiet: true,
    }
}
#[test]
fn invalid_release_cannot_change_download_host_or_path() {
    for s in ["../x", "https://example.com", "2026-11-15", "2026111a", ""] {
        assert!(rule_url(RuleSet::Core, s).is_err());
    }
    assert!(
        rule_url(RuleSet::Full, "20261115")
            .unwrap()
            .ends_with("/20261115/yara-forge-rules-full.zip")
    );
}
#[test]
fn bounded_reads_and_wrong_zip_are_rejected() {
    assert!(read_bounded(&b"1234"[..], 3).is_err());
    assert!(archive_source(b"invalid".to_vec(), RuleSet::Core).is_err());
}
#[test]
fn no_silent_compile_skips_and_no_includes() {
    assert!(
        compile(
            "rule good { condition: true } rule bad { condition: unknown }",
            1,
            1
        )
        .is_err()
    );
    assert!(compile("include \"secret.txt\"", 1, 1).is_err());
    assert!(compile("", 1, 1).is_err());
}
#[test]
fn process_memory_semantics_metadata_and_locations_survive() {
    let scanner = compile(
        r#"rule fixture : Test {
        meta: score=77 description="safe marker" verified=false
        strings: $x="KUMADE_Synthetic_Control_42"
        condition: $x and not defined filesize
    }"#,
        10,
        1,
    )
    .unwrap();
    let found = scanner.scan_fragmented(TestMemory { index: 0 }).unwrap();
    let mut p = ProcessResult::new(42, "control.exe".into());
    p.status = "Partial".into();
    let rows = detections(&scanner, found, &p);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].scan_status, "Partial");
    assert!(rows[0].metadata.contains("77"));
    assert!(rows[0].match_locations.contains("0x0"));
    assert!(!rows[0].match_locations.contains("Synthetic"));
}
#[test]
fn partial_accounting_outputs_and_empty_csv_headers() {
    let temp = tempfile::tempdir().unwrap();
    let rules = temp.path().join("rules.yar");
    fs::write(&rules, "rule test { condition: true }").unwrap();
    let out = temp.path().join("result");
    let mut opt = options(out.clone());
    opt.rules = Some(rules);
    let code = run_with(
        &opt,
        || Ok(vec![(123, "protected.exe".into())]),
        |_, pid, name, _| {
            let mut p = ProcessResult::new(pid, name);
            p.message = "access denied".into();
            (p, vec![])
        },
        Metrics::default,
    )
    .unwrap();
    assert_eq!(code, 3);
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("Summary.json")).unwrap()).unwrap();
    assert_eq!(summary["Incomplete"], 1);
    assert_eq!(summary["Status"], "Partial");
    assert!(
        fs::read_to_string(out.join("YaraDetections.csv"))
            .unwrap()
            .starts_with("Computer,PID,")
    );
    assert!(
        run_with(
            &opt,
            || Ok(vec![]),
            |_, _, _, _| unreachable!(),
            Metrics::default
        )
        .is_err()
    );
}
#[test]
fn explicit_missing_pid_is_reported_and_jsonl_has_pascal_case() {
    let temp = tempfile::tempdir().unwrap();
    let rules = temp.path().join("rules.yar");
    fs::write(&rules, "rule test { condition: true }").unwrap();
    let mut opt = options(temp.path().join("out"));
    opt.rules = Some(rules);
    opt.pids = vec![555, 555];
    opt.format = Format::Jsonl;
    run_with(
        &opt,
        || Ok(vec![]),
        |_, pid, name, _| (ProcessResult::new(pid, name), vec![]),
        Metrics::default,
    )
    .unwrap();
    let text = fs::read_to_string(opt.output.join("YaraProcesses.jsonl")).unwrap();
    assert_eq!(text.lines().count(), 1);
    let v: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!(v["PID"], 555);
    assert!(v.get("process_name").is_none());
}

#[derive(Debug)]
struct TestMemory {
    index: usize,
}
impl boreal::memory::FragmentedMemory for TestMemory {
    fn reset(&mut self) {
        self.index = 0;
    }
    fn next(
        &mut self,
        _: &boreal::memory::MemoryParams,
    ) -> Option<boreal::memory::RegionDescription> {
        self.index += 1;
        if self.index == 1 {
            Some(boreal::memory::RegionDescription {
                start: 0,
                length: 26,
            })
        } else {
            None
        }
    }
    fn fetch(&mut self, _: &boreal::memory::MemoryParams) -> Option<boreal::memory::Region<'_>> {
        Some(boreal::memory::Region {
            start: 0,
            mem: b"KUMADE_Synthetic_Control_42",
        })
    }
}

#[test]
fn windows_utf8_bom_and_console_rules_compile_without_console_output() {
    let scanner = compile(
        "\u{feff}import \"console\" rule control { condition: console.log(\"inert\") }",
        1,
        1,
    )
    .unwrap();
    assert_eq!(scanner.scan_mem(b"").unwrap().rules.len(), 1);
}
