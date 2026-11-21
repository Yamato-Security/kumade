//! Manual compatibility qualification against the exact, unmodified Forge sources.
#[test]
#[ignore = "set KUMADE_YARA_FORGE_DIR to a directory containing core.yar, extended.yar and full.yar"]
fn compile_all_forge_packages_without_dropping_rules() {
    let root = std::path::PathBuf::from(
        std::env::var_os("KUMADE_YARA_FORGE_DIR").expect("rule directory"),
    );
    for set in ["core", "extended", "full"] {
        let source = std::fs::read_to_string(root.join(format!("{set}.yar"))).unwrap();
        let start = std::time::Instant::now();
        let scanner =
            kumade::yara_scan::compile(&source, 60, 16).unwrap_or_else(|e| panic!("{set}: {e:#}"));
        let count = scanner.rules().count();
        let expected = source
            .lines()
            .find_map(|s| s.trim().strip_prefix("* Number of Rules: "))
            .unwrap()
            .parse::<usize>()
            .unwrap();
        println!(
            "{set}: {count} rules, {:.3}s, SHA256 {}",
            start.elapsed().as_secs_f64(),
            kumade::model::sha256(source.as_bytes())
        );
        assert_eq!(count, expected, "No Forge rule may be silently dropped");
    }
}
