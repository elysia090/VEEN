use assert_cmd::Command;
use std::fs;
use tempfile::NamedTempFile;

fn run_stubbed_selftest(args: &[&str]) -> Vec<String> {
    let log_file = NamedTempFile::new().expect("create stub log");
    let log_path = log_file.path().to_path_buf();

    Command::new(assert_cmd::cargo::cargo_bin!("veen"))
        .env("VEEN_SELFTEST_STUB", "1")
        .env("VEEN_SELFTEST_STUB_FILE", &log_path)
        .args(args)
        .assert()
        .success();

    let contents = fs::read_to_string(log_path).expect("read stub log");
    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.to_string())
        .collect()
}

#[test]
fn selftest_core_dispatches() {
    let suites = run_stubbed_selftest(&["selftest", "core"]);
    assert_eq!(suites, vec!["core".to_string()]);
}

#[test]
fn selftest_props_dispatches() {
    let suites = run_stubbed_selftest(&["selftest", "props"]);
    assert_eq!(suites, vec!["props".to_string()]);
}

#[test]
fn selftest_fuzz_dispatches() {
    let suites = run_stubbed_selftest(&["selftest", "fuzz"]);
    assert_eq!(suites, vec!["fuzz".to_string()]);
}

#[test]
fn selftest_all_dispatches() {
    let suites = run_stubbed_selftest(&["selftest", "all"]);
    assert_eq!(suites, vec!["all".to_string()]);
}

#[test]
fn selftest_federated_dispatches() {
    let suites = run_stubbed_selftest(&["selftest", "federated"]);
    assert_eq!(suites, vec!["federated".to_string()]);
}

#[test]
fn selftest_kex1_dispatches() {
    let suites = run_stubbed_selftest(&["selftest", "kex1"]);
    assert_eq!(suites, vec!["kex1".to_string()]);
}

#[test]
fn selftest_hardened_dispatches() {
    let suites = run_stubbed_selftest(&["selftest", "hardened"]);
    assert_eq!(suites, vec!["hardened".to_string()]);
}

#[test]
fn selftest_meta_dispatches() {
    let suites = run_stubbed_selftest(&["selftest", "meta"]);
    assert_eq!(suites, vec!["meta".to_string()]);
}

#[test]
fn selftest_plus_runs_all_suites_in_order() {
    let suites = run_stubbed_selftest(&["selftest", "plus"]);
    let expected = vec![
        "plus",
        "core",
        "props",
        "fuzz",
        "federated",
        "kex1",
        "hardened",
        "meta",
    ]
    .into_iter()
    .map(String::from)
    .collect::<Vec<_>>();
    assert_eq!(suites, expected);
}

#[test]
fn selftest_plus_plus_runs_plus_suite() {
    let suites = run_stubbed_selftest(&["selftest", "plus-plus"]);
    let expected = vec![
        "plus-plus",
        "plus",
        "core",
        "props",
        "fuzz",
        "federated",
        "kex1",
        "hardened",
        "meta",
    ]
    .into_iter()
    .map(String::from)
    .collect::<Vec<_>>();
    assert_eq!(suites, expected);
}
