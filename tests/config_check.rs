#![allow(clippy::unwrap_used, clippy::expect_used)]

//! AT-18 at the binary level: `ovenmitt config check` passes a good file and
//! refuses each bad one with a line number and exit code 1.

use std::path::Path;
use std::process::Command;

fn run_check(path: &Path) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_ovenmitt"))
        .args(["config", "check"])
        .arg(path)
        .output()
        .expect("binary runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn good_config_passes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("archive");
    std::fs::create_dir(&root).expect("mkdir");
    let cfg = dir.path().join("ovenmitt.toml");
    std::fs::write(
        &cfg,
        format!(
            "[vault.private]\nttl = \"30d\"\n\n[vault.private.destinations.archive]\nkind = \"fs\"\nroot = \"{}\"\n\n[vault.private.destinations.team]\nkind = \"send\"\nmatch = \"chat:group/team\"\n",
            root.display()
        ),
    )
    .expect("write");
    let (code, stdout, stderr) = run_check(&cfg);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("ok:"), "{stdout}");
    assert!(stdout.contains("1 vault(s), 2 destination(s)"), "{stdout}");
}

#[test]
fn bad_configs_fail_with_line_numbers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cases: &[(&str, usize)] = &[
        ("[daemon]\nlisten = \"0.0.0.0:80\"\n", 2),
        ("[vault.private]\nttl = \"30 days\"\n", 2),
        (
            "[vault.private]\n\n[vault.private.destinations.d]\nkind = \"send\"\nmatch = \"chat:*\"\n",
            5,
        ),
        (
            "[vault.private]\n[vault.private.destinations.d]\nkind = \"fs\"\nroot = \"relative/path\"\n",
            4,
        ),
        (
            "[vault.private]\n[vault.private.destinations.d]\nkind = \"fs\"\nroot = \"/definitely/not/here\"\n",
            4,
        ),
        (
            "[vault.private]\n[vault.private.destinations.d]\nkind = \"send\"\nmatch = \"a\"\nroot = \"/x\"\n",
            5,
        ),
    ];
    for (i, (src, line)) in cases.iter().enumerate() {
        let cfg = dir.path().join(format!("bad{i}.toml"));
        std::fs::write(&cfg, src).expect("write");
        let (code, _stdout, stderr) = run_check(&cfg);
        assert_eq!(code, 1, "case {i}: {stderr}");
        assert!(
            stderr.contains(&format!("line {line}:")),
            "case {i}: expected line {line} in: {stderr}"
        );
    }
}

#[test]
fn missing_file_is_an_error() {
    let (code, _, stderr) = run_check(Path::new("/nonexistent/ovenmitt.toml"));
    assert_eq!(code, 1);
    assert!(stderr.contains("cannot read"), "{stderr}");
}
