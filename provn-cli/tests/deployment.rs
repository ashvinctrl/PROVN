//! Deployment-facing integration tests: baseline suppression, SARIF output,
//! history scanning, and .gitignore awareness — driven through the real binary
//! in a throwaway git repo. These guard the security-critical contracts:
//! a baseline must never suppress a *different* secret, and machine-readable
//! output must never contain the raw secret.

use assert_cmd::Command;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

/// Synthetic, well-known example AWS key (not a live credential).
const AWS_KEY: &str = concat!("AKIAIOSFOD", "NN7EXAMPLE");
/// A *different* valid-shape key, for the rotation test.
const AWS_KEY_2: &str = concat!("AKIA123456", "7890ABCDEF");

struct Repo {
    dir: PathBuf,
}

impl Repo {
    fn new(tag: &str) -> Repo {
        let dir = std::env::temp_dir().join(format!("provn-it-{tag}-{}", uuid_like()));
        fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-q"]);
        git(&dir, &["config", "user.email", "t@t"]);
        git(&dir, &["config", "user.name", "t"]);
        Repo { dir }
    }

    fn write(&self, name: &str, content: &str) {
        let p = self.dir.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }

    fn provn(&self, args: &[&str]) -> std::process::Output {
        Command::cargo_bin("provn")
            .unwrap()
            .current_dir(&self.dir)
            .args(args)
            .output()
            .unwrap()
    }

    fn code(&self, args: &[&str]) -> i32 {
        self.provn(args).status.code().unwrap_or(-1)
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn git(dir: &Path, args: &[&str]) {
    StdCommand::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("git available");
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

#[test]
fn baseline_suppresses_then_new_secret_still_caught() {
    let repo = Repo::new("baseline");
    repo.write("config.py", &format!("AWS = \"{AWS_KEY}\"\n"));

    assert_eq!(
        repo.code(&["check", ".", "--no-baseline"]),
        1,
        "secret flagged pre-baseline"
    );

    assert_eq!(repo.code(&["baseline", "."]), 0, "baseline written");
    assert!(repo.dir.join(".provn/baseline.json").exists());

    assert_eq!(repo.code(&["check", "."]), 0, "baselined secret suppressed");

    // SECURITY: rotating to a different key must NOT be suppressed.
    repo.write("config.py", &format!("AWS = \"{AWS_KEY_2}\"\n"));
    assert_eq!(
        repo.code(&["check", "."]),
        1,
        "a different secret must not be suppressed by the baseline"
    );
}

#[test]
fn baseline_file_has_no_plaintext_secret() {
    let repo = Repo::new("baseline-nosecret");
    repo.write("config.py", &format!("AWS = \"{AWS_KEY}\"\n"));
    repo.provn(&["baseline", "."]);
    let content = fs::read_to_string(repo.dir.join(".provn/baseline.json")).unwrap();
    assert!(
        !content.contains(AWS_KEY),
        "baseline must not store the plaintext secret"
    );
}

#[test]
fn sarif_output_is_valid_and_leaks_no_secret() {
    let repo = Repo::new("sarif");
    repo.write("s.py", &format!("KEY = \"{AWS_KEY}\"\n"));
    let out = repo.provn(&["check", "s.py", "--format", "sarif", "--no-baseline"]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid SARIF JSON");
    assert_eq!(v["version"], "2.1.0");
    assert_eq!(v["runs"][0]["results"][0]["level"], "error");
    assert!(
        !stdout.contains(AWS_KEY),
        "SARIF must not contain the secret"
    );
}

#[test]
fn history_scan_finds_secret_removed_from_working_tree() {
    let repo = Repo::new("history");
    repo.write(
        "leak.py",
        concat!(
            "GITHUB = \"ghp_abcdefghijklmnopqr",
            "stuvwxyz0123456789\"\n"
        ),
    ); // provn:allow
    git(&repo.dir, &["add", "-A"]);
    git(&repo.dir, &["commit", "-qm", "introduce secret"]);

    repo.write("leak.py", "cleaned = 1\n");
    git(&repo.dir, &["add", "-A"]);
    git(&repo.dir, &["commit", "-qm", "remove from tree"]);

    // Working tree is clean…
    assert_eq!(repo.code(&["check", "leak.py", "--no-baseline"]), 0);
    // …but history still carries it.
    let out = repo.provn(&["scan-history", "--json"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("github_token"),
        "history scan should surface the old secret"
    );
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn directory_scan_respects_gitignore() {
    let repo = Repo::new("gitignore");
    repo.write(".gitignore", "buildout/\n");
    repo.write("buildout/x.py", &format!("IGN = \"{AWS_KEY}\"\n"));
    repo.write("tracked.py", &format!("K = \"{AWS_KEY}\"\n"));

    let out = repo.provn(&["check", ".", "--no-baseline", "--format", "sarif"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("buildout/x.py"),
        "ignored dir must be skipped"
    );
    assert!(
        stdout.contains("tracked.py"),
        "non-ignored file must still be scanned"
    );
}
