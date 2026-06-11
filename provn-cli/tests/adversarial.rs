//! Adversarial detection suite.
//!
//! Drives the built `provn` binary against intentionally obfuscated secrets
//! and known false-positive shapes, asserting the documented detection
//! contract. All secret values here are synthetic / well-known examples.
//!
//! Detection contract (also documented in ARCHITECTURE.md):
//!   MUST detect:     base64-encoded key, hex-encoded key, secret in comment,
//!                    secret in multiline string, split-string concatenation,
//!                    homoglyph-substituted variable, BIP39 mnemonic
//!   MUST NOT flag:   SHA-256 checksum, UUID, bcrypt hash, base64 PNG header,
//!                    semver string

use assert_cmd::Command;
use std::io::Write;

/// Write `content` to a temp file with the given extension and return its path.
fn fixture(name: &str, content: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("provn-adv-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
    path
}

fn check(path: &std::path::Path) -> bool {
    // Returns true when provn flags the file (exit code 1).
    let out = Command::cargo_bin("provn")
        .unwrap()
        .arg("check")
        .arg(path)
        .output()
        .unwrap();
    out.status.code() == Some(1)
}

fn assert_detected(name: &str, content: &str, label: &str) {
    let p = fixture(name, content);
    assert!(check(&p), "should detect: {label}");
}

fn assert_clean(name: &str, content: &str, label: &str) {
    let p = fixture(name, content);
    assert!(!check(&p), "false positive on: {label}");
}

#[test]
fn detects_base64_encoded_key() {
    assert_detected(
        "b64.py",
        concat!(
            "secret = base64.b64decode(\"c2stcHJvai1hYmMxMjNkZWY0NTZna",
            "Gk3ODlqa2wwMTJtbm8zNDVwcXI2Nzg=\").decode()\n"
        ),
        "base64-encoded key literal",
    );
}

#[test]
fn detects_hex_encoded_key() {
    assert_detected(
        "hex.py",
        concat!(
            "key_hex = \"414b4941494f53464f44",
            "4e4e374558414d504c45\"\n"
        ),
        "hex-encoded AWS key",
    );
}

#[test]
fn detects_secret_in_comment() {
    assert_detected(
        "comment.py",
        concat!("# old key: AKIAIOSFOD", "NN7EXAMPLE do not use\n"),
        "secret inside a comment",
    );
}

#[test]
fn detects_secret_in_multiline_string() {
    assert_detected(
        "multiline.py",
        concat!(
            "p = \"\"\"line one\nAKIAIOSFO",
            "DNN7EXAMPLE\nline three\"\"\"\n"
        ),
        "secret inside a multiline string",
    );
}

#[test]
fn detects_split_string_concatenation() {
    assert_detected(
        "split.py",
        "k = \"AKIA\" + \"IOSFODNN\" + \"7EXAMPLE\"\n",
        "split-string concatenation",
    );
}

#[test]
fn detects_homoglyph_variable() {
    // Cyrillic А (U+0410) in the variable name; real key in the value.
    assert_detected(
        "homoglyph.py",
        concat!("\u{0410}KI\u{0410} = \"AKIAIOSFOD", "NN7EXAMPLE\"\n"),
        "homoglyph-substituted variable",
    );
}

#[test]
fn detects_bip39_mnemonic() {
    assert_detected(
        "mnemonic.py",
        "mnemonic = \"abandon ability able about above absent absorb abstract absurd abuse access accident\"\n",
        "BIP39 mnemonic phrase",
    );
}

#[test]
fn does_not_flag_sha256_checksum() {
    assert_clean(
        "sha.py",
        concat!(
            "checksum = \"e3b0c44298fc1c149afbf4c8996fb924",
            "27ae41e4649b934ca495991b7852b855\"\n"
        ),
        "SHA-256 checksum",
    );
}

#[test]
fn does_not_flag_uuid() {
    assert_clean(
        "uuid.py",
        "trace = \"550e8400-e29b-41d4-a716-446655440000\"\n",
        "UUID",
    );
}

#[test]
fn does_not_flag_bcrypt_hash() {
    assert_clean(
        "bcrypt.py",
        concat!(
            "h = \"$2b$12$KIXQeQpP3O5l7uZxJ9yzUuY7vG",
            "m4dDqB1cF8aWnEHs6T0jRkLmNoq\"\n"
        ),
        "bcrypt hash",
    );
}

#[test]
fn does_not_flag_base64_png() {
    assert_clean(
        "png.py",
        concat!(
            "icon = \"iVBORw0KGgoAAAANSUhEUgAAAAEAAA",
            "ABCAYAAAAfFcSJAAAADUlEQVR42mNk\"\n"
        ),
        "base64 PNG header",
    );
}

#[test]
fn does_not_flag_semver() {
    assert_clean(
        "semver.py",
        "version = \"1.2.3-rc.1+build.42\"\n",
        "semver string",
    );
}
