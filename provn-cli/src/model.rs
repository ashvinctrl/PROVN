//! Layer 3 model management.
//!
//! Layer 3 used to require a six-step manual dance (install the `hf` CLI, log
//! in, make a directory, download a GGUF, start `llama-server`, edit
//! `provn.yml`), which meant that in practice almost nobody enabled it — the
//! shipped product was the deterministic layers alone. This module reduces that
//! to `provn model install`, by keeping a small registry of known-good GGUF
//! builds that can be fetched over plain HTTPS with no account and no extra
//! tooling.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// A downloadable Layer 3 model.
pub struct ModelSpec {
    /// Short id used on the command line (`provn model install nemotron`).
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// Hugging Face repository holding the GGUF.
    pub repo: &'static str,
    /// GGUF filename, also the on-disk name under the models directory.
    pub file: &'static str,
    /// Download size when it is known ahead of time. `None` means Provn cannot
    /// state one — for a repo it cannot read, the real size is whatever the
    /// server reports at download time, and guessing here would put a made-up
    /// number in front of the user.
    pub size_bytes: Option<u64>,
    /// True when the repo needs Hugging Face credentials, which the plain
    /// HTTPS download path cannot supply.
    pub needs_auth: bool,
    pub notes: &'static str,
}

impl ModelSpec {
    /// Direct download URL. Hugging Face answers `/resolve/main/<file>` with a
    /// redirect to its CDN, which reqwest follows.
    pub fn url(&self) -> String {
        format!(
            "https://huggingface.co/{}/resolve/main/{}",
            self.repo, self.file
        )
    }

    /// Printable size, or "size unknown" when Provn has no verified figure.
    pub fn size_label(&self) -> String {
        match self.size_bytes {
            Some(n) => human_bytes(n),
            None => "size unknown".to_string(),
        }
    }
}

/// Models Provn knows how to install.
///
/// The first entry is the default: an openly licensed NVIDIA build that needs
/// no Hugging Face account, so `provn model install` works for anyone.
pub const REGISTRY: &[ModelSpec] = &[
    ModelSpec {
        id: "nemotron",
        name: "NVIDIA Nemotron 3 Nano 4B (Q4_K_M)",
        repo: "nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF",
        file: "NVIDIA-Nemotron3-Nano-4B-Q4_K_M.gguf",
        // Reported by the Hugging Face CDN for this exact file.
        size_bytes: Some(2_837_072_864),
        needs_auth: false,
        notes: "open weights, no account required — the default",
    },
    ModelSpec {
        id: "gemma",
        name: "Provn Gemma 4 E2B (Q4_K_M, fine-tuned on LeakBench)",
        repo: "ashvinctrl/provn-gemma4-e2b-q4km",
        file: "provn-gemma4-e2b-q4km.gguf",
        size_bytes: None,
        needs_auth: true,
        notes: "task-tuned for leak classification; the repo does not answer anonymous \
                requests, so it needs Hugging Face credentials",
    },
];

pub fn find(id: &str) -> Option<&'static ModelSpec> {
    REGISTRY.iter().find(|m| m.id.eq_ignore_ascii_case(id))
}

/// The user's home directory, portable across the platforms Provn ships for.
pub fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// Where GGUF files live: `~/.provn/models`.
pub fn models_dir() -> PathBuf {
    home_dir().join(".provn").join("models")
}

/// Resolve a configured `model` value to a path. An absolute path or one
/// containing a separator is used as-is; a bare filename is looked up under the
/// models directory.
pub fn resolve_path(model: &str) -> PathBuf {
    let raw = model.trim();
    if raw.contains('/') || raw.contains('\\') {
        PathBuf::from(shellexpand_home(raw))
    } else {
        models_dir().join(raw)
    }
}

/// Expand a leading `~` — config files are hand-written, so `~/models/x.gguf`
/// is a realistic thing to find in one.
fn shellexpand_home(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/").or_else(|| p.strip_prefix("~\\")) {
        return home_dir().join(rest).to_string_lossy().into_owned();
    }
    p.to_string()
}

#[derive(Debug)]
pub enum DownloadError {
    Http(String),
    Io(std::io::Error),
    Incomplete { got: u64, expected: u64 },
}

impl std::fmt::Display for DownloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DownloadError::Http(m) => write!(f, "{m}"),
            DownloadError::Io(e) => write!(f, "{e}"),
            DownloadError::Incomplete { got, expected } => {
                write!(f, "truncated download: got {got} of {expected} bytes")
            }
        }
    }
}

impl From<std::io::Error> for DownloadError {
    fn from(e: std::io::Error) -> Self {
        DownloadError::Io(e)
    }
}

/// Stream a model to `dest`, reporting progress through `on_progress`.
///
/// Downloads to a `.part` file and renames on success, so an interrupted run
/// can never leave a half-written GGUF that looks installed.
pub fn download(
    spec: &ModelSpec,
    dest: &Path,
    mut on_progress: impl FnMut(u64, Option<u64>),
) -> Result<(), DownloadError> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }

    // No overall timeout: this is a multi-gigabyte transfer. A stalled
    // connection surfaces as a read error from the body stream instead.
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| DownloadError::Http(e.to_string()))?;

    let resp = client
        .get(spec.url())
        .send()
        .map_err(|e| DownloadError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        let code = resp.status().as_u16();
        let hint = if code == 401 || code == 403 {
            format!(
                " — {} requires Hugging Face credentials that a plain download cannot supply",
                spec.repo
            )
        } else {
            String::new()
        };
        return Err(DownloadError::Http(format!("HTTP {code}{hint}")));
    }

    let expected = resp.content_length();
    let part = dest.with_extension("part");
    let mut file = fs::File::create(&part)?;

    let mut reader = resp;
    let mut buf = vec![0u8; 1 << 20]; // 1 MiB
    let mut written: u64 = 0;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                let _ = fs::remove_file(&part);
                return Err(DownloadError::Io(e));
            }
        };
        if let Err(e) = file.write_all(&buf[..n]) {
            let _ = fs::remove_file(&part);
            return Err(DownloadError::Io(e));
        }
        written += n as u64;
        on_progress(written, expected);
    }
    file.flush()?;
    drop(file);

    if let Some(total) = expected {
        if written != total {
            let _ = fs::remove_file(&part);
            return Err(DownloadError::Incomplete {
                got: written,
                expected: total,
            });
        }
    }

    fs::rename(&part, dest)?;
    Ok(())
}

/// Format a byte count for progress output.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} {}", UNITS[0])
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_model_is_open_weights() {
        // `provn model install` with no argument must work without an account,
        // otherwise Layer 3 stays effectively unreachable.
        let default = &REGISTRY[0];
        assert!(!default.needs_auth, "default model must not require auth");
        assert_eq!(default.id, "nemotron");
    }

    #[test]
    fn registry_ids_are_unique() {
        for (i, m) in REGISTRY.iter().enumerate() {
            assert!(
                REGISTRY.iter().skip(i + 1).all(|o| o.id != m.id),
                "duplicate model id {}",
                m.id
            );
        }
    }

    #[test]
    fn lookup_is_case_insensitive() {
        assert!(find("NEMOTRON").is_some());
        assert!(find("nemotron").is_some());
        assert!(find("no-such-model").is_none());
    }

    #[test]
    fn url_points_at_the_resolve_endpoint() {
        let m = find("nemotron").unwrap();
        assert_eq!(
            m.url(),
            "https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF/resolve/main/NVIDIA-Nemotron3-Nano-4B-Q4_K_M.gguf"
        );
    }

    #[test]
    fn bare_filename_resolves_under_models_dir() {
        let p = resolve_path("model.gguf");
        assert_eq!(p.parent().unwrap(), models_dir());
        assert_eq!(p.file_name().unwrap(), "model.gguf");
    }

    #[test]
    fn explicit_path_is_left_alone() {
        let p = resolve_path("/opt/models/x.gguf");
        assert_eq!(p, PathBuf::from("/opt/models/x.gguf"));
    }

    #[test]
    fn tilde_is_expanded() {
        let p = resolve_path("~/custom/x.gguf");
        assert!(!p.to_string_lossy().starts_with('~'), "got {p:?}");
        assert!(p.ends_with("custom/x.gguf") || p.ends_with("custom\\x.gguf"));
    }

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2_837_072_864), "2.8 GB");
    }
}
