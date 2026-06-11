use crate::config::Config;
use std::path::PathBuf;
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiffError {
    #[error("git command failed: {0}")]
    Git(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct DiffChunk {
    pub file: PathBuf,
    pub extension: String,
    pub added_lines: Vec<(usize, String)>,
}

pub fn parse_staged_diff(cfg: &Config) -> Result<Vec<DiffChunk>, DiffError> {
    let output = Command::new("git")
        .args(["diff", "--cached", "--unified=0"])
        .output()?;

    if !output.status.success() {
        return Err(DiffError::Git(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    parse_diff_text(&text, cfg)
}

/// SHA-1 of git's empty tree — diff base for brand-new branches in pre-push.
const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

/// Parse the diff of a commit range (pre-push hook mode). `old` of all zeros
/// (git's convention for a new branch) diffs against the empty tree so every
/// outgoing commit is scanned.
pub fn parse_range_diff(old: &str, new: &str, cfg: &Config) -> Result<Vec<DiffChunk>, DiffError> {
    let base = if old.is_empty() || old.chars().all(|c| c == '0') {
        EMPTY_TREE
    } else {
        old
    };

    let output = Command::new("git")
        .args(["diff", "--unified=0", &format!("{base}..{new}")])
        .output()?;

    if !output.status.success() {
        return Err(DiffError::Git(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    parse_diff_text(&text, cfg)
}

/// Findings grouped by the commit that introduced them.
pub struct CommitDiff {
    pub sha: String,
    pub subject: String,
    pub chunks: Vec<DiffChunk>,
}

/// Scan git history for secrets introduced in past commits.
///
/// Uses a single `git log -p` invocation (not one subprocess per commit) with a
/// sentinel `--format` so the whole history streams in one pass. `max_commits`
/// of 0 means all commits reachable from HEAD; any positive value caps the walk
/// to bound work on very large repositories. Merge commits are skipped — their
/// changes appear in the parents.
pub fn parse_history(max_commits: usize, cfg: &Config) -> Result<Vec<CommitDiff>, DiffError> {
    const SENTINEL: &str = "@@PROVN_COMMIT@@";

    let mut args: Vec<String> = vec![
        "log".into(),
        "-p".into(),
        "--no-merges".into(),
        "--unified=0".into(),
        "--no-color".into(),
        format!("--format={SENTINEL}%H@@%s"),
    ];
    if max_commits > 0 {
        args.push(format!("--max-count={max_commits}"));
    }

    let output = Command::new("git").args(&args).output()?;
    if !output.status.success() {
        return Err(DiffError::Git(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut commits: Vec<CommitDiff> = Vec::new();
    let mut cur_sha = String::new();
    let mut cur_subject = String::new();
    let mut buf = String::new();

    let flush = |commits: &mut Vec<CommitDiff>,
                 sha: &str,
                 subject: &str,
                 buf: &str|
     -> Result<(), DiffError> {
        if sha.is_empty() {
            return Ok(());
        }
        let chunks = parse_diff_text(buf, cfg)?;
        if !chunks.is_empty() {
            commits.push(CommitDiff {
                sha: sha.to_string(),
                subject: subject.to_string(),
                chunks,
            });
        }
        Ok(())
    };

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(SENTINEL) {
            // Boundary between commits — flush the previous one.
            flush(&mut commits, &cur_sha, &cur_subject, &buf)?;
            buf.clear();
            let (sha, subject) = rest.split_once("@@").unwrap_or((rest, ""));
            cur_sha = sha.to_string();
            cur_subject = subject.to_string();
        } else {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    flush(&mut commits, &cur_sha, &cur_subject, &buf)?;

    Ok(commits)
}

pub fn parse_file(path: &str, cfg: &Config) -> Result<Vec<DiffChunk>, DiffError> {
    let file_path = PathBuf::from(path);

    if should_skip(&file_path, cfg) {
        return Ok(vec![]);
    }

    let content = std::fs::read_to_string(path)?;

    // Honour provn:skip-file anywhere in the file — same semantics as in diff mode.
    if content.contains("provn:skip-file") || content.contains("aegis:skip-file") {
        return Ok(vec![]);
    }

    let ext = file_path
        .extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_default();

    // Synthesize "added" lines from every line in the file, applying the same
    // provn:allow filter that parse_diff_text uses so the annotation works in
    // both `provn scan` (pre-commit) and `provn check` (file) modes.
    let added_lines: Vec<(usize, String)> = content
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.contains("provn:allow") && !l.contains("aegis:allow"))
        .map(|(i, l)| (i + 1, l.to_string()))
        .collect();

    Ok(vec![DiffChunk {
        file: file_path,
        extension: ext,
        added_lines,
    }])
}

fn parse_diff_text(text: &str, cfg: &Config) -> Result<Vec<DiffChunk>, DiffError> {
    let mut chunks: Vec<DiffChunk> = Vec::new();
    let mut current_file: Option<PathBuf> = None;
    let mut current_lines: Vec<(usize, String)> = Vec::new();
    let mut current_line_num: usize = 0;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("+++ b/") {
            // Save previous chunk
            if let Some(file) = current_file.take() {
                if !current_lines.is_empty() && !should_skip(&file, cfg) {
                    let ext = file
                        .extension()
                        .map(|e| e.to_string_lossy().to_string())
                        .unwrap_or_default();
                    chunks.push(DiffChunk {
                        file,
                        extension: ext,
                        added_lines: std::mem::take(&mut current_lines),
                    });
                } else {
                    current_lines.clear();
                }
            }
            current_file = Some(PathBuf::from(rest));
            current_line_num = 0;
        } else if line.starts_with("@@ ") {
            // Parse hunk header: @@ -a,b +c,d @@
            if let Some(new_info) = line.split('+').nth(1) {
                let num_str = new_info
                    .split(',')
                    .next()
                    .unwrap_or("0")
                    .split(' ')
                    .next()
                    .unwrap_or("0");
                current_line_num = num_str.parse().unwrap_or(0);
            }
        } else if let Some(added) = line.strip_prefix('+') {
            if current_file.is_some() {
                let content = added.to_string();
                // Respect provn:skip-file annotation, plus legacy aegis:skip-file.
                if content.contains("provn:skip-file") || content.contains("aegis:skip-file") {
                    current_lines.clear();
                    current_file = None;
                    continue;
                }
                // Skip provn:allow lines, plus legacy aegis:allow.
                if !content.contains("provn:allow") && !content.contains("aegis:allow") {
                    current_lines.push((current_line_num, content));
                }
                current_line_num += 1;
            }
        } else if line.starts_with(' ') {
            // Context line — advances the new-file line counter. Removed (-) lines
            // and diff headers do not exist in the new file, so they don't count.
            current_line_num += 1;
        }
    }

    // Push last chunk
    if let Some(file) = current_file {
        if !current_lines.is_empty() && !should_skip(&file, cfg) {
            let ext = file
                .extension()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_default();
            chunks.push(DiffChunk {
                file,
                extension: ext,
                added_lines: current_lines,
            });
        }
    }

    Ok(chunks)
}

/// Recursively collect scannable files under `root`, honoring Provn's exclude
/// rules and `.gitignore`. Used by `provn check <directory>` and `provn baseline`.
///
/// Files git would ignore (build output, vendored deps, local caches) are
/// dropped so scans are both faster and accurate. Outside a git repo, or if git
/// is unavailable, every walked file is kept.
pub fn walk_dir(root: &std::path::Path, cfg: &Config, out: &mut Vec<PathBuf>) {
    let mut candidates: Vec<PathBuf> = Vec::new();
    walk_raw(root, cfg, &mut candidates);

    // Keys are forward-slash, "./"-stripped strings so comparison is stable
    // across platforms (git wants forward slashes; Windows walks backslashes).
    let ignored = git_ignored_set(&candidates);
    for path in candidates {
        if !ignored.contains(&ignore_key(&path)) {
            out.push(path);
        }
    }
}

/// Normalize a path to the string form sent to / received from git check-ignore.
fn ignore_key(path: &std::path::Path) -> String {
    let s = path.to_string_lossy().replace('\\', "/");
    s.trim_start_matches("./").to_string()
}

fn walk_raw(root: &std::path::Path, cfg: &Config, out: &mut Vec<PathBuf>) {
    if should_skip(root, cfg) {
        return;
    }
    // Never follow symlinks: a symlink committed into a repo could otherwise
    // point at a file outside the tree (e.g. ~/.aws/credentials) and leak its
    // contents into scan output. symlink_metadata does not dereference.
    let meta = match std::fs::symlink_metadata(root) {
        Ok(m) => m,
        Err(_) => return,
    };
    if meta.file_type().is_symlink() {
        return;
    }
    if meta.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    if meta.is_dir() {
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                walk_raw(&entry.path(), cfg, out);
            }
        }
    }
}

/// Return the subset of `candidates` (as [`ignore_key`] strings) that git would
/// ignore, via a single `git check-ignore --stdin` call. Empty set if not a git
/// repo or git is missing, so scanning falls back to "keep everything".
fn git_ignored_set(candidates: &[PathBuf]) -> std::collections::HashSet<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut ignored = std::collections::HashSet::new();
    if candidates.is_empty() {
        return ignored;
    }

    // `--no-index` so check-ignore consults .gitignore for tracked paths too;
    // forward-slash keys so git (which wants /) matches and the echoed output
    // lines up with our candidate keys on every platform.
    let child = Command::new("git")
        .args(["check-ignore", "--no-index", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(_) => return ignored, // git not available — keep everything
    };

    if let Some(mut stdin) = child.stdin.take() {
        for p in candidates {
            let _ = writeln!(stdin, "{}", ignore_key(p));
        }
        // stdin dropped here, closing the pipe so git can finish.
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(_) => return ignored,
    };

    // Exit 0 = some paths ignored, 1 = none ignored, 128 = not a git repo.
    // In the 128 case stdout is empty, so we correctly keep everything.
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        ignored.insert(line.trim_start_matches("./").to_string());
    }
    ignored
}

fn should_skip(path: &std::path::Path, cfg: &Config) -> bool {
    // Skip excluded dirs — match whole path components, not substrings,
    // so `dist` does not skip `distributed/` and `build` does not skip `buildkit.py`.
    for component in path.components() {
        let comp = component.as_os_str().to_string_lossy();
        if cfg.exclude_dirs.iter().any(|dir| comp == dir.as_str()) {
            return true;
        }
    }

    // Skip excluded file patterns (simple glob: leading/trailing *)
    let filename = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    for pattern in &cfg.exclude_files {
        if let Some(suffix) = pattern.strip_prefix('*') {
            if filename.ends_with(suffix) {
                return true;
            }
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            if filename.starts_with(prefix) {
                return true;
            }
        } else if &filename == pattern {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::default()
    }

    #[test]
    fn skips_excluded_dir_component() {
        assert!(should_skip(
            std::path::Path::new("node_modules/pkg/index.js"),
            &cfg()
        ));
        assert!(should_skip(std::path::Path::new("src/dist/out.js"), &cfg()));
    }

    #[test]
    fn does_not_skip_substring_of_component() {
        // "dist" must not match "distributed", "build" must not match "buildkit.py"
        assert!(!should_skip(
            std::path::Path::new("distributed/worker.py"),
            &cfg()
        ));
        assert!(!should_skip(
            std::path::Path::new("src/buildkit.py"),
            &cfg()
        ));
    }

    #[test]
    fn skips_excluded_file_patterns() {
        assert!(should_skip(std::path::Path::new("Cargo.lock"), &cfg()));
        assert!(should_skip(std::path::Path::new("app.min.js"), &cfg()));
        assert!(!should_skip(std::path::Path::new("app.js"), &cfg()));
    }

    #[test]
    fn parses_added_lines_with_correct_numbers() {
        let diff = "\
diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -10,0 +11,2 @@
+first_added = 1
+second_added = 2
@@ -20,0 +30,1 @@
+third_added = 3
";
        let chunks = parse_diff_text(diff, &cfg()).unwrap();
        assert_eq!(chunks.len(), 1);
        let lines = &chunks[0].added_lines;
        assert_eq!(lines[0], (11, "first_added = 1".to_string()));
        assert_eq!(lines[1], (12, "second_added = 2".to_string()));
        assert_eq!(lines[2], (30, "third_added = 3".to_string()));
    }

    #[test]
    fn respects_allow_annotation() {
        let diff = "\
+++ b/src/app.py
@@ -0,0 +1,2 @@
+api_key = \"EXAMPLE_PLACEHOLDER_NOT_A_REAL_KEY\" # provn:allow
+clean_line = 1
";
        let chunks = parse_diff_text(diff, &cfg()).unwrap();
        assert_eq!(chunks[0].added_lines.len(), 1);
        assert_eq!(chunks[0].added_lines[0].1, "clean_line = 1");
    }

    #[test]
    fn skip_file_annotation_drops_whole_file() {
        let diff = "\
+++ b/src/gen.py
@@ -0,0 +1,2 @@
+# provn:skip-file
+would_be_scanned = 1
+++ b/src/other.py
@@ -0,0 +1,1 @@
+kept = 1
";
        let chunks = parse_diff_text(diff, &cfg()).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].file, std::path::PathBuf::from("src/other.py"));
    }
}
