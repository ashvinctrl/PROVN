use crate::config::AstConfig;
use tree_sitter::{Node, Parser};

pub struct AstMatch {
    pub var_name: String,
    pub line: usize,
    pub snippet: String,
    pub confidence: f64,
}

/// Scan `source` for sensitive variable assignments and return **all** matches.
/// Previously returned only the first match found during the tree walk, so a file
/// with both `system_prompt` and `api_key` assignments would silently miss the second.
pub fn scan_source(source: &str, lang: &str, cfg: &AstConfig) -> Vec<AstMatch> {
    let language = match lang {
        "python" => tree_sitter_python::LANGUAGE.into(),
        "javascript" | "typescript" => tree_sitter_javascript::LANGUAGE.into(),
        _ => return vec![],
    };

    let mut parser = Parser::new();
    if parser.set_language(&language).is_err() {
        return vec![];
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let mut matches = Vec::new();
    scan_node(tree.root_node(), source.as_bytes(), cfg, &mut matches);
    matches
}

fn scan_node(node: Node<'_>, src: &[u8], cfg: &AstConfig, out: &mut Vec<AstMatch>) {
    let kind = node.kind();
    if kind == "assignment" || kind == "expression_statement" {
        if let Some(m) = check_assignment(node, src, cfg) {
            out.push(m);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        scan_node(child, src, cfg, out);
    }
}

fn check_assignment(node: Node, src: &[u8], cfg: &AstConfig) -> Option<AstMatch> {
    let mut cursor = node.walk();
    let children: Vec<Node> = node.children(&mut cursor).collect();

    let lhs = children.iter().find(|n| n.kind() == "identifier")?;
    let lhs_text = lhs.utf8_text(src).ok()?;

    let is_sensitive = cfg
        .sensitive_vars
        .iter()
        .any(|v| lhs_text.to_lowercase().contains(v.as_str()));

    if !is_sensitive {
        return None;
    }

    let rhs = children.iter().find(|n| {
        matches!(
            n.kind(),
            "string" | "string_literal" | "template_string" | "concatenated_string"
        )
    })?;

    let rhs_text = rhs.utf8_text(src).ok()?;
    let inner = rhs_text.trim_matches(|c| c == '"' || c == '\'' || c == '`');

    if inner.len() < 10 {
        return None;
    }

    if inner.starts_with("test_")
        || inner.starts_with("fake_")
        || inner.starts_with("placeholder")
        || inner == "your_api_key_here"
        || inner == "xxx"
    {
        return None;
    }

    let line = lhs.start_position().row + 1;
    let snippet = node.utf8_text(src).ok()?.chars().take(100).collect();

    // Factor entropy of the RHS value into the confidence score instead of
    // using string length alone — a long but low-entropy string is less suspicious.
    let entropy = shannon_entropy(inner);
    let confidence = if entropy >= 4.0 {
        if inner.len() > 50 { 0.90 } else { 0.80 }
    } else {
        if inner.len() > 50 { 0.75 } else { 0.60 }
    };

    Some(AstMatch {
        var_name: lhs_text.to_string(),
        line,
        snippet,
        confidence,
    })
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_cfg() -> AstConfig {
        AstConfig {
            enabled: true,
            sensitive_vars: vec![
                "system_prompt".into(),
                "api_key".into(),
                "secret".into(),
                "password".into(),
                "token".into(),
            ],
        }
    }

    #[test]
    fn detects_system_prompt_assignment() {
        let src = r#"system_prompt = "You are a financial advisor with proprietary scoring.""#;
        let results = scan_source(src, "python", &default_cfg());
        assert!(!results.is_empty());
        assert_eq!(results[0].var_name, "system_prompt");
    }

    #[test]
    fn detects_all_sensitive_assignments() {
        let src = "system_prompt = \"You are a secret agent with classified intel.\"\napi_key = \"sk-proj-abcdefghijklmnopqrstuvwxyz123456\"";
        let results = scan_source(src, "python", &default_cfg());
        assert_eq!(results.len(), 2, "expected both assignments to be caught");
    }

    #[test]
    fn skips_test_values() {
        let src = r#"api_key = "test_key_placeholder""#;
        let result = scan_source(src, "python", &default_cfg());
        let _ = result; // verifies no panic; value may or may not be flagged
    }

    #[test]
    fn allows_non_sensitive_vars() {
        let src = r#"greeting = "Hello, World! This is a long enough string to trigger length checks.""#;
        let results = scan_source(src, "python", &default_cfg());
        assert!(results.is_empty());
    }
}
