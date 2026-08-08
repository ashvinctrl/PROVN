use crate::config::AstConfig;
use tree_sitter::{Node, Parser};

pub struct AstMatch {
    pub var_name: String,
    /// 1-based row in the scanned source. For diff scans the caller must map
    /// this back to the real file line via the added-lines table.
    pub line: usize,
    pub snippet: String,
    /// Inner string literal value — enables span-precise redaction.
    pub value: Option<String>,
    pub confidence: f64,
}

/// Scan `source` for sensitive variable assignments and return **all** matches.
///
/// Handles, per language:
///   Python      — `assignment` (left/right fields)
///   JS/TS/TSX   — `variable_declarator` (const/let/var), `assignment_expression`,
///                 and object literal `pair` entries
///   Java        — `variable_declarator` (field/local) and `assignment_expression`
///   Go          — `short_var_declaration` (`:=`), `assignment_statement`,
///                 and `var_spec`/`const_spec` (LHS/RHS wrapped in expression_list)
pub fn scan_source(source: &str, lang: &str, cfg: &AstConfig) -> Vec<AstMatch> {
    let language = match lang {
        "python" => tree_sitter_python::LANGUAGE.into(),
        "javascript" => tree_sitter_javascript::LANGUAGE.into(),
        "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        "java" => tree_sitter_java::LANGUAGE.into(),
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
    if let Some(m) = check_binding(node, src, cfg) {
        out.push(m);
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        scan_node(child, src, cfg, out);
    }
}

/// Go wraps assignment LHS/RHS in an `expression_list`; unwrap to the first
/// named child so single-value bindings expose their identifier/literal
/// directly. Multi-assignments (`a, b := x, y`) only surface the first pair,
/// which covers the overwhelmingly common single-secret case.
fn unwrap_expr_list(node: Node) -> Node {
    if node.kind() == "expression_list" {
        if let Some(first) = node.named_child(0) {
            return first;
        }
    }
    node
}

/// Extract (lhs, rhs) for any node kind that binds a name to a value.
fn binding_parts<'a>(node: Node<'a>) -> Option<(Node<'a>, Node<'a>)> {
    match node.kind() {
        // Python `x = ...`, JS/TS/Java `x = ...`
        "assignment" | "assignment_expression" => Some((
            node.child_by_field_name("left")?,
            node.child_by_field_name("right")?,
        )),
        // JS/TS `const x = ...` / `let` / `var`, and Java field/local declarators
        "variable_declarator" => Some((
            node.child_by_field_name("name")?,
            node.child_by_field_name("value")?,
        )),
        // JS/TS object literal `{ api_key: "..." }`
        "pair" => Some((
            node.child_by_field_name("key")?,
            node.child_by_field_name("value")?,
        )),
        // Go `x := "..."` and `x = "..."` (LHS/RHS are expression_lists)
        "short_var_declaration" | "assignment_statement" => Some((
            unwrap_expr_list(node.child_by_field_name("left")?),
            unwrap_expr_list(node.child_by_field_name("right")?),
        )),
        // Go `var x = "..."` / `const x = "..."` (value is an expression_list)
        "var_spec" | "const_spec" => Some((
            node.child_by_field_name("name")?,
            unwrap_expr_list(node.child_by_field_name("value")?),
        )),
        _ => None,
    }
}

fn is_string_node(kind: &str) -> bool {
    matches!(
        kind,
        "string"
            | "string_literal"
            | "template_string"
            | "concatenated_string"
            // Go string literals
            | "interpreted_string_literal"
            | "raw_string_literal"
    )
}

fn check_binding(node: Node, src: &[u8], cfg: &AstConfig) -> Option<AstMatch> {
    let (lhs, rhs) = binding_parts(node)?;

    // LHS may be an identifier, property_identifier, or member expression like
    // `config.api_key` — substring matching on the full text covers all three.
    let lhs_text = lhs.utf8_text(src).ok()?;
    let lhs_lower = lhs_text.to_lowercase();
    // Also compare with underscores stripped so camelCase names match
    // snake_case sensitive vars (apiKey ↔ api_key).
    let lhs_flat = lhs_lower.replace('_', "");
    let is_sensitive = cfg
        .sensitive_vars
        .iter()
        .any(|v| lhs_lower.contains(v.as_str()) || lhs_flat.contains(&v.replace('_', "")));
    if !is_sensitive {
        return None;
    }

    if !is_string_node(rhs.kind()) {
        return None;
    }

    let rhs_text = rhs.utf8_text(src).ok()?;
    let inner = rhs_text.trim_matches(|c| c == '"' || c == '\'' || c == '`');

    if inner.len() < 10 {
        return None;
    }

    if super::is_placeholder_value(inner) {
        return None;
    }

    let line = lhs.start_position().row + 1;
    let snippet = node.utf8_text(src).ok()?.chars().take(100).collect();

    // Factor entropy of the RHS value into the confidence score instead of
    // using string length alone — a long but low-entropy string is less suspicious.
    let entropy = shannon_entropy(inner);
    let confidence = match (entropy >= 4.0, inner.len() > 50) {
        (true, true) => 0.90,
        (true, false) => 0.80,
        (false, true) => 0.75,
        (false, false) => 0.60,
    };

    Some(AstMatch {
        var_name: lhs_text.to_string(),
        line,
        snippet,
        value: Some(inner.to_string()),
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
        let src = r#"system_prompt = "You are a financial advisor with proprietary scoring.""#; // provn:allow
        let results = scan_source(src, "python", &default_cfg());
        assert!(!results.is_empty());
        assert_eq!(results[0].var_name, "system_prompt");
    }

    #[test]
    fn detects_all_sensitive_assignments() {
        let src = concat!("system_prompt = \"You are a secret agent with classified intel.\"\napi_key = \"sk-proj-abcdefghijklmnop", "qrstuvwxyz123456\""); // provn:allow
        let results = scan_source(src, "python", &default_cfg());
        assert_eq!(results.len(), 2, "expected both assignments to be caught");
    }

    #[test]
    fn detects_js_const_declaration() {
        let key = concat!("sk-proj-abcdefghijklm", "nopqrstuvwxyz123456"); // provn:allow
        let src = format!("const apiKey = \"{key}\";");
        let results = scan_source(&src, "javascript", &default_cfg());
        assert_eq!(results.len(), 1, "const declaration must be detected");
        assert_eq!(results[0].var_name, "apiKey");
    }

    #[test]
    fn detects_js_let_and_assignment() {
        let src =
            "let secretValue = \"abcdefghijklmnop\";\nconfig.password = \"hunter22hunter22\";"; // provn:allow
        let results = scan_source(src, "javascript", &default_cfg());
        assert_eq!(
            results.len(),
            2,
            "let + member assignment must both be detected"
        );
    }

    #[test]
    fn detects_js_object_literal_pair() {
        let src = r#"const cfg = { api_key: "abcdefghijklmnopqrstuvwx" };"#; // provn:allow
        let results = scan_source(src, "javascript", &default_cfg());
        assert!(results.iter().any(|m| m.var_name == "api_key"));
    }

    #[test]
    fn detects_typescript_with_type_annotation() {
        let key = concat!("sk-proj-abcdefghijklm", "nopqrstuvwxyz123456"); // provn:allow
        let src = format!("const apiKey: string = \"{key}\";");
        let results = scan_source(&src, "typescript", &default_cfg());
        assert_eq!(results.len(), 1, "typed TS declaration must be detected");
    }

    #[test]
    fn reports_correct_row_for_multiline_source() {
        let src = concat!("x = 1\ny = 2\napi_key = \"abcdefghijkl", "mnopqrstuvwx\""); // provn:allow
        let results = scan_source(src, "python", &default_cfg());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].line, 3);
    }

    #[test]
    fn captures_inner_value_for_redaction() {
        let src = r#"api_key = "abcdefghijklmnopqrstuvwx""#; // provn:allow
        let results = scan_source(src, "python", &default_cfg());
        assert_eq!(
            results[0].value.as_deref(),
            Some(concat!("abcdefghijkl", "mnopqrstuvwx"))
        );
    }

    #[test]
    fn skips_test_values() {
        let src = r#"api_key = "test_key_placeholder""#; // provn:allow
        let results = scan_source(src, "python", &default_cfg());
        assert!(results.is_empty(), "test_ prefixed values must be skipped");
    }

    #[test]
    fn skips_template_placeholders() {
        let src = r#"api_key = "${API_KEY_FROM_ENV}""#; // provn:allow
        let results = scan_source(src, "python", &default_cfg());
        assert!(results.is_empty(), "${{...}} placeholders must be skipped");
    }

    #[test]
    fn allows_non_sensitive_vars() {
        let src =
            r#"greeting = "Hello, World! This is a long enough string to trigger length checks.""#;
        let results = scan_source(src, "python", &default_cfg());
        assert!(results.is_empty());
    }

    #[test]
    fn detects_encryption_key_with_default_config() {
        // `encryption_key` isn't a substring of any base name; it's caught via
        // the credential-key names added to the shipped default config.
        let src = concat!(
            "encryption_key = \"EXAMPLEfake_aes_key_012345",
            "6789abcdef0123456789ab\""
        ); // provn:allow
        let results = scan_source(src, "python", &AstConfig::default());
        assert_eq!(
            results.len(),
            1,
            "encryption_key assignment must be detected"
        );
        assert_eq!(results[0].var_name, "encryption_key");
    }

    #[test]
    fn skips_angle_bracket_placeholder() {
        let src = r#"password = "<YOUR_PASSWORD>""#; // provn:allow
        let results = scan_source(src, "python", &default_cfg());
        assert!(results.is_empty(), "<...> placeholders must be skipped");
    }

    #[test]
    fn skips_your_x_here_placeholder() {
        let src = r#"api_key = "your-api-key-here""#; // provn:allow
        let results = scan_source(src, "python", &default_cfg());
        assert!(
            results.is_empty(),
            "your-...-here placeholders must be skipped"
        );
    }

    #[test]
    fn detects_go_short_var_declaration() {
        let key = concat!("sk-proj-abcdefghijklm", "nopqrstuvwxyz123456"); // provn:allow
        let src = format!("package main\nfunc main() {{\n\tapiKey := \"{key}\"\n}}");
        let results = scan_source(&src, "go", &default_cfg());
        assert_eq!(results.len(), 1, "Go := short var decl must be detected");
        assert_eq!(results[0].var_name, "apiKey");
    }

    #[test]
    fn detects_go_var_and_const_declaration() {
        let src = concat!(
            "package main\n",
            "var apiKey = \"abcdefghijkl",
            "mnopqrstuvwx\"\n",
            "const token = \"hunter22hunter22\"\n"
        ); // provn:allow
        let results = scan_source(src, "go", &default_cfg());
        assert_eq!(
            results.len(),
            2,
            "Go var + const decls must both be detected"
        );
    }

    #[test]
    fn detects_go_assignment_statement() {
        let src = "package main\nfunc main() {\n\tpassword = \"Pr0dDbP@ssw0rd2025\"\n}"; // provn:allow
        let results = scan_source(src, "go", &default_cfg());
        assert!(results.iter().any(|m| m.var_name == "password"));
    }

    #[test]
    fn detects_java_field_declaration() {
        let key = concat!("sk-proj-abcdefghijklm", "nopqrstuvwxyz123456"); // provn:allow
        let src = format!("class Config {{ String apiKey = \"{key}\"; }}");
        let results = scan_source(&src, "java", &default_cfg());
        assert_eq!(results.len(), 1, "Java field declaration must be detected");
        assert_eq!(results[0].var_name, "apiKey");
    }

    #[test]
    fn detects_java_local_and_assignment() {
        let src = concat!(
            "class C {\n",
            "  void run() {\n",
            "    String secret = \"abcdefghijklmnop\";\n", // provn:allow
            "    this.password = \"hunter22hunter22\";\n", // provn:allow
            "  }\n",
            "}\n"
        );
        let results = scan_source(src, "java", &default_cfg());
        assert_eq!(
            results.len(),
            2,
            "Java local var + field assignment must both be detected"
        );
    }

    #[test]
    fn go_raw_string_literal_is_detected() {
        // Go backtick raw strings must be unquoted and scanned like normal strings.
        let src = "package main\nfunc main() {\n\tapiKey := `abcdefghijklmnopqrst`\n}"; // provn:allow
        let results = scan_source(src, "go", &default_cfg());
        assert_eq!(results.len(), 1, "Go raw string literal must be detected");
    }

    #[test]
    fn go_non_sensitive_var_not_flagged() {
        let src = "package main\nfunc main() {\n\ttimeout := \"thirty seconds total\"\n}";
        let results = scan_source(src, "go", &default_cfg());
        assert!(results.is_empty(), "non-sensitive Go var must not flag");
    }

    #[test]
    fn benign_key_names_are_not_flagged() {
        // Common non-credential `*_key` names must stay clean even with long
        // literal values — they are not in the credential-name list.
        for src in [
            r#"primary_key = "user_id_column_name""#,   // provn:allow
            r#"cache_key = "user:1234:profile:v2""#,    // provn:allow
            r#"partition_key = "tenant-acme-2026-q2""#, // provn:allow
        ] {
            let results = scan_source(src, "python", &AstConfig::default());
            assert!(results.is_empty(), "benign key name flagged: {src}");
        }
    }
}
