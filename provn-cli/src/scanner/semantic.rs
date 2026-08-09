//! Layer 3 client.
//!
//! Both supported backends speak the same OpenAI-style
//! `/v1/chat/completions` API, so one client covers a local `llama-server`
//! and a hosted endpoint the user supplies their own key for.
//!
//! ## Local-first
//!
//! Provn's default is that source code never leaves the machine. A hosted
//! backend breaks that by definition, so it is opt-in twice over: the config
//! must name an environment variable (`layers.semantic.api_key_env`) *and*
//! that variable must be set. When a scan is about to send snippets to a
//! non-loopback host, `Backend::warn_once_if_remote` says so on stderr rather
//! than letting it happen silently.

use crate::config::SemanticConfig;
use serde::Deserialize;
use std::time::Duration;

pub struct SemanticResult {
    pub label: String, // "leak" or "clean"
    pub skipped: bool, // true if server unavailable or timed out
}

const SYSTEM: &str = "You are a code security classifier. \
Respond with exactly one word: leak or clean. No explanation.";

#[derive(Deserialize)]
struct ChatMessage {
    content: String,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatMessage,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

/// Everything the Layer 3 call needs, resolved once per scan.
#[derive(Clone)]
pub struct Backend {
    pub endpoint: String,
    pub timeout_ms: u64,
    /// Bearer token, read from the environment variable named in the config.
    pub api_key: Option<String>,
    /// Model id to request. Required by hosted APIs, ignored by llama-server.
    pub model: Option<String>,
}

impl Backend {
    pub fn from_config(cfg: &SemanticConfig) -> Self {
        // The key is read from the environment, never from provn.yml.
        let api_key = cfg
            .api_key_env
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .and_then(|name| std::env::var(name).ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        Self {
            endpoint: cfg.endpoint.clone(),
            timeout_ms: cfg.timeout_ms,
            api_key,
            model: cfg
                .api_model
                .as_deref()
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .map(str::to_string),
        }
    }

    /// True when the configured endpoint points somewhere other than this
    /// machine, i.e. when scanning would transmit code off-box.
    pub fn is_remote(&self) -> bool {
        !is_loopback_endpoint(&self.endpoint)
    }

    /// Print a one-time notice when Layer 3 is about to leave the machine.
    /// Silence here would undermine the guarantee the rest of the tool makes.
    pub fn warn_once_if_remote(&self) {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        if !self.is_remote() {
            return;
        }
        ONCE.call_once(|| {
            eprintln!(
                "  [provn] Layer 3 is sending code snippets to {} — this is not a local scan",
                host_of(&self.endpoint).unwrap_or_else(|| self.endpoint.clone())
            );
        });
    }
}

/// Host portion of an endpoint URL, without scheme, port, or path.
fn host_of(endpoint: &str) -> Option<String> {
    let rest = endpoint
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(endpoint);
    let host = rest.split(['/', '?']).next()?;
    // Strip userinfo, then the port. IPv6 literals are bracketed, so a colon
    // inside brackets is part of the address rather than a port separator.
    let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host);
    if let Some(end) = host.find(']') {
        return Some(host[..=end].to_string());
    }
    Some(
        host.rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host)
            .to_string(),
    )
}

/// True when the endpoint addresses this machine.
fn is_loopback_endpoint(endpoint: &str) -> bool {
    match host_of(endpoint) {
        Some(h) => {
            let h = h.trim().trim_start_matches('[').trim_end_matches(']');
            h.eq_ignore_ascii_case("localhost")
                || h == "::1"
                || h.parse::<std::net::Ipv4Addr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false)
                || h.parse::<std::net::Ipv6Addr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false)
        }
        None => false,
    }
}

/// Call the backend's `/v1/chat/completions` endpoint.
/// Returns `skipped=true` when it is unreachable, returns an unexpected
/// response, or exceeds `timeout_ms`.
pub fn classify(code: &str, backend: &Backend) -> SemanticResult {
    // Derive the chat completions URL from whatever endpoint is configured.
    // Support both bare base URLs (http://host:port) and explicit paths.
    let endpoint = &backend.endpoint;
    let url = if endpoint.ends_with("/v1/chat/completions") {
        endpoint.to_string()
    } else {
        // Strip any trailing path and append the standard route.
        let base = endpoint
            .trim_end_matches('/')
            .trim_end_matches("/completion");
        format!("{}/v1/chat/completions", base)
    };

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(backend.timeout_ms))
        .build()
    {
        Ok(c) => c,
        Err(_) => return skipped(),
    };

    let mut body = serde_json::json!({
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user",   "content": format!("Classify:\n```\n{code}\n```")},
        ],
        "temperature": 0.0,
        "max_tokens": 500,
    });
    if let Some(model) = &backend.model {
        body["model"] = serde_json::Value::String(model.clone());
    }

    let mut req = client.post(&url).json(&body);
    if let Some(key) = &backend.api_key {
        req = req.bearer_auth(key);
    }

    match req.send() {
        Ok(resp) => match resp.json::<ChatResponse>() {
            Ok(cr) => match cr.choices.first() {
                Some(choice) => match parse_label(&choice.message.content) {
                    Some(label) => SemanticResult {
                        label: label.into(),
                        skipped: false,
                    },
                    None => skipped(),
                },
                None => skipped(),
            },
            Err(_) => skipped(),
        },
        Err(_) => skipped(),
    }
}

fn skipped() -> SemanticResult {
    SemanticResult {
        label: "clean".into(),
        skipped: true,
    }
}

fn parse_label(content: &str) -> Option<&'static str> {
    let text = content.trim().to_lowercase();
    if text.starts_with("leak") {
        Some("leak")
    } else if text.starts_with("clean") {
        Some("clean")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SemanticConfig;

    #[test]
    fn accepts_leak_prefix() {
        assert_eq!(parse_label("leak"), Some("leak"));
        assert_eq!(parse_label("Leak detected"), Some("leak"));
    }

    #[test]
    fn accepts_clean_prefix() {
        assert_eq!(parse_label("clean"), Some("clean"));
        assert_eq!(parse_label("clean\n"), Some("clean"));
    }

    #[test]
    fn rejects_unexpected_tokens() {
        assert_eq!(parse_label("<unused25><unused25>"), None);
        assert_eq!(parse_label(""), None);
    }

    #[test]
    fn loopback_endpoints_are_local() {
        for ep in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://127.2.3.4:8080",
            "http://[::1]:8080",
            "http://LOCALHOST:8080/v1/chat/completions",
        ] {
            assert!(is_loopback_endpoint(ep), "{ep} should be local");
        }
    }

    #[test]
    fn hosted_endpoints_are_remote() {
        for ep in [
            "https://integrate.api.nvidia.com/v1/chat/completions",
            "https://api.openai.com/v1",
            "http://192.168.1.10:8080",
            "http://10.0.0.5:8080",
        ] {
            assert!(!is_loopback_endpoint(ep), "{ep} should be remote");
        }
    }

    #[test]
    fn default_config_is_local_and_unauthenticated() {
        // The local-first guarantee: an untouched config never carries a key
        // and never points off-box.
        let b = Backend::from_config(&SemanticConfig::default());
        assert!(b.api_key.is_none());
        assert!(b.model.is_none());
        assert!(!b.is_remote());
    }

    #[test]
    fn api_key_comes_from_the_environment_not_the_config() {
        let var = "PROVN_TEST_KEY_FROM_ENV";
        let cfg = SemanticConfig {
            api_key_env: Some(var.to_string()),
            ..SemanticConfig::default()
        };

        // Unset → no key, so a misconfigured repo cannot silently authenticate.
        std::env::remove_var(var);
        assert!(Backend::from_config(&cfg).api_key.is_none());

        std::env::set_var(var, "secret-value");
        assert_eq!(
            Backend::from_config(&cfg).api_key.as_deref(),
            Some("secret-value")
        );
        std::env::remove_var(var);
    }

    #[test]
    fn blank_env_var_name_is_ignored() {
        let cfg = SemanticConfig {
            api_key_env: Some("   ".to_string()),
            ..SemanticConfig::default()
        };
        assert!(Backend::from_config(&cfg).api_key.is_none());
    }

    #[test]
    fn host_is_extracted_without_port_or_path() {
        assert_eq!(
            host_of("https://api.example.com:443/v1"),
            Some("api.example.com".into())
        );
        assert_eq!(host_of("http://[::1]:8080/v1"), Some("[::1]".into()));
        assert_eq!(
            host_of("http://user:pw@example.com:9/v1"),
            Some("example.com".into())
        );
    }
}
