use crate::config;
use crate::providers::codex::catalog;

use super::request::ServiceTier;

/// Allowed models come from the model catalog (`supported_in_api`).
pub fn allowed_models() -> Vec<String> {
    catalog::current().allowed_slugs()
}

pub fn allowed_models_display() -> String {
    allowed_models().join(", ")
}

/// The one alias table: Anthropic-style names and their Codex targets. The
/// registry routes these names to the alias provider.
pub const MODEL_ALIASES: &[(&str, &str)] = &[
    ("haiku", "gpt-6-luna"),
    ("claude-haiku-4-5", "gpt-6-luna"),
    ("claude-haiku-4-5-20251001", "gpt-6-luna"),
    ("sonnet", "gpt-5.6-terra"),
    ("claude-sonnet-4-6", "gpt-5.6-terra"),
    ("claude-sonnet-5", "gpt-5.6-terra"),
    ("opus", "gpt-6-sol"),
    ("claude-opus-4-7", "gpt-6-sol"),
    ("claude-opus-4-8", "gpt-6-sol"),
    ("claude-opus-5", "gpt-6-sol"),
    ("claude-opus-5-5", "gpt-6-sol"),
    ("fable", "gpt-6-sol"),
    ("claude-fable-5", "gpt-6-sol"),
];

#[derive(Debug, Clone)]
pub struct ResolvedModel {
    pub model: String,
    pub service_tier: Option<ServiceTier>,
}

/// `<slug>-fast` for an allowed `<slug>` resolves to that slug on the
/// priority tier.
pub fn fast_model_base(model: &str) -> Option<&str> {
    model
        .strip_suffix("-fast")
        .filter(|base| catalog::current().is_allowed(base))
}

fn resolve_fast_model_alias(model: &str) -> ResolvedModel {
    if let Some(base) = fast_model_base(model) {
        ResolvedModel {
            model: base.to_string(),
            service_tier: Some(ServiceTier::Priority),
        }
    } else {
        ResolvedModel {
            model: model.to_string(),
            service_tier: None,
        }
    }
}

pub fn resolve_model_request(model: &str) -> ResolvedModel {
    resolve_model_request_with_config_override(model, true)
}

pub fn resolve_model_request_with_config_override(
    model: &str,
    apply_config_override: bool,
) -> ResolvedModel {
    let alias = MODEL_ALIASES
        .iter()
        .find(|(alias, _)| *alias == model)
        .map(|(_, target)| *target)
        .unwrap_or(model);

    let requested = resolve_fast_model_alias(alias);

    let override_model = apply_config_override.then(config::codex_model).flatten();
    let resolved = match override_model {
        Some(ref val) if !val.is_empty() => resolve_fast_model_alias(val),
        _ => requested.clone(),
    };

    ResolvedModel {
        model: resolved.model,
        service_tier: if requested.service_tier == Some(ServiceTier::Priority)
            || resolved.service_tier == Some(ServiceTier::Priority)
        {
            Some(ServiceTier::Priority)
        } else {
            resolved.service_tier
        },
    }
}

pub fn resolve_model(model: &str) -> String {
    resolve_model_request(model).model
}

#[derive(Debug, Clone)]
pub struct ModelNotAllowedError {
    pub model: String,
}

impl std::fmt::Display for ModelNotAllowedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Model not allowed: {}", self.model)
    }
}

pub fn assert_allowed_model(model: &str) -> Result<(), ModelNotAllowedError> {
    if catalog::current().is_allowed(model) {
        Ok(())
    } else {
        Err(ModelNotAllowedError {
            model: model.to_string(),
        })
    }
}

/// The catalog's `use_responses_lite`; models missing from it use the full lane.
pub fn uses_responses_lite(model: &str) -> bool {
    catalog::current().uses_responses_lite(model)
}

/// Luna models exist only behind the Responses Lite lane; the full
/// Responses API resolves them to a `-free` variant and returns 404 (Model not
/// found gpt-5.6-luna-free-...). Hosted web_search requests must run on the
/// full lane, so luna is upgraded to its nearest full-lane sibling. The
/// catalog does not say which lite-lane models also exist on the full lane
/// (its `supports_search_tool` is about tool search, not hosted web search),
/// so this stays a static table.
pub const LITE_ONLY_WEB_SEARCH_UPGRADES: &[(&str, &str)] =
    &[("gpt-5.6-luna", "gpt-5.6-sol"), ("gpt-6-luna", "gpt-6-sol")];

pub fn full_lane_web_search_model(model: &str) -> &str {
    LITE_ONLY_WEB_SEARCH_UPGRADES
        .iter()
        .find(|(lite_only, _)| *lite_only == model)
        .map(|(_, full_lane)| *full_lane)
        .unwrap_or(model)
}

pub fn is_alias(model: &str) -> bool {
    MODEL_ALIASES.iter().any(|(alias, _)| *alias == model)
}

pub fn is_valid_model_for_codex(model: &str) -> bool {
    catalog::current().accepts(model) || is_alias(model)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn haiku_resolves_to_luna() {
        let r = resolve_model_request("haiku");
        assert_eq!(r.model, "gpt-6-luna");
    }

    #[test]
    fn web_search_upgrades_luna_to_full_lane_sibling() {
        assert_eq!(full_lane_web_search_model("gpt-5.6-luna"), "gpt-5.6-sol");
        assert_eq!(full_lane_web_search_model("gpt-5.6-sol"), "gpt-5.6-sol");
        assert_eq!(full_lane_web_search_model("gpt-5.6-terra"), "gpt-5.6-terra");
        assert_eq!(full_lane_web_search_model("gpt-5.4"), "gpt-5.4");
        assert_eq!(full_lane_web_search_model("gpt-6-luna"), "gpt-6-sol");
        assert_eq!(full_lane_web_search_model("gpt-6-sol"), "gpt-6-sol");
    }

    #[test]
    fn sonnet_resolves_to_terra() {
        let r = resolve_model_request("sonnet");
        assert_eq!(r.model, "gpt-5.6-terra");
    }

    #[test]
    fn sonnet_5_resolves_to_terra() {
        let r = resolve_model_request("claude-sonnet-5");
        assert_eq!(r.model, "gpt-5.6-terra");
    }

    #[test]
    fn opus_resolves_to_sol() {
        let r = resolve_model_request("opus");
        assert_eq!(r.model, "gpt-6-sol");
    }

    #[test]
    fn opus_aliases_resolve_to_sol() {
        for model in ["claude-opus-4-8", "claude-opus-5", "claude-opus-5-5"] {
            let r = resolve_model_request(model);
            assert_eq!(r.model, "gpt-6-sol");
        }
    }

    #[test]
    fn fable_5_resolves_to_sol() {
        for model in ["fable", "claude-fable-5"] {
            let r = resolve_model_request(model);
            assert_eq!(r.model, "gpt-6-sol");
        }
    }

    #[test]
    fn gpt_6_sol_fast_adds_priority() {
        let r = resolve_model_request("gpt-6-sol-fast");
        assert_eq!(r.model, "gpt-6-sol");
        assert_eq!(r.service_tier, Some(ServiceTier::Priority));
    }

    #[test]
    fn gpt_6_models_use_responses_lite() {
        assert!(uses_responses_lite("gpt-6-sol"));
        assert!(uses_responses_lite("gpt-6-luna"));
    }

    #[test]
    fn fast_suffix_adds_priority() {
        let r = resolve_model_request("gpt-5.6-sol-fast");
        assert_eq!(r.model, "gpt-5.6-sol");
        assert_eq!(r.service_tier, Some(ServiceTier::Priority));
    }

    #[test]
    fn allowed_models_accept_base() {
        assert!(assert_allowed_model("gpt-5.4").is_ok());
        assert!(assert_allowed_model("gpt-5.6-sol").is_ok());
        assert!(assert_allowed_model("gpt-5.6-terra").is_ok());
        assert!(assert_allowed_model("gpt-6-astra").is_ok());
        assert!(assert_allowed_model("gpt-5.6-luna").is_ok());
    }

    #[test]
    fn not_allowed_rejected() {
        assert!(assert_allowed_model("gpt-7").is_err());
    }
}
