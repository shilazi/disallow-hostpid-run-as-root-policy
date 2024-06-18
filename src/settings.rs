use std::collections::HashSet;

use kubewarden::logging;
use lazy_static::lazy_static;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use slog::{info, o, warn, Logger};

// Log prefix for policy server of this policy.
pub(crate) const POLICY_NAME: &str = "disallow-hostpid-run-as-root-policy";

pub(crate) const USIZE_63: usize = 63;
pub(crate) const USIZE_253: usize = 253;
// Regex used to validate the kubernetes object name.
pub(crate) const KUBERNETES_OBJECT_NAME_REGEX: &str = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$";

lazy_static! {
    static ref LOG_DRAIN: Logger =
        Logger::root(logging::KubewardenDrain::new(), o!("policy" => POLICY_NAME));
}

// Describe the settings your policy expects when
// loaded by the policy server.
#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
pub(crate) struct Settings {
    // exempt with service account by username
    pub(crate) exempt_usernames: Option<HashSet<String>>,
    // exempt with Namespace
    pub(crate) exempt_namespaces: Option<HashSet<String>>,
}

// Kubernetes object name char regex
fn validate_kubernetes_object_name_regex(obj_name: &str) -> bool {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(KUBERNETES_OBJECT_NAME_REGEX).unwrap());
    RE.is_match(obj_name)
}

impl Settings {
    // exempt return true，otherwise return false
    pub(crate) fn exempt(&self, username: &String, namespace: &String) -> bool {
        if let Some(usernames) = &self.exempt_usernames {
            if usernames.contains(username) {
                return true;
            }
        }
        if let Some(namespaces) = &self.exempt_namespaces {
            if namespaces.contains(namespace) {
                return true;
            }
        }
        false
    }
}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        info!(LOG_DRAIN, "starting settings validation");

        if let Some(usernames) = &self.exempt_usernames {
            for username in usernames.iter() {
                if username.len() > USIZE_253 || !validate_kubernetes_object_name_regex(username) {
                    return Err(format!("exempt_username with invalid name: {}", username));
                }
            }
        }

        if let Some(namespaces) = &self.exempt_namespaces {
            for namespace in namespaces.iter() {
                if namespace.len() > USIZE_63 || !validate_kubernetes_object_name_regex(namespace) {
                    return Err(format!("exempt_namespace with invalid name: {}", namespace));
                }
            }
        }

        warn!(LOG_DRAIN, "settings validates");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use kubewarden::settings::Validatable;

    use crate::settings::Settings;

    #[test]
    fn valid_validate_settings() -> Result<(), ()> {
        let exempt_usernames =
            HashSet::from(["valid-name".to_string(), "valid-name-123".to_string()]);

        let settings = Settings {
            exempt_usernames: Some(exempt_usernames),
            exempt_namespaces: None,
        };

        assert!(settings.validate().is_ok());
        Ok(())
    }

    #[test]
    fn invalid_validate_settings() -> Result<(), ()> {
        let exempt_usernames = HashSet::from([
            "Invalid-Name".to_string(),
            "invalid_name".to_string(),
            "12345".to_string(),
            "-invalid".to_string(),
            "invalid-".to_string(),
        ]);

        let settings = Settings {
            exempt_usernames: Some(exempt_usernames),
            exempt_namespaces: None,
        };

        assert!(settings.validate().is_err());
        Ok(())
    }
}
