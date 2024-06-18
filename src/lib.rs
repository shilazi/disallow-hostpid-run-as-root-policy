use anyhow::{anyhow, Result};
use lazy_static::lazy_static;

use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

use k8s_openapi::api::batch::v1::CronJob as v1_cronJob;
use k8s_openapi::api::batch::v1beta1::CronJob as v1beta1_cronJob;
use k8s_openapi::api::core::v1 as apicore;
use k8s_openapi::Resource;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use settings::Settings;

use slog::{info, o, warn, Logger};

lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => settings::POLICY_NAME)
    );
}

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate(payload: &[u8]) -> CallResult {
    let mut validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;

    info!(LOG_DRAIN, "starting validation");
    if validation_request.request.dry_run {
        info!(LOG_DRAIN, "dry run mode, accepting resource");
        return kubewarden::accept_request();
    }

    // service account username
    let username = &validation_request.request.user_info.username;
    // obj name
    let obj_name = &validation_request.request.name;
    // namespace
    let namespace = &validation_request.request.namespace;
    // operation
    let operation = &validation_request.request.operation;
    // kind
    let kind = &validation_request.request.kind.kind;
    // version
    let version = &validation_request.request.kind.version;

    info!(LOG_DRAIN,  "{} {}", operation.to_lowercase(), kind, ; "name" => obj_name, "namespace" => namespace);
    if validation_request.settings.exempt(username, namespace) {
        warn!(LOG_DRAIN, "accepting {} with exemption", kind);
        return kubewarden::accept_request();
    }

    // when kind was CronJob, convert batch/v1beta1 to batch/v1
    // adapt for validation_request.extract_pod_spec_from_object method
    if kind == v1beta1_cronJob::KIND && version == v1beta1_cronJob::VERSION {
        let v1beta1_object = &serde_json::to_string(&validation_request.request.object.clone())
            .unwrap()
            .replace(v1beta1_cronJob::VERSION, v1_cronJob::VERSION);
        validation_request.request.object = serde_json::from_str(v1beta1_object).unwrap();
    }

    match validation_request.extract_pod_spec_from_object() {
        Ok(pod_spec) => {
            if let Some(pod_spec) = pod_spec {
                if !pod_spec.host_pid.unwrap_or(false) {
                    info!(LOG_DRAIN, "accepting {} with hostPID false", kind);
                    return kubewarden::accept_request();
                }
                return match validate_pod(&pod_spec) {
                    Ok(_) => {
                        info!(
                            LOG_DRAIN,
                            "accepting {} with hostPID, SecurityContext.runAsNonRoot already true",
                            kind
                        );
                        kubewarden::accept_request()
                    }
                    Err(err) => {
                        warn!(LOG_DRAIN,
                            "reject {} run with hostPID true and securityContext.runAsNonRoot was not set",
                            kind
                        );
                        kubewarden::reject_request(Some(err.to_string()), None, None, None)
                    }
                };
            };
            info!(LOG_DRAIN, "accepting {} with invalid pod spec", kind);
            kubewarden::accept_request()
        }
        Err(_) => {
            warn!(LOG_DRAIN, "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it");
            kubewarden::accept_request()
        }
    }
}

fn validate_pod(pod_spec: &apicore::PodSpec) -> Result<bool> {
    let mut pod_valid = false;
    if let Some(security_context) = &pod_spec.security_context {
        pod_valid = security_context.run_as_non_root.unwrap_or(false)
    }
    for container in &pod_spec.containers {
        let container_valid = validate_container(container);
        if !pod_valid && !container_valid {
            return Err(anyhow!("Container run as root with hostPID is not allowed"));
        }
    }
    if let Some(init_containers) = &pod_spec.init_containers {
        for container in init_containers {
            let container_valid = validate_container(container);
            if !pod_valid && !container_valid {
                return Err(anyhow!(
                    "Init container run as root with hostPID is not allowed"
                ));
            }
        }
    }
    if let Some(ephemeral_containers) = &pod_spec.ephemeral_containers {
        for container in ephemeral_containers {
            let container_valid = validate_ephemeral_container(container);
            if !pod_valid && !container_valid {
                return Err(anyhow!(
                    "Ephemeral container run as root with hostPID is not allowed"
                ));
            }
        }
    }
    Ok(true)
}

fn validate_ephemeral_container(container: &apicore::EphemeralContainer) -> bool {
    if let Some(security_context) = &container.security_context {
        return security_context.run_as_non_root.unwrap_or(false);
    }
    false
}

fn validate_container(container: &apicore::Container) -> bool {
    if let Some(security_context) = &container.security_context {
        return security_context.run_as_non_root.unwrap_or(false);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use kubewarden_policy_sdk::test::Testcase;

    #[test]
    fn reject_obj_with_hostpid() -> Result<(), ()> {
        let request_file = "test_data/pod_creation.json";
        // let request_file = "test_data/deployment_creation.json";
        // let request_file = "test_data/replicaset_creation.json";
        // let request_file = "test_data/cronjob_v1_creation.json";
        let tc = Testcase {
            name: String::from("Reject pod"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings::default(),
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn reject_batchv1beta1_cronjob_with_hostpid() -> Result<(), ()> {
        let request_file = "test_data/cronjob_creation.json";
        let tc = Testcase {
            name: String::from("Reject batch/v1beta1 cronjob"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings::default(),
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn accept_pod_without_hostpid() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_without_hostPID.json";
        let tc = Testcase {
            name: String::from("Accept pod"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings::default(),
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn accept_pod_with_hostpid_but_exempt() -> Result<(), ()> {
        let request_file = "test_data/pod_creation.json";
        // let request_file = "test_data/deployment_creation.json";
        // let request_file = "test_data/replicaset_creation.json";
        // let request_file = "test_data/cronjob_creation.json";
        // let request_file = "test_data/cronjob_v1_creation.json";

        let exempt_usernames = HashSet::from(["kubernetes-admin".to_string()]);
        let exempt_namespaces = HashSet::from(["default".to_string()]);

        let tc = Testcase {
            name: String::from("Accept pod with exempt"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                exempt_usernames: Some(exempt_usernames),
                exempt_namespaces: Some(exempt_namespaces),
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }
}
