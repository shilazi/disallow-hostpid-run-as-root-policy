use anyhow::{anyhow, Result};
use lazy_static::lazy_static;

use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

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
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;

    info!(LOG_DRAIN, "starting validation");
    if validation_request.request.dry_run {
        info!(LOG_DRAIN, "dry run mode, accepting resource");
        return kubewarden::accept_request();
    }

    // service account username
    let username = &validation_request.request.user_info.username;
    // pod name
    let pod_name = &validation_request.request.name;
    // namespace
    let namespace = &validation_request.request.namespace;
    // operation
    let operation = &validation_request.request.operation;
    // kind
    let kind = &validation_request.request.kind.kind;
    // version
    let version = &validation_request.request.kind.version;

    info!(LOG_DRAIN,  "{} {}", operation.to_lowercase(), kind.to_lowercase(); "name" => pod_name, "namespace" => namespace);
    if validation_request
        .settings
        .exempt(username, pod_name, namespace)
    {
        warn!(LOG_DRAIN, "accepting resource with exemption");
        return kubewarden::accept_request();
    }

    // Reject CronJob with batch/v1beta1 apiVersion if hostPID was true
    if kind == v1beta1_cronJob::KIND && version == v1beta1_cronJob::VERSION {
        let cronjob =
            serde_json::from_value::<v1beta1_cronJob>(validation_request.request.object.clone())?;
        if let Some(pod_spec) = cronjob
            .spec
            .and_then(|spec| spec.job_template.spec.and_then(|spec| spec.template.spec))
        {
            if !pod_spec.host_pid.unwrap_or(false) {
                info!(
                    LOG_DRAIN,
                    "accepting {} with hostPID false",
                    v1beta1_cronJob::KIND
                );
                return kubewarden::accept_request();
            }
            return match validate_pod(&pod_spec) {
                Ok(_) => {
                    info!(
                        LOG_DRAIN,
                        "accepting {} with hostPID, SecurityContext.runAsNonRoot already true",
                        v1beta1_cronJob::KIND
                    );
                    kubewarden::accept_request()
                }
                Err(err) => {
                    warn!(
                        LOG_DRAIN,
                        "reject {}: {}",
                        v1beta1_cronJob::KIND,
                        err.to_string()
                    );
                    return kubewarden::reject_request(Some(err.to_string()), None, None, None);
                }
            };
        }
        info!(
            LOG_DRAIN,
            "accepting resource with invalid batch/v1beta1#cronjob spec"
        );
        return kubewarden::accept_request();
    }

    match validation_request.extract_pod_spec_from_object() {
        Ok(pod_spec) => {
            if let Some(pod_spec) = pod_spec {
                if !pod_spec.host_pid.unwrap_or(false) {
                    info!(LOG_DRAIN, "accepting resource with hostPID false");
                    return kubewarden::accept_request();
                }
                return match validate_pod(&pod_spec) {
                    Ok(_) => {
                        info!(LOG_DRAIN, "accepting resource with hostPID, SecurityContext.runAsNonRoot already true");
                        kubewarden::accept_request()
                    }
                    Err(_) => {
                        warn!(
                            LOG_DRAIN,
                            "mutated resource with SecurityContext.runAsNonRoot true"
                        );
                        kubewarden::mutate_pod_spec_from_request(
                            validation_request,
                            mutate_pod_spec(pod_spec),
                        )
                    }
                };
            };
            info!(LOG_DRAIN, "accepting resource with invalid pod spec");
            kubewarden::accept_request()
        }
        Err(_) => {
            warn!(LOG_DRAIN, "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it");
            kubewarden::accept_request()
        }
    }
}

fn mutate_pod_spec(mut pod_spec: apicore::PodSpec) -> apicore::PodSpec {
    for container in &mut pod_spec.containers.iter_mut() {
        let sc = container
            .security_context
            .get_or_insert_with(|| apicore::SecurityContext::default());
        sc.run_as_non_root = Some(true);
    }
    if let Some(init_containers) = &mut pod_spec.init_containers {
        for init_container in init_containers {
            let sc = init_container
                .security_context
                .get_or_insert_with(|| apicore::SecurityContext::default());
            sc.run_as_non_root = Some(true);
        }
    }
    if let Some(ephemeral_containers) = &mut pod_spec.ephemeral_containers {
        for ephemeral_container in ephemeral_containers {
            let sc = ephemeral_container
                .security_context
                .get_or_insert_with(|| apicore::SecurityContext::default());
            sc.run_as_non_root = Some(true);
        }
    }
    pod_spec
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
    fn mutate_pod_with_hostpid() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_with_hostPID.json";
        let tc = Testcase {
            name: String::from("Mutate pod"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings::default(),
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_some(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn reject_batchv1beta1_cronjob_with_hostpid() -> Result<(), ()> {
        let request_file = "test_data/cronjob_creation_with_hostPID.json";
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
        let request_file = "test_data/pod_creation_with_hostPID.json";

        let exempt_usernames = HashSet::from(["kubernetes-admin".to_string()]);
        let exempt_pod_names = HashSet::from(["nginx".to_string()]);
        let exempt_namespaces = HashSet::from(["default".to_string()]);

        let tc = Testcase {
            name: String::from("Accept pod with exempt"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                exempt_usernames: Some(exempt_usernames),
                exempt_pod_names: Some(exempt_pod_names),
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
