# disallow-hostpid-run-as-root-policy

Disallow `hostPID` with true, but `securityContext.runAsNonRoot` was not set.

## Build

```bash
make
```

## Usage

1. Upload `disallow-hostpid-run-as-root-policy-v1.0.0.wasm` to static server
2. Generate `ClusterAdmissionPolicy` manifest
    ```yaml
    apiVersion: policies.kubewarden.io/v1alpha2
    kind: ClusterAdmissionPolicy
    metadata:
      name: disallow-hostpid-run-as-root-policy
    spec:
      module: https://your.server/kubewarden/policies/disallow-hostpid-run-as-root-policy-v1.0.0.wasm
      rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
        operations: ["CREATE"]
      - apiGroups: ["batch"]
        apiVersions: ["v1beta1"]
        resources: ["cronjobs"]
        operations: ["CREATE", "UPDATE"]
      mutating: true
      settings:
        # exempt with service account by username
        exempt_users:
        - kubernetes-admin
        # exempt with pod name
        exempt_pod_names:
        - foo
        # exempt with Namespace
        exempt_namespaces:
        - kube-system
    ```
3. Apply with kubectl
   ```bash
   kubectl apply -f disallow-hostpid-run-as-root-policy.yml
   ```

## Validation

Example pod manifest:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  hostPID: true
  containers:
  - image: nginx
    name: nginx
EOF
```

With exempt:

```
$ kubectl get po
NAME   READY   STATUS             RESTARTS   AGE
nginx  1/1     Running            0          15s
```

```
accepting resource with exemption data={"column":5,"file":"src/lib.rs","line":60,"policy":"disallow-hostpid-run-as-root-policy"}
```

Without exempt:

```
$ kubectl get po
NAME   READY   STATUS                       RESTARTS   AGE
nginx  0/1     CreateContainerConfigError   0          15s

$ kubectl describe po nginx
Events:
  Type     Reason     Age               From               Message
  ----     ------     ----              ----               -------
  Warning  Failed     6s (x3 over 20s)  kubelet            Error: container has runAsNonRoot and image will run as root
```

Work with `batch/v1beta1#CronJob`:

```
Error from server: error when creating "cj.yml": admission webhook "disallow-hostpid-run-as-root-policy.kubewarden.admission" denied the request: Container run as root with hostPID is not allowed
```
