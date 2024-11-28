## deployment.yaml

### Kubernetes Deployment with securityContext
The ```securityContext``` in the deployment configuration defines security settings for the pods and containers in the deployment. It helps to control permissions, user access, and capabilities within the containerized application.

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
```

- ```runAsNonRoot: true```: Ensures that the container does not run as the root user. This prevents privilege escalation, which is a security best practice.
- ```runAsUser: 1000```: Specifies that the container should run as a user with UID 1000 (non-root). If the application needs specific permissions, you can define which user it should run as.
- ```runAsGroup: 3000```: Specifies the group ID (GID) under which the container should run.
- ```fsGroup: 2000```: Defines the group ID that will be applied to any volumes mounted by the pod. This ensures that files within volumes have the correct group ownership.

```yaml
containers:
- name: app
  image: secure-app:latest
  securityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop:
        - ALL
```

- ```allowPrivilegeEscalation: false```: Prevents the container from escalating its privileges (e.g., running as root). This ensures that the container cannot gain additional privileges during runtime.
- ```capabilities.drop: [ALL]```: Drops all Linux capabilities, further restricting the container's access to sensitive system operations. This minimizes the potential attack surface by ensuring the container has only the essential capabilities needed to run the application.


## admissionController.yaml

This component is an **Admission Controller Policy** managed by Open Policy Agent (OPA) and Gatekeeper, which is used to enforce certain security standards at the time of pod creation in the Kubernetes cluster. In your case, the policy ensures that all pods must run as non-root.

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequireNonRoot
metadata:
  name: require-non-root
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
```

- ```K8sRequireNonRoot```: This policy ensures that any pod created must run as a non-root user.
- ```match.kinds```: Specifies that this policy applies to the "Pod" kind (which includes both deployments and standalone pods).
- ```apiGroups: [""]```: Indicates that the policy applies to resources in the core API group (i.e., Pod is part of the core group).

When this policy is enforced by Gatekeeper, any pod creation that violates the rule (e.g., if a pod runs as root) will be rejected, ensuring all workloads are secured by not allowing them to run with elevated privileges.

### How It All Works Together:
**1.** The Deployment specifies that containers should run as non-root users and limits the capabilities of the containers for enhanced security.

**2.** The Gatekeeper Admission Controller enforces the rule that all Pods must be configured to run as non-root users.

**3. **This setup ensures that if any container in the cluster is improperly configured to run as root, the Admission Controller will block it.

