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
