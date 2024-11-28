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
