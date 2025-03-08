#!/bin/bash
set -e

SERVICE_NAME=$1
NAMESPACE=${2:-default}

if [ -z "$SERVICE_NAME" ]; then
  echo "Usage: $0 <service-name> [namespace]"
  exit 1
fi

# Create config from template
sed "s/SERVICE_NAME/$SERVICE_NAME/g; s/NAMESPACE/$NAMESPACE/g" service.conf > ${SERVICE_NAME}.conf

# Generate key and CSR
openssl genrsa -out ${SERVICE_NAME}.key 2048
openssl req -new -key ${SERVICE_NAME}.key -out ${SERVICE_NAME}.csr -config ${SERVICE_NAME}.conf

# Sign CSR with CA
openssl x509 -req -in ${SERVICE_NAME}.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out ${SERVICE_NAME}.crt -days 365 \
  -extensions v3_req -extfile ${SERVICE_NAME}.conf

# Create K8s secret with certificates
kubectl create secret generic ${SERVICE_NAME}-certs \
  --namespace ${NAMESPACE} \
  --from-file=ca.crt=ca.crt \
  --from-file=tls.key=${SERVICE_NAME}.key \
  --from-file=tls.crt=${SERVICE_NAME}.crt \
  --dry-run=client -o yaml > ${SERVICE_NAME}-certs.yaml

kubectl apply -f ${SERVICE_NAME}-certs.yaml

echo "Created TLS secret ${SERVICE_NAME}-certs in namespace ${NAMESPACE}"
EOF

chmod +x generate_service_cert.sh
