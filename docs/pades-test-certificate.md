# Development PAdES signing certificate

The server TLS certificate is not a document-signing certificate and must not
be reused. The signing private key remains in SoftHSM throughout this
procedure.

## 1. Generate the CSR with the SoftHSM key

From the project root:

```bash
.venv/bin/python -m scripts.create_hsm_signing_csr
openssl req -in certs/remotesign-lab-signing.csr -noout -verify
```

The script reads only the public key and asks the PKCS#11 token to sign the
CSR. It never exports the private key.

## 2. Create a small test CA outside the server

On a separate development workstation, create a CA dedicated solely to the
prototype. Its private key must not be copied to the RemoteSignLab server:

```bash
openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 \
  -keyout remotesign-lab-test-ca.key \
  -out remotesign-lab-test-ca.crt \
  -subj "/CN=RemoteSignLab Development CA"
```

Create a `signing-cert.ext` file:

```text
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
```

Then sign the CSR exported from the server:

```bash
openssl x509 -req \
  -in remotesign-lab-signing.csr \
  -CA remotesign-lab-test-ca.crt \
  -CAkey remotesign-lab-test-ca.key \
  -CAcreateserial \
  -days 365 \
  -sha256 \
  -extfile signing-cert.ext \
  -out remotesign-lab-signing.crt
```

## 3. Install only the public certificates

Copy these files to the server:

```text
certs/remotesign-lab-signing.crt
certs/remotesign-lab-test-ca.crt
```

If the chain contains intermediates, place them in the chain file in order
from the intermediate certificate to the root certificate; the root must be
the final certificate in the file.

Never copy `remotesign-lab-test-ca.key` there. Configure the paths with
`PADES_SIGNING_CERTIFICATE` and `PADES_CERTIFICATE_CHAIN`.

For every signature, the server compares the certificate's public key with
the public key actually read from SoftHSM. A mismatch blocks PAdES generation
before any database write.

This certificate is strictly a development certificate. The generated PDFs
are not qualified signatures.

The key and certificate for this identity must not be reused for the TSA. The
separate RFC 3161 procedure is described in `docs/pades-test-tsa.md`, and the
complete architecture in `docs/pades.md`.
