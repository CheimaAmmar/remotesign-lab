# Local development RFC 3161 TSA

This procedure creates a genuine RFC 3161 response with OpenSSL. The TSA is
separate from the TLS certificate, PDF signer, and SoftHSM key.

## 1. Create the keys outside the repository

Choose a private directory **outside** the repository and expose it only to
the TSA process:

```bash
export REMOTESIGN_LAB_TSA_DIR=/private/path/outside-repository/remotesign-lab-tsa
install -d -m 700 "$REMOTESIGN_LAB_TSA_DIR"

openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
  -keyout "$REMOTESIGN_LAB_TSA_DIR/tsa-ca.key" \
  -out "$REMOTESIGN_LAB_TSA_DIR/tsa-ca.crt" \
  -subj "/CN=RemoteSignLab Development TSA CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -new -newkey rsa:3072 -nodes \
  -keyout "$REMOTESIGN_LAB_TSA_DIR/tsa.key" \
  -out "$REMOTESIGN_LAB_TSA_DIR/tsa.csr" \
  -subj "/CN=RemoteSignLab Development TSA"

chmod 600 "$REMOTESIGN_LAB_TSA_DIR/tsa-ca.key" \
  "$REMOTESIGN_LAB_TSA_DIR/tsa.key"
```

The public `scripts/dev-tsa-certificate.ext` file contains:

```text
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,timeStamping
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
```

Sign the TSA certificate:

```bash
openssl x509 -req -in "$REMOTESIGN_LAB_TSA_DIR/tsa.csr" \
  -CA "$REMOTESIGN_LAB_TSA_DIR/tsa-ca.crt" \
  -CAkey "$REMOTESIGN_LAB_TSA_DIR/tsa-ca.key" \
  -CAcreateserial -days 730 -sha256 \
  -extfile scripts/dev-tsa-certificate.ext \
  -out "$REMOTESIGN_LAB_TSA_DIR/tsa.crt"

printf '01\n' > "$REMOTESIGN_LAB_TSA_DIR/tsaserial"
```

The `timeStamping` EKU must be critical and dedicated. Never use the
`RemoteSignLab Development Signer` certificate or a SoftHSM key for this TSA.

## 2. OpenSSL configuration

The public `scripts/dev-tsa-openssl.cnf` file contains:

```ini
[ tsa ]
default_tsa = tsa_config

[ tsa_config ]
dir = $ENV::REMOTESIGN_LAB_TSA_DIR
serial = $dir/tsaserial
crypto_device = builtin
signer_cert = $dir/tsa.crt
certs = $dir/tsa-ca.crt
signer_key = $dir/tsa.key
signer_digest = sha256
default_policy = 1.3.6.1.4.1.55555.1
other_policies = 1.3.6.1.4.1.55555.1
digests = sha256
accuracy = secs:1
clock_precision_digits = 0
ordering = yes
tsa_name = yes
ess_cert_id_chain = yes
ess_cert_id_alg = sha256
```

## 3. Start the local HTTP transport

From the project root, with `REMOTESIGN_LAB_TSA_DIR` still in the
environment:

```bash
.venv/bin/python -m scripts.dev_tsa_server \
  --config scripts/dev-tsa-openssl.cnf \
  --bind 127.0.0.1 --port 8090
```

The script limits request sizes, does not log request content, and delegates
token generation to `openssl ts -reply`. The server is local and
single-process so that updates to the OpenSSL serial number are serialized.

Copy only the public trust anchor to the ignored public `certs/` directory:

```bash
cp "$REMOTESIGN_LAB_TSA_DIR/tsa-ca.crt" \
  certs/remotesign-lab-development-tsa-ca.crt
```

Configure `.env` locally without committing any secret:

```dotenv
PADES_PROFILE=PAdES-B-T
TSA_URL=http://127.0.0.1:8090
TSA_CA_CERTIFICATE=certs/remotesign-lab-development-tsa-ca.crt
TSA_TIMEOUT_SECONDS=5
```

## 4. Verify a standalone RFC 3161 response

```bash
printf 'remotesign-lab-tsa-test' > /tmp/remotesign-lab-tsa-test.bin
openssl ts -query -data /tmp/remotesign-lab-tsa-test.bin -sha256 -cert \
  -out /tmp/remotesign-lab-tsa-test.tsq
curl --fail --silent --show-error \
  -H 'Content-Type: application/timestamp-query' \
  --data-binary @/tmp/remotesign-lab-tsa-test.tsq \
  http://127.0.0.1:8090/ \
  -o /tmp/remotesign-lab-tsa-test.tsr
openssl ts -reply -in /tmp/remotesign-lab-tsa-test.tsr -text
openssl ts -verify \
  -queryfile /tmp/remotesign-lab-tsa-test.tsq \
  -in /tmp/remotesign-lab-tsa-test.tsr \
  -CAfile "$REMOTESIGN_LAB_TSA_DIR/tsa-ca.crt"
```

To validate the complete B-T PDF, then use the command with two trust anchors
documented in `docs/pades.md`.

This TSA is strictly for development. Its private key and its CA private key
must never enter the repository.
