# TSA RFC 3161 locale de développement

Cette procédure crée une vraie réponse RFC 3161 avec OpenSSL. La TSA est
distincte du certificat TLS, du signataire PDF et de la clé SoftHSM.

## 1. Créer les clés hors du dépôt

Choisir un répertoire privé **extérieur** au dépôt et l'exposer uniquement au
processus TSA :

```bash
export STAGE_HSM_TSA_DIR=/chemin/prive/hors-du-depot/stage-hsm-tsa
install -d -m 700 "$STAGE_HSM_TSA_DIR"

openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
  -keyout "$STAGE_HSM_TSA_DIR/tsa-ca.key" \
  -out "$STAGE_HSM_TSA_DIR/tsa-ca.crt" \
  -subj "/CN=Stage-HSM Development TSA CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -new -newkey rsa:3072 -nodes \
  -keyout "$STAGE_HSM_TSA_DIR/tsa.key" \
  -out "$STAGE_HSM_TSA_DIR/tsa.csr" \
  -subj "/CN=Stage-HSM Development TSA"

chmod 600 "$STAGE_HSM_TSA_DIR/tsa-ca.key" \
  "$STAGE_HSM_TSA_DIR/tsa.key"
```

Le fichier public `scripts/dev-tsa-certificate.ext` contient :

```text
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,timeStamping
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
```

Signer le certificat TSA :

```bash
openssl x509 -req -in "$STAGE_HSM_TSA_DIR/tsa.csr" \
  -CA "$STAGE_HSM_TSA_DIR/tsa-ca.crt" \
  -CAkey "$STAGE_HSM_TSA_DIR/tsa-ca.key" \
  -CAcreateserial -days 730 -sha256 \
  -extfile scripts/dev-tsa-certificate.ext \
  -out "$STAGE_HSM_TSA_DIR/tsa.crt"

printf '01\n' > "$STAGE_HSM_TSA_DIR/tsaserial"
```

L'EKU `timeStamping` doit être critique et dédiée. Ne jamais employer le
certificat `Stage-HSM Development Signer` ni une clé SoftHSM pour cette TSA.

## 2. Configuration OpenSSL

Le fichier public `scripts/dev-tsa-openssl.cnf` contient :

```ini
[ tsa ]
default_tsa = tsa_config

[ tsa_config ]
dir = $ENV::STAGE_HSM_TSA_DIR
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

## 3. Démarrer le transport HTTP local

Depuis la racine du projet, en conservant `STAGE_HSM_TSA_DIR` dans
l'environnement :

```bash
.venv/bin/python -m scripts.dev_tsa_server \
  --config scripts/dev-tsa-openssl.cnf \
  --bind 127.0.0.1 --port 8090
```

Le script limite la taille des requêtes, n'en journalise pas le contenu et
délègue la production du token à `openssl ts -reply`. Le serveur est local et
mono-processus afin de sérialiser la mise à jour du numéro de série OpenSSL.

Copier uniquement l'ancre publique dans le répertoire public ignoré `certs/` :

```bash
cp "$STAGE_HSM_TSA_DIR/tsa-ca.crt" \
  certs/stage-hsm-development-tsa-ca.crt
```

Configurer localement `.env` sans versionner de secret :

```dotenv
PADES_PROFILE=PAdES-B-T
TSA_URL=http://127.0.0.1:8090
TSA_CA_CERTIFICATE=certs/stage-hsm-development-tsa-ca.crt
TSA_TIMEOUT_SECONDS=5
```

## 4. Vérifier une réponse RFC 3161 isolée

```bash
printf 'stage-hsm-tsa-test' > /tmp/stage-hsm-tsa-test.bin
openssl ts -query -data /tmp/stage-hsm-tsa-test.bin -sha256 -cert \
  -out /tmp/stage-hsm-tsa-test.tsq
curl --fail --silent --show-error \
  -H 'Content-Type: application/timestamp-query' \
  --data-binary @/tmp/stage-hsm-tsa-test.tsq \
  http://127.0.0.1:8090/ \
  -o /tmp/stage-hsm-tsa-test.tsr
openssl ts -reply -in /tmp/stage-hsm-tsa-test.tsr -text
openssl ts -verify \
  -queryfile /tmp/stage-hsm-tsa-test.tsq \
  -in /tmp/stage-hsm-tsa-test.tsr \
  -CAfile "$STAGE_HSM_TSA_DIR/tsa-ca.crt"
```

Pour valider le PDF B-T complet, utiliser ensuite la commande à deux ancres
documentée dans `docs/pades.md`.

Cette TSA est exclusivement destinée au développement. Sa clé privée et la
clé privée de sa CA ne doivent jamais entrer dans le dépôt.
