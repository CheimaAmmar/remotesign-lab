# Certificat de signature PAdES de développement

Le certificat TLS du serveur n'est pas un certificat de signature de
documents et ne doit pas être réutilisé. La clé privée de signature reste
dans SoftHSM pendant toute cette procédure.

## 1. Générer la CSR avec la clé SoftHSM

Depuis la racine du projet :

```bash
.venv/bin/python -m scripts.create_hsm_signing_csr
openssl req -in certs/remotesign-lab-signing.csr -noout -verify
```

Le script lit uniquement la clé publique et demande au token PKCS#11 de
signer la CSR. Il n'exporte jamais la clé privée.

## 2. Créer une petite CA de test hors du serveur

Sur un poste de développement séparé, créer une CA uniquement destinée au
prototype. Sa clé privée ne doit pas être copiée sur le serveur RemoteSignLab :

```bash
openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 \
  -keyout remotesign-lab-test-ca.key \
  -out remotesign-lab-test-ca.crt \
  -subj "/CN=RemoteSignLab Development CA"
```

Créer un fichier `signing-cert.ext` :

```text
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
```

Signer ensuite la CSR exportée du serveur :

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

## 3. Installer uniquement les certificats publics

Copier sur le serveur :

```text
certs/remotesign-lab-signing.crt
certs/remotesign-lab-test-ca.crt
```

Si la chaîne comprend des intermédiaires, les placer dans le fichier de
chaîne dans l'ordre certificat intermédiaire vers certificat racine ; la
racine doit être le dernier certificat du fichier.

Ne jamais y copier `remotesign-lab-test-ca.key`. Les chemins se configurent avec
`PADES_SIGNING_CERTIFICATE` et `PADES_CERTIFICATE_CHAIN`.

À chaque signature, le serveur compare la clé publique du certificat avec
la clé publique réellement lue dans SoftHSM. Une différence bloque la
génération PAdES avant toute écriture en base.

Ce certificat est exclusivement un certificat de développement. Les PDF
produits ne constituent pas des signatures qualifiées.

La clé et le certificat de cette identité ne doivent pas être réutilisés pour
la TSA. La procédure RFC 3161 distincte est décrite dans
`docs/pades-test-tsa.md`, et l'architecture complète dans `docs/pades.md`.
