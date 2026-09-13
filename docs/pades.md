# Signature PDF PAdES dans RemoteSignLab

RemoteSignLab produit un PDF signé séparé sous `storage/signed/`. Le PDF original
de `storage/documents/` n'est jamais remplacé. La publication suit l'ordre
suivant : fichier temporaire, génération pyHanko, validation, renommage
atomique, écriture de `DocumentSignature`, transition de la demande vers
`SIGNED`, puis commit PostgreSQL.

## Profils disponibles

- `PAdES-B-B` contient la signature CMS de base et le certificat du signataire.
- `PAdES-B-T` ajoute un jeton d'horodatage de signature RFC 3161 signé par une
  TSA distincte.

Le profil se choisit avec `PADES_PROFILE`. En mode `PAdES-B-T`, `TSA_URL` et
`TSA_CA_CERTIFICATE` sont obligatoires. Une indisponibilité ou une réponse TSA
invalide fait échouer la signature ; RemoteSignLab ne revient jamais implicitement
à B-B.

L'apparence visible est créée sur la dernière page avant le calcul du
`ByteRange`. Sa boîte est calculée dans la `CropBox`, ou la `MediaBox` si
nécessaire, avec une marge et une réduction pour les petites pages. Le texte
reprend le nom du `User` relu côté serveur, le vrai certificat X.509, le profil,
la date serveur et l'identifiant de signature.

## Trois certificats, trois usages

- Le certificat TLS protège la connexion HTTPS FastAPI.
- `RemoteSignLab Development Signer` certifie la clé de signature de document dont
  la clé privée reste dans SoftHSM.
- `RemoteSignLab Development TSA` signe les jetons RFC 3161 avec une autre clé.

Ces identités ne sont jamais interchangeables. Le certificat de signataire et
la chaîne TSA sont publics ; les clés privées de CA/TSA et le PIN SoftHSM ne
doivent pas être placés dans Git.

## Validation

Le endpoint ADMIN `GET /api/v1/signatures/{signature_id}/verify` contrôle la
signature détachée historique, puis, si un PDF PAdES existe, son intégrité, sa
couverture complète, le certificat signataire et son ancre de confiance. Pour
B-T, il exige en plus un timestamp présent, cryptographiquement valide et
fiable selon `TSA_CA_CERTIFICATE`.

Validation CLI B-B :

```bash
.venv/bin/pyhanko sign validate \
  --pretty-print \
  --trust certs/remotesign-lab-test-ca.crt \
  --trust-replace \
  storage/signed/<document-id>-<signature-id>.pdf
```

Validation CLI B-T avec les deux ancres de développement :

```bash
.venv/bin/pyhanko sign validate \
  --pretty-print \
  --trust certs/remotesign-lab-test-ca.crt \
  --trust certs/remotesign-lab-development-tsa-ca.crt \
  --trust-replace \
  storage/signed/<document-id>-<signature-id>.pdf
```

Le propriétaire connecté télécharge le fichier validé par
`GET /user/documents/{document_id}/signed`. Le chemin disque n'est jamais pris
depuis le navigateur.

## Portée et limites

Cette infrastructure utilise des certificats privés de développement. Elle ne
constitue pas une signature électronique qualifiée et ne modifie aucun trust
store système. PAdES-B-T prouve une heure par RFC 3161, mais ne fournit pas les
données de révocation embarquées et la maintenance requises par PAdES-B-LT ou
PAdES-B-LTA. Les étapes suivantes seront l'intégration OCSP/CRL, un DSS, puis
une chaîne de timestamps d'archivage.
