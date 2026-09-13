# PAdES PDF signatures in RemoteSignLab

RemoteSignLab produces a separate signed PDF under `storage/signed/`. The
original PDF in `storage/documents/` is never replaced. Publication follows
this order: temporary file, pyHanko generation, validation, atomic rename,
`DocumentSignature` write, request transition to `SIGNED`, then PostgreSQL
commit.

## Available profiles

- `PAdES-B-B` contains the basic CMS signature and the signer's certificate.
- `PAdES-B-T` adds an RFC 3161 signature timestamp token signed by a separate
  TSA.

Select the profile with `PADES_PROFILE`. In `PAdES-B-T` mode, `TSA_URL`
and `TSA_CA_CERTIFICATE` are required. An unavailable TSA or an invalid TSA
response causes the signature to fail; RemoteSignLab never falls back
implicitly to B-B.

The visible appearance is created on the last page before calculating the
`ByteRange`. Its box is computed within the `CropBox`, or the `MediaBox`
when necessary, with a margin and a size reduction for small pages. The text
uses the `User` name read again on the server, the actual X.509 certificate,
the profile, the server date, and the signature identifier.

## Three certificates, three purposes

- The TLS certificate protects the FastAPI HTTPS connection.
- `RemoteSignLab Development Signer` certifies the document-signing key whose
  private key remains in SoftHSM.
- `RemoteSignLab Development TSA` signs RFC 3161 tokens with a different key.

These identities are never interchangeable. The signer certificate and TSA
chain are public; CA/TSA private keys and the SoftHSM PIN must not be stored in
Git.

## Validation

The ADMIN endpoint `GET /api/v1/signatures/{signature_id}/verify` checks the
historical detached signature and, when a PAdES PDF exists, its integrity, full
coverage, signer certificate, and trust anchor. For B-T, it also requires a
present, cryptographically valid timestamp trusted according to
`TSA_CA_CERTIFICATE`.

B-B CLI validation:

```bash
.venv/bin/pyhanko sign validate \
  --pretty-print \
  --trust certs/remotesign-lab-test-ca.crt \
  --trust-replace \
  storage/signed/<document-id>-<signature-id>.pdf
```

B-T CLI validation with both development trust anchors:

```bash
.venv/bin/pyhanko sign validate \
  --pretty-print \
  --trust certs/remotesign-lab-test-ca.crt \
  --trust certs/remotesign-lab-development-tsa-ca.crt \
  --trust-replace \
  storage/signed/<document-id>-<signature-id>.pdf
```

The signed-in owner downloads the validated file through
`GET /user/documents/{document_id}/signed`. The disk path is never supplied
by the browser.

## Scope and limitations

This infrastructure uses private development certificates. It does not
constitute a qualified electronic signature and does not modify any system
trust store. PAdES-B-T proves a time through RFC 3161, but does not provide the
embedded revocation data and maintenance required by PAdES-B-LT or PAdES-B-LTA.
The next steps would be OCSP/CRL integration, a DSS, and then an archival
timestamp chain.
