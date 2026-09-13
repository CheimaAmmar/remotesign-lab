# Journal d'audit RemoteSignLab

## Architecture

Les événements de sécurité sont stockés dans `security_audit_events` et
sont écrits par `app.services.audit_service.write_audit_event`. Les routes
ne calculent jamais elles-mêmes les empreintes de la chaîne.

Deux modes d'écriture existent :

- `add_audit_event` ajoute l'événement à la transaction métier. Il est donc
  validé ou annulé avec l'opération qu'il décrit.
- `record_audit_event` ouvre une transaction indépendante pour conserver
  un refus ou un échec après le rollback de la transaction métier. Une
  panne du journal est journalisée côté serveur mais ne masque jamais
  l'erreur principale retournée au client.

Les événements antérieurs à la migration `a84f2c1d9e70` sont conservés
sans modification. Ils restent consultables, avec `previous_hash` et
`event_hash` à `NULL`.

## Schéma d'un événement

Un événement peut décrire :

- quand : `created_at` ;
- qui : `actor_type`, `actor_id`, `user_id`, `device_id` ;
- quoi : `category`, `event_type` ;
- sur quel objet : `document_id`, `signature_request_id`, `signature_id`,
  `session_id` ;
- résultat : `outcome` ;
- pourquoi : `failure_code`, `detail`, `details` ;
- contexte HTTP : `http_method`, `http_path`, `http_status`, `source_ip`,
  `user_agent` ;
- corrélation : `correlation_id` ;
- preuve de chaîne : `previous_hash`, `event_hash`.

Les champs contextuels sont optionnels. Les acteurs autorisés sont
`USER`, `ADMIN`, `DEVICE` et `SYSTEM`. Les résultats normalisés sont
`SUCCESS`, `FAILURE` et `DENIED`. `actor_type` désigne la nature de
l'acteur ; `user_id` reste l'utilisateur métier concerné et ne change pas
un événement DEVICE en événement USER.

La corrélation emploie en priorité les identifiants métier. Lorsque le
document est connu et qu'aucun identifiant de corrélation explicite n'est
fourni, `document_id` est utilisé comme `correlation_id`. Cette valeur est
générée ou sélectionnée côté serveur et ne participe jamais à une décision
d'autorisation.

## Taxonomie

Catégories : `AUTH`, `DOCUMENT`, `CONSENT`, `SIGNATURE_REQUEST`,
`DEVICE_AUTH`, `SIGNATURE`, `PADES`, `TSA`, `ADMIN`, `SECURITY`.

Événements du workflow actuellement produits :

- compte : `USER_LOGIN_SUCCESS`, `USER_LOGIN_FAILED`, `USER_LOGOUT`,
  `ADMIN_LOGIN_SUCCESS`, `ADMIN_LOGIN_FAILED`, `ADMIN_LOGOUT` ;
- document et consentement : `DOCUMENT_UPLOADED`, `DOCUMENT_ASSIGNED`,
  `DOCUMENT_VIEWED`, `CONSENT_RECORDED`,
  `SIGNED_DOCUMENT_DOWNLOADED` ;
- demande : `SIGNATURE_REQUEST_CREATED`, `SIGNATURE_REQUEST_CLAIMED`,
  `SIGNATURE_REQUEST_FAILED`, `SIGNATURE_REQUEST_EXPIRED` ;
- terminal : `DEVICE_CHALLENGE_CREATED`, `DEVICE_CHALLENGE_REJECTED`,
  `DEVICE_AUTH_SUCCESS`, `DEVICE_AUTH_FAILED`, `HMAC_REJECTED`,
  `NONCE_REPLAY_REJECTED`, `RATE_LIMIT_BLOCKED` ;
- signature : `SIGNATURE_STARTED`, `SIGNATURE_SUCCESS`,
  `SIGNATURE_FAILED` ;
- PDF et horodatage : `PADES_CREATED`, `PADES_VALIDATION_SUCCESS`,
  `PADES_VALIDATION_FAILED`, `TSA_TIMESTAMP_SUCCESS`,
  `TSA_TIMESTAMP_FAILED` ;
- vérification : `SIGNATURE_VERIFY_REQUESTED`,
  `SIGNATURE_VERIFY_SUCCESS`, `SIGNATURE_VERIFY_FAILED`.

Les consultations à vide de `/next` ne produisent volontairement pas un
événement à chaque poll de trois secondes : l'authentification rejetée et
la réclamation effective sont auditées, sans transformer le journal en
trace réseau redondante.

Les `failure_code` sont des identifiants techniques courts, en majuscules,
composés de `A-Z`, `0-9` et `_` (3 à 64 caractères), par exemple
`INVALID_HMAC`, `NONCE_REPLAY`, `RFID_MISMATCH`,
`FINGERPRINT_MISMATCH`, `CONSENT_MISSING`, `CONSENT_MISMATCH`,
`DOCUMENT_HASH_MISMATCH`, `REQUEST_STATE_INVALID`, `DEVICE_MISMATCH`,
`TSA_UNAVAILABLE`, `TSA_VALIDATION_FAILED`, `PADES_CREATION_FAILED`,
`PADES_VALIDATION_FAILED` ou `SIGNED_DOCUMENT_MISSING`.

## Sanitisation

`details` est nettoyé récursivement avant stockage et de nouveau avant
lecture/export. La profondeur, le nombre d'éléments et la longueur des
chaînes sont bornés. Une denylist supprime notamment mots de passe,
empreintes de mots de passe, secrets DEVICE/HMAC/ADMIN, PIN SoftHSM,
clés privées, jetons de session, cookies, en-têtes Authorization, jetons
CSRF et clés privées TSA/CA. Le champ historique `detail` masque également
les affectations sensibles et jetons Bearer reconnaissables.

L'adresse IP vient de la socket cliente exposée par FastAPI. Le service ne
fait pas confiance à `X-Forwarded-For` sans configuration explicite d'un
proxy de confiance.

## Chaîne d'intégrité

Chaque nouvel événement démarre avec `previous_hash` égal à 64 zéros si
aucun événement scellé ne le précède, sinon avec le `event_hash` précédent.
`event_hash` est le SHA-256 des octets UTF-8 d'un objet JSON canonique.

Les champs couverts, exactement, sont :

`id`, `category`, `event_type`, `actor_type`, `actor_id`, `user_id`,
`device_id`, `session_id`, `document_id`, `signature_request_id`,
`signature_id`, `outcome`, `failure_code`, `correlation_id`,
`http_method`, `http_path`, `http_status`, `source_ip`, `user_agent`,
`detail`, `details`, `created_at`, `previous_hash`.

La canonicalisation utilise :

- des clés JSON triées ;
- les séparateurs `,` et `:` sans espaces ;
- UTF-8, sans échappement forcé des caractères Unicode ;
- UUID sous forme de chaîne canonique ;
- dates converties en UTC sous la forme
  `YYYY-MM-DDTHH:MM:SS.ffffffZ` ;
- `null`, booléens et entiers JSON natifs ;
- aucun `repr()` Python et aucun saut de ligne final.

`event_hash` lui-même est exclu du contenu à hacher. La comparaison lors
de la vérification emploie `hmac.compare_digest`.

Sous PostgreSQL, `pg_advisory_xact_lock(6004502579051058500)` sérialise
uniquement l'ajout en fin de chaîne, jusqu'à la fin de la transaction. La
valeur correspond au mnémonique hexadécimal `STGHMAUD` et lui est réservée.
Le verrou empêche deux écritures concurrentes de réutiliser le même
`previous_hash`. Un verrou de processus sert uniquement de repli aux tests
sur SQLite ; PostgreSQL reste le mécanisme de production.

`GET /ui/api/audit/integrity` relit sans modifier la base et distingue :

- `historical_unsealed_events`, événements historiques non scellés ;
- `chained_events`, événements appartenant à la chaîne ;
- `events_checked`, événements recalculés avant la première erreur ;
- `first_invalid_event_id`, premier maillon invalide.

Hash chaining provides tamper evidence, not absolute immutability.

En français : le chaînage rend une altération détectable, mais ne fournit
pas une immutabilité absolue face à un administrateur capable de réécrire
toute la base et de recalculer l'ensemble de la chaîne. Une garantie plus
forte nécessiterait un ancrage externe périodique ou un stockage WORM.

## API et interface ADMIN

Ces routes exigent la session ADMIN de l'interface et n'offrent aucune
écriture :

- `GET /ui/api/audit` : liste paginée, tri
  `created_at DESC, id DESC`, `limit` de 1 à 200 ;
- `GET /ui/api/audit/{event_id}` : détail nettoyé ;
- `GET /ui/api/audit/integrity` : vérification de chaîne ;
- `GET /ui/api/audit/export.csv` : export filtré, maximum 5 000 lignes.

Filtres communs : `from`, `to`, `category`, `event_type`, `actor_type`,
`user_id`, `device_id`, `document_id`, `signature_request_id`,
`signature_id`, `outcome`, `failure_code`, `correlation_id`, plus `limit`
et `offset`.

L'export neutralise les cellules texte commençant par `=`, `+`, `-`, `*`
ou `@` en les préfixant par une apostrophe afin de réduire le risque
d'injection de formule dans un tableur.

Les index existants sur la date, le type d'événement, les IDs user/device/
document/signature et le résultat sont conservés. La migration ajoute les
index correspondant aux nouveaux filtres les plus structurants : catégorie,
type d'acteur, demande de signature et corrélation. Les champs peu sélectifs
ou principalement consultés en détail ne sont pas indexés mécaniquement.

## Limites opérationnelles

- Les anciens événements sont consultables mais explicitement non scellés.
- La migration ne réalise aucun backfill cryptographique inventé.
- Un événement de succès lié à la transaction métier disparaît si celle-ci
  est annulée ; un refus ou échec utilise l'écriture indépendante.
- Une indisponibilité simultanée de PostgreSQL peut empêcher la conservation
  d'un échec ; l'erreur métier reste prioritaire et une erreur serveur est
  alors émise dans les logs applicatifs.
- Une politique de rétention, un ancrage externe et une exportation vers un
  SIEM/WORM restent des renforcements ultérieurs possibles.
