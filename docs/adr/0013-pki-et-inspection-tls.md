# ADR 0013 — PKI de la console et autorité d'inspection TLS (crate `afw-tls`)

- Statut : accepté — 2026-10-30
- Lot : L2

## Contexte
ENF-02 / ENF-03 et ADR 0004 : chaque passerelle a sa propre autorité d'inspection, dont la clé ne quitte
jamais l'hôte ; la console a sa propre autorité et signe les CSR des passerelles pour le mTLS de `/gw/v1`.
ADR 0009 impose rustls 0.23 + `ring` et rcgen 0.13, sans aws-lc-rs ni cmake.

## Décisions
1. **Fournisseur crypto explicite.** Tous les constructeurs rustls passent par
   `builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))` ; aucun fournisseur par défaut
   du processus n'est installé ni requis. TLS 1.2 et 1.3 (versions sûres par défaut de rustls).
2. **Stockage des clés.** `ca.crt` en 0644, `ca.key` en 0600, répertoire créé en 0700. Écriture atomique
   (fichier temporaire créé directement avec le bon mode, puis renommage). Au chargement, refus si la clé
   donne un droit quelconque au groupe ou aux autres (`mode & 0o077 != 0`), si le chemin n'est pas un fichier
   régulier (lien symbolique refusé), si le certificat ne correspond pas à la clé, s'il n'est pas une CA, ou si
   un seul des deux fichiers existe (on ne remplace jamais en silence une autorité déjà distribuée).
3. **CA d'inspection de la passerelle.** ECDSA P-256, 10 ans (antidatée d'1 h), `cA=true` avec
   `pathLenConstraint=0` (ne peut pas créer de sous-CA), keyCertSign + cRLSign + digitalSignature,
   **sans** nameConstraints (elle doit pouvoir signer n'importe quel hôte inspecté). Empreinte = SHA-256 du
   DER, hexadécimal minuscule sans séparateur (format attendu dans le battement de cœur).
4. **Feuilles.** Une clé P-256 neuve par nom, SAN DNS **ou** IP selon l'entrée, CN = nom s'il tient en
   64 caractères, EKU serverAuth, validité 7 jours à partir de `maintenant - 1 h`, numéro de série aléatoire
   de 128 bits. Les noms sont normalisés (minuscules, point final retiré, IPv6 entre crochets acceptée) et
   validés strictement (étiquettes LDH + `_`, 63/253 caractères) : pas de joker, pas de non-ASCII, pas
   d'étiquette vide. Nom invalide ⇒ pas de certificat ⇒ poignée de main refusée (fermeture par défaut).
   Chaîne présentée : feuille + CA.
5. **Cache.** LRU borné à 10 000 entrées (HashMap + BTreeMap d'ancienneté, sans dépendance supplémentaire),
   protégé par un `Mutex` ; génération hors verrou, la première feuille insérée gagne en cas de course (tous
   les appelants partagent le même `Arc`). Une feuille est régénérée après 6 jours.
6. **Résolution SNI.** `ResolvesServerCert` sur le SNI ; sans SNI (cible IP), `server_config_for_target`
   permet de fournir le nom de repli (l'IP de destination d'origine). ALPN par défaut `h2`, `http/1.1`.
7. **Client amont.** Racines webpki-roots + racines supplémentaires configurées ; une racine supplémentaire
   illisible est une erreur (jamais ignorée). Vérification rustls standard, non désactivable : l'API
   n'expose aucun moyen d'accepter un certificat invalide. `upstream_client_config` renvoie donc un `Result`.
8. **Signature des CSR passerelles.** La CSR est analysée avec x509-parser, sa signature vérifiée (preuve de
   possession), puis **seule la clé publique** est reprise. Tout le reste (sujet, SAN, extensions, demande de
   CA) est ignoré : on n'utilise pas `CertificateSigningRequestParams` de rcgen, qui refuse les CSR portant des
   extensions qu'il ne connaît pas et recopierait les SAN demandés. Certificat émis : CN `gw:<gateway_id>`,
   SAN URI `urn:afw:gw:<gateway_id>` (un SAN DNS avec `:` serait invalide), EKU clientAuth seul,
   `cA=false`, digitalSignature, validité demandée entre 1 et 825 jours. `gateway_id` limité à
   `[A-Za-z0-9._-]{1,128}`.
9. **Serveur de l'API console.** Certificat serveur signé par la CA console, généré en mémoire à chaque
   construction de la configuration (1 an, SAN DNS/IP donnés). Certificat client **optionnel**
   (`WebPkiClientVerifier::allow_unauthenticated`, nécessaire à `POST /gw/v1/register`) mais vérifié par la
   CA console quand il est présenté. `peer_gateway_id` lit le CN `gw:<id>` de la feuille et ne vérifie rien
   lui-même : il ne doit être appelé que sur la chaîne déjà validée par rustls. Les routes autres que
   `/register` doivent exiger un identifiant (responsabilité de l'API, lot L7).
10. **Identité de la passerelle.** `gateway.key` (0600, régénérée à chaque `generate`), `gateway.crt`,
    `console-ca.crt`. Le client mTLS ne fait confiance qu'à `console-ca.crt` (pas de PKI publique).
    `store_cert` vérifie que le certificat correspond à la clé stockée.

## Conséquences
- Dépendance de workspace ajoutée : `time` 0.3 (dates de validité de rcgen). Feature `verify` de x509-parser
  activée dans la crate (déjà tirée par rcgen).
- Pas de révocation (CRL/OCSP) en V1 : la console refuse les passerelles révoquées au niveau applicatif
  (identifiant en base), et les certificats passerelle ont une durée bornée.
- La CA console n'est pas chiffrée au repos : sa protection repose sur les droits du fichier et du volume.
