# ADR 0012 — Détection des classes de données (`afw-dlp`)

- Statut : accepté — 2026-10-30 (révisé après la revue de la PR #7)
- Lot : L1

## Contexte
La passerelle doit reconnaître des classes de données (secrets, inventaire infra, données commerciales et
personnelles) dans les corps, en-têtes, URL et flux continus, pour appliquer les règles de contenu (EF-08),
analyser au fil de l'eau (EF-24) et masquer avant stockage (EF-35), sans signaler les URL présignées (EF-72).
La crate est autonome (pas de dépendance à `afw-core`) : l'orchestrateur convertit `afw_dlp::Finding`.

## Décisions
1. **Expressions régulières sur octets** (`regex::bytes`, Unicode désactivé dans les motifs intégrés) : aucune
   hypothèse UTF-8, pas de panique sur des octets arbitraires, temps linéaire (pas de ReDoS). Mots-clés et
   préfixes de jetons insensibles à la casse. Motif personnalisé : 4 Kio maximum, limites de taille de
   l'automate, refus d'un motif qui accepte la chaîne vide ; un groupe nommé `value` (ou `v`) désigne la
   valeur à masquer, sinon la correspondance entière.
2. **Validateurs** : Luhn et préfixe (carte, séparateurs espace, tiret ou point), mod 97 (IBAN), IPv4 privées
   (octets ≤ 255) et IPv6 ULA fc00::/7, entropie de Shannon (jetons), exclusion de `user:pass@` pour `email`,
   refus d'un nom d'hôte qui continue (`a.internal.example.com`).
3. **Affectations génériques** (`generic_secret_assignment`) : une valeur entre guillemets va jusqu'au
   guillemet fermant (espaces, `;`, `&` compris) ; une valeur sans guillemets s'arrête à un blanc ou à un
   paramètre suivant (`&nom=`, `;nom=`, `,nom=`). Clés de mot de passe (`password`, `passwd`, `passphrase`,
   `pwd`, `secret`, en suffixe) : ≥ 8 octets sans exigence d'entropie. Autres clés (`token`, `api_key`,
   `credential`…) : ≥ 12 octets, sans blanc, entropie ≥ 3,5 bits/octet. Ignorés : valeurs triviales
   (`***`, `changeme`, `password`, `null`, `<redacted>`, un seul caractère répété), références de variables
   (`$VAR`, `${VAR}`, `{{ … }}`, `%(…)s`) et, sans guillemets, expressions de code (`getpass.getpass()`,
   `os.environ[…]`, `process.env.X`).
4. **Clé privée PEM** : du `-----BEGIN … PRIVATE KEY-----` jusqu'au `-----END` correspondant, sans regarder le
   contenu (en-têtes `Proc-Type`, `DEK-Info`, `Comment`, `Version` compris), ou à défaut sur 16 Kio.
5. **Variantes décodées**, analysées récursivement sur deux niveaux : percent-encoding, échappements JSON
   (`\" \\ \/ \n \uXXXX`), normalisation Unicode (chiffres et lettres pleine chasse U+FF01–FF5E ramenés en
   ASCII ; U+200B–200D, U+2060, U+FEFF et U+00AD supprimés), base64/base64url (lignes repliées, groupes
   séparés par des espaces, segments collés à `-`/`_`), hexadécimal (suites ≥ 32 caractères) et UTF-16 LE/BE
   à dominante ASCII. Le décodé base64 est **toujours** analysé, même binaire (les motifs sont sur octets) ;
   les trois autres alignements possibles ne sont gardés que s'ils donnent du texte. Une détection dans une
   variante est rapportée sur la plage **encodée** de l'original (le masquage efface la forme encodée), avec
   l'empreinte de la valeur **décodée**. Une variante JSON qui ne diffère que par `\"`/`\n` n'est réanalysée
   que par les détecteurs sensibles aux guillemets.
6. **Flux** (`StreamScanner`) : on garde `max_pattern_len` octets (512 par défaut), et davantage seulement s'il y
   a une détection en attente (depuis le début de sa correspondance, clé comprise) ou une suite base64 ouverte
   en fin de tampon (coupée sur un multiple de 4), dans la limite de 17 Kio. Les petits blocs sont cumulés : on
   ne réanalyse que lorsque les octets non analysés atteignent un quart du tampon, ce qui borne le travail à
   environ 5 analyses par octet quelle que soit la taille des blocs (1 Mio en blocs de 16 octets sans blanc :
   < 500 ms en release). Une détection qui touche la fin des données reçues est différée. Dédoublonnage par
   position absolue, et par empreinte pour des plages qui se recouvrent.
7. **Contrat avec la passerelle** : `StreamScanner::safe_len()` = nombre d'octets du flux relayables sans
   risque (début de la queue retenue, qui contient toute détection en attente). La passerelle ne relaie jamais
   au-delà de `safe_len()` ; une détection rendue par `feed` commence toujours à ou après le `safe_len()`
   précédent ; à `finish()`, elle ne relaie le reste que s'il n'y a pas de détection qui l'interdit.
8. **Encodage de contenu** : `decode_content(encoding, data, max_out)` défait `gzip`/`x-gzip`, `deflate`
   (zlib, ou brut à défaut), `br` et `identity`, en liste empilée (ordre inverse). Chaque étape est bornée
   à `max_out` octets (anti-bombe : lecture limitée à `max_out + 1`, puis `TooLarge`). C'est la passerelle qui
   l'appelle avant l'analyse. Dépendances : `flate2` (MIT/Apache-2.0, moteur `miniz_oxide`) et `brotli`
   (BSD-3-Clause/MIT).
9. **URL signées (EF-72)** :
   - SigV4 : la portée `X-Amz-Credential=` (URL) ou `Credential=` (en-tête `Authorization: AWS4-HMAC-SHA256`)
     `<AKIA|ASIA…>/<aaaammjj>/…` n'est pas un secret ; un en-tête `Authorization` signé (`AWS4-…`, `GOOG4-…`)
     n'est pas un `bearer_token`.
   - SigV2 : `AWSAccessKeyId=` n'est pas signalé quand `Signature=` et `Expires=` sont présents.
   - GCS : la valeur de `X-Goog-Credential` (compte de service) n'est pas signalée.
   - Les paramètres `X-Amz-Security-Token`, `X-Amz-Signature`, `X-Amz-Credential`, `X-Goog-Signature`,
     `X-Goog-Credential` ne sont pas des affectations génériques **seulement dans une chaîne de requête**
     (`?` ou `&` devant) ; une clé `x-amz-…` ailleurs (corps, en-tête) reste analysée.
   - Azure : la `sig=` d'une SAS sur `*.{blob,file,queue,table,dfs}.core.windows.net` est un secret
     (`azure_sas_signature`), car elle donne l'accès à elle seule.
   - Les autres détecteurs restent actifs : un vrai jeton glissé dans une URL présignée est signalé.
10. **En-têtes** : on analyse `Nom: valeur` (affectations `X-Api-Key`, `Private-Token`…) ; `Authorization`
    hors schéma signé : la partie après le schéma est un `bearer_token` ; `Cookie`/`Set-Cookie` : chaque
    valeur de ≥ 24 octets à forte entropie est un `session_cookie` ; une valeur cachée dans le nom de
    l'en-tête est rapportée avec `header_name:<nom>`.
11. **Masquage** : `[CATEGORIE:kind:empreinte]`, empreinte = 12 premiers hex du SHA-256 ; détections qui se
    recouvrent fusionnées en un seul remplacement ; plage hors limites ignorée.
12. **Classes par défaut** : `secrets` (14 détecteurs), `inventaire-infra` (`private_ip`, `internal_hostname`),
    `commercial` (`price_amount`, `iban`), `donnees-personnelles` (`email`, `credit_card`). Suffixes internes
    par défaut : `.internal .local .lan .corp .localdomain .home.arpa`.

## Inspiration et licences
Formes de jetons inspirées des jeux de règles de gitleaks (MIT) et de Pipelock (Apache 2.0) ; aucun motif ni
code n'est repris mot pour mot, d'où aucune entrée dans la section « Third-party code » de `NOTICE`.

## Performances
`tests/bench.rs` (`--release`, 10 Mio de JSON type API LLM) : 40 à 60 Mio/s pour `scan` comme en flux, selon
la charge du poste. `tests/review.rs::adversarial_inputs_4mib_release` : 40 entrées hostiles de 4 Mio, chacune
analysée en moins de 1 s (pire cas observé : 0,7 s).

## Limites connues
- Deux niveaux de décodage : base64 dans base64 dans base64, ou percent-encoding triple, ne sont pas vus.
- Caractères séparés un à un par des espaces (`s k - a n t …`) : non reconstitués (indiscernable de la prose).
- Normalisation Unicode limitée à la pleine chasse et aux caractères invisibles cités : pas d'homoglyphes
  (cyrillique, mathématiques) ni de NFKC complet. UTF-16 seulement pour un texte à dominante ASCII.
- En flux, la fenêtre peut couper un jeton qui n'est ni en attente ni base64 (contexte gauche perdu : un faux
  positif reste possible en bord de fenêtre, pas un faux négatif pour un secret ≤ 512 octets).
- Un PEM sans `-----END` est masqué sur 16 Kio, y compris le texte qui le suit.
- `credit_card` peut, rarement, signaler une suite de chiffres qui passe Luhn (par exemple dans un IBAN).
