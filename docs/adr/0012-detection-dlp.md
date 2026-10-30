# ADR 0012 — Détection des classes de données (`afw-dlp`)

- Statut : accepté — 2026-10-30
- Lot : L1

## Contexte
La passerelle doit reconnaître des classes de données (secrets, inventaire infra, données commerciales et
personnelles) dans les corps, en-têtes, URL et flux continus, pour appliquer les règles de contenu (EF-08),
analyser au fil de l'eau (EF-24) et masquer avant stockage (EF-35), sans signaler les URL S3 présignées (EF-72).
La crate est autonome (pas de dépendance à `afw-core`) : l'orchestrateur convertit `afw_dlp::Finding`.

## Décisions
1. **Expressions régulières sur octets** (`regex::bytes`, Unicode désactivé dans les motifs intégrés) : aucune
   hypothèse UTF-8, pas de panique sur des octets arbitraires, temps linéaire (pas de ReDoS). Mots-clés et
   préfixes de jetons insensibles à la casse (contournement « en majuscules »). Motif personnalisé : 4 Kio
   maximum, limites de taille de l'automate, refus d'un motif qui accepte la chaîne vide ; un groupe nommé
   `value` (ou `v`) désigne la valeur à masquer, sinon la correspondance entière.
2. **Validateurs** après la correspondance : Luhn et préfixe (carte), mod 97 (IBAN), octets ≤ 255 (IP),
   entropie de Shannon ≥ 3,5 bits/octet et ≥ 12 caractères (`generic_secret_assignment`, `openai_key`),
   exclusion de la partie `user:pass@` d'une URL pour `email`, refus d'un nom d'hôte qui continue
   (`a.internal.example.com`, `www.internal-tools.com`).
3. **Variantes décodées** : chaque tampon est analysé tel quel puis décodé (percent-encoding, échappements
   JSON `\" \\ \/ \n \uXXXX`, segments base64/base64url plausibles, y compris repliés sur plusieurs lignes
   et désalignés), récursivement sur deux niveaux. Une détection dans une variante est rapportée sur la plage
   **encodée** de l'original (le masquage efface donc la forme encodée), avec l'empreinte de la valeur
   **décodée** (même secret = même empreinte quelle que soit l'encodage). Un segment base64 n'est analysé que
   si son décodage ressemble à du texte (≥ 90 % imprimable ou UTF-8 sans caractère de contrôle).
   Une variante JSON qui ne diffère que par `\"`/`\n` n'est réanalysée que par les détecteurs sensibles aux
   guillemets (affectations clé/valeur) : le coût d'un corps JSON ordinaire passe de 2 à ~1,2 analyse.
4. **Flux** : la fenêtre garde au moins `max_pattern_len` octets (512 par défaut) ; une détection qui touche
   la fin du tampon est différée (elle peut encore grandir) ; la découpe ne coupe jamais un jeton en deux
   (contexte gauche conservé : frontière de mot, alignement base64, préfixe `clé=`), dans la limite de
   16 Kio retenus (bloc PEM, base64 long). Dédoublonnage par position absolue, et par empreinte pour des
   plages qui se recouvrent. Les positions rapportées sont absolues dans le flux.
5. **EF-72** : dans `X-Amz-Credential=<AKIA|ASIA…>/<aaaammjj>/…` (ou `%2F`), l'identifiant de clé d'accès est
   un identifiant public, pas un secret : il n'est pas signalé. Un paramètre dont le nom commence par
   `X-Amz-` (dont `X-Amz-Security-Token`, `X-Amz-Signature`) n'est jamais une « affectation de secret ».
   Les autres détecteurs restent actifs : un vrai jeton glissé dans une URL présignée est signalé.
6. **En-têtes** : on analyse `Nom: valeur`, ce qui fait correspondre `X-Api-Key`/`Private-Token`/`Cookie:
   x_token=…` aux affectations clé/valeur ; pour `Authorization`/`Proxy-Authorization`, la partie après le
   schéma (≥ 8 octets) est toujours un `bearer_token` (Bearer, Basic, Token…). Une valeur cachée dans le nom
   de l'en-tête est rapportée avec `header_name:<nom>`.
7. **Masquage** : `[CATEGORIE:kind:empreinte]`, empreinte = 12 premiers hex du SHA-256 ; les détections qui
   se recouvrent sont fusionnées en un seul remplacement ; une plage hors limites est ignorée.
8. **Classes par défaut** : `secrets` (12 détecteurs de secrets), `inventaire-infra` (`private_ip`,
   `internal_hostname`), `commercial` (`price_amount`, `iban`), `donnees-personnelles` (`email`,
   `credit_card`). Un même détecteur partagé par plusieurs classes est compilé une fois et produit une
   détection par classe. Suffixes internes par défaut : `.internal .local .lan .corp .localdomain .home.arpa`.

## Inspiration et licences
Formes de jetons inspirées des jeux de règles de gitleaks (MIT) et de Pipelock (Apache 2.0) ; aucun motif
ni code n'est repris mot pour mot, d'où aucune entrée dans la section « Third-party code » de `NOTICE`.

## Performances
Banc `tests/bench.rs` (`--release`, 10 Mio de JSON type API LLM avec échappements, base64 et secrets),
conteneur `rust:1.91-bookworm` sur le poste de développement : ~50 Mio/s pour `scan`, ~49 Mio/s en flux
par blocs de 64 Kio.

## Limites connues
- Deux niveaux de décodage seulement (base64 dans base64 dans base64 non vu).
- Un secret plus long que 16 Kio coupé entre deux blocs, ou un segment base64 de plus de 16 Kio coupé, peut
  être manqué ou décodé désaligné en flux.
- `private_key_pem` : un en-tête PEM chiffré (`Proc-Type: 4,ENCRYPTED`) arrête le corps masqué au premier `-`.
- Pas de détection d'adresses IPv6 privées (fc00::/7) dans `private_ip`.
- `credit_card` peut, rarement, signaler une suite de chiffres qui passe Luhn (par exemple dans un IBAN).
