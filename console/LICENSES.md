# Licences des dépendances de la console

La console est publiée sous Apache-2.0. Ses dépendances npm (directes et transitives, voir
`pnpm licenses list`) doivent être sous l'une des licences suivantes :

| Licence | Condition |
|---|---|
| MIT, MIT-0, ISC, 0BSD, BSD-2-Clause, BSD-3-Clause, Apache-2.0, Zlib | — |
| BlueOak-1.0.0, CC0-1.0, Unlicense | — |
| Python-2.0 | — (ex. `argparse`) |
| CC-BY-3.0, CC-BY-4.0 | données uniquement (listes SPDX, `caniuse-lite`) |
| MPL-2.0 | fichiers **non modifiés** uniquement (ex. `lightningcss`, outil de build) |
| Double licence (« X OR Y ») | acceptée si l'une des branches est dans cette liste (ex. `node-forge` : BSD-3-Clause) |

Refusées : GPL, AGPL, LGPL, SSPL, BUSL et toute licence non libre. Une licence absente de ce tableau
se signale en revue avant l'ajout de la dépendance.

Polices : Geist et Geist Mono (Vercel), SIL Open Font License 1.1, téléchargées au build par
`@nuxt/fonts` et servies par la console ; mention dans `NOTICE`.
