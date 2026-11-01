# Recette agents-firewall — résultats

Généré le 2026-10-31T11:11:19Z : 20 PASS, 0 FAIL, 0 SKIP.

| Scénario | Résultat | Durée | Détail |
|---|---|---|---|
| 01-refus-immediat — Refus immédiat et explicite d'une destination non autorisée | PASS | 4 s | 403 explicite en 88 ms, journalisé, rien reçu par la cible |
| 02-autoriser-depuis-le-journal — Un refus légitime corrigé depuis le journal en < 2 min | PASS | 8 s | corrigé depuis le journal en 5 s |
| 03-contournement-variable — Destination interdite cachée dans une variable | PASS | 1 s | aucune variante n'a atteint la cible |
| 04-contournement-script — Script Python qui ignore le proxy | PASS | 21 s | le script qui ignore le proxy n'a rien fait sortir |
| 05-contournement-proxy-ignore — curl --noproxy, IP directe, nc, DNS externe, métadonnées | PASS | 2 s | aucune méthode de contournement n'a abouti |
| 06-secret-bloque — Secret envoyé vers une destination autorisée : bloqué et masqué | PASS | 1 s | secret bloqué vers une destination autorisée et masqué dans le journal |
| 07-llm-exempte — Secret vers le fournisseur LLM : passe, masqué dans le journal | PASS | 1 s | LLM exempté du blocage, contenu journalisé et masqué |
| 08-mouvement-lateral — Balayage de ports sur le réseau interne : alerte | PASS | 1 s | balayage détecté et alerté, flux internes visibles |
| 09-publier-installer-rollback — Publication, installation et retour arrière | PASS | 7 s | publication, installation et retour arrière vérifiés par le trafic |
| 10-mcp-agree-audit — Administration par l'agent agréé via MCP, tracée ; sa propre zone refusée | PASS | 11 s | zone déléguée modifiée et tracée (interface mcp), propre zone refusée |
| 11-hermes-une-commande — Nouveau bot Hermes enrôlé en une commande | PASS | 10 s | bot Hermes enrôlé, publié, démarré et visible en une commande (6 s), protégé |
| 12-latence — Latence p50/p95 avec et sans passerelle (HTTPS inspecté, connexion nouvelle et réutilisée) | PASS | 61 s | surcoût médian, connexion nouvelle : p50 5.0 ms, p95 5.3 ms ; connexion réutilisée : p50 0.4 ms, p95 0.2 ms |
| 13-agent-vers-agent — Un agent ne joint pas directement un autre agent | PASS | 6 s | aucun chemin direct entre agents ; tout passe par la passerelle |
| 14-tracabilite — Flux → agent, conversation, outil, contenu, règle en < 60 s | PASS | 1 s | flux retrouvé avec agent, conversation, outil, contenu et règle en 1 s |
| 15-outil-mcp-sortant — Outil MCP qui fait sa propre sortie réseau | PASS | 5 s | l'outil MCP n'a rien fait sortir (proxy, sans proxy, IP directe) |
| 16-agent-reecrit-politique — Un agent ne peut pas réécrire la politique par l'API | PASS | 1 s | la passerelle refuse toute écriture de la politique par un agent |
| 17-passerelle-sans-internet — La passerelle ne joint pas example.com | PASS | 11 s | aucune sortie Internet depuis la passerelle ; résolution par le seul DNS amont configuré |
| 18-passerelle-arretee — Passerelle arrêtée : plus aucun accès réseau pour les agents | PASS | 45 s | passerelle arrêtée : aucun accès (proxy, IP directe, LAN, DNS) ; reprise avec la révision 9 |
| 19-console-injoignable — Console injoignable : la passerelle continue d'appliquer la politique | PASS | 13 s | console coupée : la passerelle a continué d'appliquer la révision 9 (autorisé, refusé, DLP), journal rattrapé au retour |
| 20-mesures-journal — Mesures : refus → flux ouvert, et flux → agent/conversation/action/contenu/règle | PASS | 15 s | refus → flux ouvert : médiane 919 ms ; flux → agent/conversation/action/contenu/règle : médiane 832 ms (max 997 ms) |

Hors démo (production) : migration de Daniel, Laurent et Vulcain et retrait de l'egress-guard actuel (cahier §8) ; à constater sur les hôtes réels.

## Preuves

### 01-refus-immediat — PASS

- `positive control: laurent-bot -> allowed.example received (ctl-a08ae2490230)`
- `HTTPS through the proxy: HTTP 403 in 88 ms (denied on CONNECT)`
- `header: x-agents-firewall: denied`
- `body: blocked by agents-firewall: exfil.example not allowed for laurent-bot (rule default-deny)`
- `exfil received nothing for s01-e81e4188b76d (0 requests in its log)`
- `log: flow 01a191a4-7b7c-7642-a88a-6aaada664d0c rule #null (no rule matched: default deny)`

### 02-autoriser-depuis-le-journal — PASS

- `before: acme-bot -> api.github.com = HTTP 403`
- `denied flow 01a191a4-8b1e-74c1-9cb3-f9613eeb8d31`
- `rule created from the log: {"id":"1ad64912-21a8-4053-9775-c99e1bb0c70d","name":"Autoriser api.github.com","layer":{"type":"zone","zone_id":"00000000-0000-4000-8000-000000000402"},"destinations":["00000000-0000-4000-8000-000000000107"],"action":"accept"}`
- `revision 3 published and installed`
- `after: acme-bot -> api.github.com = HTTP 200, total 5 s`
- `cleanup: revision 4 removes the rule`

### 03-contournement-variable — PASS

- `positive control: laurent-bot -> allowed.example received (ctl-d62d50f2d0ef)`
- `variable: exit 56, curl: (56) CONNECT tunnel failed, response 403`
- `concatenation: exit 56, curl: (56) CONNECT tunnel failed, response 403`
- `base64: exit 56, curl: (56) CONNECT tunnel failed, response 403`
- `wget: exit 1, wget: server returned error: HTTP/1.1 400 Bad Request`
- `python env: exit 1, Traceback (most recent call last):   File "/usr/local/lib/python3.12/urllib/request.py", line 1344, in do_open     h.request(req.get_method(), req.selector, req.data, headers,   File "/usr/local/lib/p`
- `exfil received nothing for s03-3e3fdfaef25a (0 requests in its log)`

### 04-contournement-script — PASS

- `positive control: laurent-bot -> allowed.example received (ctl-09cb7a49c68f)`
- `urllib-noproxy: URLError: <urlopen error [Errno -3] Try again>`
- `raw-socket-tls: gaierror: [Errno -3] Try again`
- `http.client: gaierror: [Errno -3] Try again`
- `plain-http: gaierror: [Errno -3] Try again`
- `exfil received nothing for s04-abc1de2e3c33 (0 requests in its log)`

### 05-contournement-proxy-ignore — PASS

- `positive control: laurent-bot -> allowed.example received (ctl-4e51ccf31914)`
- `curl --noproxy '*': exit 6, curl: (6) Could not resolve host: exfil.example`
- `direct IP (no DNS, no SNI): exit 0, blocked by agents-firewall: 198.18.0.11 not allowed for laurent-bot (rule default-deny)`
- `direct IP over HTTP: exit 0, blocked by agents-firewall: 198.18.0.11 not allowed for laurent-bot (rule default-deny)`
- `Host header spoofing: HTTP/1.1 200 OK {"service": "allowed-api", "received": 17, "path": "/spoof"} `
- `domain fronting (SNI allowed, Host forbidden): exit 0, blocked by agents-firewall: exfil.example not allowed for laurent-bot (rule host-mismatch)`
- `raw TCP (nc): exit 0, `
- `external DNS resolver: exit 0,  ; <<>> DiG 9.18.49 <<>> +time=3 +tries=1 @198.18.0.53 s05-b7126b765d27.exfil.example A ; (1 server found) ;; global options: +cmd ;; Got answer: ;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 47`
- `change the route (no NET_ADMIN): exit 2, RTNETLINK answers: Operation not permitted`
- `dig @8.8.8.8 s05-b7126b765d27.exfil.example -> ''`
- `cloud metadata (direct): HTTP '403'`
- `metadata denied by baseline rule #1`
- `exfil received nothing for s05-b7126b765d27 (0 requests in its log)`
- `exfil received nothing for s05s-eb9ee06340b8 (0 requests in its log)`
- `Host-spoofed request delivered to allowed-api (address of allowed.example), never to 198.18.0.11`
- `allowed-api received nothing for s05-b7126b765d27 (6 requests in its log)`
- `the outside resolver never saw s05-b7126b765d27.exfil.example`
- `default route still via the gateway`

### 06-secret-bloque — PASS

- `positive control: laurent-bot -> allowed.example received (ctl-262392008472)`
- `laurent-bot -> allowed.example with an AWS access key: HTTP 403`
- `allowed-api received nothing for AKIA**************** (7 requests in its log)`
- `flow: rule #2 Secrets sortants, classes []`
- `log stores no raw secret (masked)`

### 07-llm-exempte — PASS

- `laurent-bot -> api.anthropic.com/v1/messages with a secret in the prompt: HTTP 200`
- `the provider received the prompt (exemption EF-25)`
- `flow: llm_provider=true, tls_inspected=true, classes ["Secrets"]`
- `request body logged with the secret masked: [SECRET:aws_access_key:f3adf83b7108]`

### 08-mouvement-lateral — PASS

- `scanned 20 ports of 10.78.0.20: Connection to 10.78.0.20 21 port [tcp/ftp] succeeded! open:21 Connection to 10.78.0.20 22 port [tcp/ssh] succeeded! open:22 Connection to 10.78.0.20 23 port [tcp/telnet] succeeded! open:23 Connection to 10.78.0.20 25 port [tcp/smtp] succeeded! open:25 Connection to 10.78.0.20 80 port [tcp/http] succeeded! open:80 Connection to 10.78.0.20 110 port [tcp/pop3] succeeded! open:110 Connection to 10.78.0.20 135 port [tcp/epmap] succeeded! open:135 Connection to 10.78.0.20 139 port [tcp/netbios-ssn] succeeded! open:139 Connection to 10.78.0.20 443 port [tcp/https] succeeded! open:443 Connection to 10.78.0.20 445 port [tcp/microsoft-ds] succeeded! open:445 Connection to 10.78.0.20 1433 port [tcp/ms-sql-s] succeeded! open:1433 Connection to 10.78.0.20 1521 port [tcp/*] succeeded! open:1521 Connection to 10.78.0.20 3306 port [tcp/mysql] succeeded! open:3306 Connection to 10.78.0.20 3389 port [tcp/ms-wbt-server] succeeded! open:3389 Connection to 10.78.0.20 5432 port [tcp/postgresql] succeeded! open:5432 Connection to 10.78.0.20 5900 port [tcp/*] succeeded! open:5900 Connection to 10.78.0.20 6379 port [tcp/redis] succeeded! open:6379 Connection to 10.78.0.20 8080 port [tcp/http-alt] succeeded! open:8080 Connection to 10.78.0.20 9200 port [tcp/*] succeeded! open:9200 Connection to 10.78.0.20 27017 port [tcp/*] succeeded! open:27017`
- `internal flow to 5432 allowed (monitored)`
- `alert: warning port_scan: 10 ports of 10.78.0.20 contacted in 60 s`
- `internal map edges to 10.78.0.20: [21,22,23,25,80,110,135,139,443,445,1433,1521,3306,3389,5432,5900,6379,8080,9200,27017]`

### 09-publier-installer-rollback — PASS

- `revision 4: acme-bot -> allowed.example = 200`
- `revision 5 installed: [{"kind":"modified","name":"API autorisée"}]`
- `revision 5: acme-bot -> allowed.example = 403`
- `rollback to revision 4: acme-bot -> allowed.example = 200`
- `revision 6 restores the demo policy`

### 10-mcp-agree-audit — PASS

- `afw-mcp tools: whoami, list_resources, get_resource, create_resource, update_resource, delete_resource, where_used, move_rule, get_rulebase, open_session, current_session, discard_session, publish_session, allow_from_log, verify_policy, list_revisions, diff_revision, install_revision, list_installs, list_gateways, policy_status, search_flows, get_flow, search_dns, agent_overview, internal_map, list_alerts, ack_alert, list_audit, verify_audit, list_approvals`
- `open_session: {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{\n  \"id\": \"e52f83cb-f9b7-46a1-bef4-763f18db00e3\",\n  \"owner\": {\n    \"kind\": \"agen`
- `rule in delegated zone clients: {"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"{\n  \"action\": \"accept\",\n  \"comment\": \"\",\n  \"data_classes\": [],\n  \"destinations\": [\n    \"00000000-0000-4000-8000-00`
- `rule in its own zone internes: {"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"Refused by the agents-firewall API (403 Forbidden): the MCP agent cannot modify its own zone\nThe API decides what you may change: o`
- `publish: {"jsonrpc":"2.0","id":6,"result":{"content":[{"type":"text","text":"Published revision 7. Install it with install_revision.\n{\n  \"number\": 7,\n  \"published_at\": \"2026-10-31T11:08:16.135Z\",\n  \`
- `audit (interface mcp): #66 agent/demo-mcp-d5d8b5 session.publish revision:7;#65 agent/demo-mcp-d5d8b5 rule.create rule:7a621ec0-d88f-490b-b2ce-67d0e8dc9229;#64 agent/demo-mcp-d5d8b5 session.open session:e52f83cb-f9b7-46a1-bef4-763f18db00e3;`
- `audit chain: {"ok":true,"checked":66,"broken_at":null,"head_seq":66,"head_hash":"56430f280b3b079ab94cf2bffb1dee9a673a2df24623ea37884d009ea4a2cb99","anchor_sources":["db"]}`

### 11-hermes-une-commande — PASS

- `one command: afw enroll hermes-nouveau-2f3a --zone clients --ip 10.77.0.13 --gateway demo-gw --compose demo/.state/s11/docker-compose.yml --network afw-demo_afw-internal --ca-path demo/.state/s11/gateway.crt --hermes --hermes-plugin-dir integrations/hermes --console-url http://10.76.0.10:8080 --env-file demo/.state/s11/.env --publish 'Démo 11 : enrôlement de hermes-nouveau-2f3a' --apply`
- `output:  Container afw-demo-s11-hermes-nouveau-2f3a-1  Starting  Container afw-demo-s11-hermes-nouveau-2f3a-1  Started Enrolled hermes-nouveau-2f3a (0beec7b9-6074-44fd-a29d-4d7ec09e2c0b) in zone clients on gateway a7d9d881-8fbd-4f8e-87e6-aadb422722b7, session 23502b75-2d9a-4674-841b-39a93ea369a2. Published `
- `agent hermes-nouveau-2f3a visible in the console (id 0beec7b9-6074-44fd-a29d-4d7ec09e2c0b, zone 00000000-0000-4000-8000-000000000402), revision 9 published, in 6 s`
- `before install: hermes-nouveau-2f3a -> exfil.example = 403`
- `after install of 9: hermes-nouveau-2f3a -> allowed.example = 200 (zone clients)`
- `new bot protected: exfil.example denied by rule default-deny`

### 12-latence — PASS

- `5 passes x 50 requests per mode (gateway path: explicit proxy + TLS inspection; reuse mode drops the first, connecting, transfer)`
- `pass 1 new: gateway p50 51.7 / p95 55.7 ms — direct p50 46.8 / p95 50.4 ms`
- `pass 1 reuse: gateway p50 44.1 / p95 46.5 ms — direct p50 42.9 / p95 45.9 ms`
- `pass 2 new: gateway p50 51.3 / p95 55.6 ms — direct p50 46.0 / p95 49.7 ms`
- `pass 2 reuse: gateway p50 43.6 / p95 45.9 ms — direct p50 43.4 / p95 45.7 ms`
- `pass 3 new: gateway p50 51.5 / p95 55.2 ms — direct p50 46.3 / p95 50.1 ms`
- `pass 3 reuse: gateway p50 43.2 / p95 46.1 ms — direct p50 43.0 / p95 45.4 ms`
- `pass 4 new: gateway p50 51.4 / p95 55.4 ms — direct p50 46.5 / p95 49.6 ms`
- `pass 4 reuse: gateway p50 43.4 / p95 45.3 ms — direct p50 42.9 / p95 45.8 ms`
- `pass 5 new: gateway p50 51.6 / p95 54.8 ms — direct p50 46.5 / p95 50.4 ms`
- `pass 5 reuse: gateway p50 43.1 / p95 45.9 ms — direct p50 43.1 / p95 45.5 ms`
- `MEDIAN new connection: gateway p50 51.5 ms, p95 55.4 ms — direct p50 46.5 ms, p95 50.1 ms — overhead p50 5.0 ms, p95 5.3 ms`
- `MEDIAN reuse connection: gateway p50 43.4 ms, p95 45.9 ms — direct p50 43.0 ms, p95 45.7 ms — overhead p50 0.4 ms, p95 0.2 ms`
- `sample flow: tls_inspected=true, content_inspected=true`

### 13-agent-vers-agent — PASS

- `laurent-bot routes: default via 10.77.0.2 dev eth0 ;10.77.0.2 dev eth0 scope link `
- `path to acme-bot: 10.77.0.12 via 10.77.0.2 dev eth0 src 10.77.0.11 uid 0 `
- `no IPv6 link-local, no other interface up`
- `laurent-bot -> acme-bot:7777: exit 0, `
- `neighbours of laurent-bot: 10.77.0.2 dev eth0 lladdr 4e:ff:52:af:9b:3c REACHABLE `
- `delivered through the gateway: internal flow {"id":"01a191a6-9b64-74a8-8371-0cdefbcde470","internal":true,"layer":"implicit","reason":"internal destination: allowed and monitored by default"}`

### 14-tracabilite — PASS

- `daniel-bot /run fetch in conv-s14-2d7cc7b2: {"blocked": false, "status": "ok", "error": null, "result": {"status": 200, "bytes": 61}, "tool_call_id": "d3e2bc16-c5f3-4820-afc6-0ad6d6428997"}`
- `agent: b80790e3-0090-4942-882e-914a432cbbe1 (daniel-bot)`
- `conversation: conv-s14-2d7cc7b2 (confidence certain)`
- `tool: fetch — url: https://allowed.example/report; method: POST; body: weekly report s14-537a9`
- `content: request body logged (POST https://allowed.example:443/report)`
- `rule: #8 API autorisée`

### 15-outil-mcp-sortant — PASS

- `positive control: laurent-bot -> allowed.example received (ctl-198f056011a6)`
- `call 1: URLError: <urlopen error Tunnel connection failed: 403 Forbidden>`
- `call 2: URLError: <urlopen error [Errno -3] Try again>`
- `call 3: HTTPError: HTTP Error 403: Forbidden`
- `exfil received nothing for s15-0ac773f3411c (0 requests in its log)`

### 16-agent-reecrit-politique — PASS

- `open a session (direct): HTTP/1.1 403 Forbidden x-agents-firewall: denied x-agents-firewall-reason: blocked by agents-firewall: 10.76.0.10 not allowed for laurent-bot (rule 4) blocked by agents-firewall: 10.76.0.10 not allowe`
- `open a session (direct): denied by the gateway (HTTP answer with X-Agents-Firewall: denied)`
- `open a session (proxy): HTTP/1.1 403 Forbidden x-agents-firewall: denied x-agents-firewall-reason: blocked by agents-firewall: 10.76.0.10 not allowed for laurent-bot (rule 4) blocked by agents-firewall: 10.76.0.10 not allowe`
- `open a session (proxy): denied by the gateway (HTTP answer with X-Agents-Firewall: denied)`
- `rewrite a rule: HTTP/1.1 403 Forbidden x-agents-firewall: denied x-agents-firewall-reason: blocked by agents-firewall: 10.76.0.10 not allowed for laurent-bot (rule 4) blocked by agents-firewall: 10.76.0.10 not allowe`
- `rewrite a rule: denied by the gateway (HTTP answer with X-Agents-Firewall: denied)`
- `path traversal: HTTP 403 x-agents-firewall: denied`
- `x-agents-firewall-reason: blocked by agents-firewall: 10.76.0.10 not allowed for laurent-bot (rule 4)`
- `ingestion from another zone: HTTP/1.1 403 Forbidden x-agents-firewall: denied x-agents-firewall-reason: blocked by agents-firewall: 10.76.0.10 not allowed for acme-bot (rule 4) blocked by agents-firewall: 10.76.0.10 not allowed f`
- `ingestion from another zone: denied by the gateway (HTTP answer with X-Agents-Firewall: denied)`
- `gateway endpoint :8443: HTTP/2 403  x-agents-firewall: denied x-agents-firewall-reason: blocked by agents-firewall: 10.76.0.10 not allowed for laurent-bot (rule 4) blocked by agents-firewall: 10.76.0.10 not allowed for laure`
- `gateway endpoint :8443: denied by the gateway (HTTP answer with X-Agents-Firewall: denied)`
- `control-plane database 10.76.0.5:5432: no answer (LAN database control answered 'N')`
- `plugin token on an admin route: HTTP/1.1 403 Forbidden x-agents-firewall: denied x-agents-firewall-reason: blocked by agents-firewall: 10.76.0.10 not allowed for daniel-bot (rule 4) blocked by agents-firewall: 10.76.0.10 not allowed`
- `plugin token on an admin route: denied by the gateway (HTTP answer with X-Agents-Firewall: denied)`
- `plugin ingestion route without token: HTTP 401 (answered by the API)`
- `no new session, revision still 9`

### 17-passerelle-sans-internet — PASS

- `system resolver: example.com not resolved`
- `no route to a public IP or resolver`
- `AFW_UPSTREAM_DNS (198.18.0.53): example.com -> NXDOMAIN, api.anthropic.com -> 198.18.0.10`

### 18-passerelle-arretee — PASS

- `positive control: laurent-bot -> allowed.example received (ctl-b1a8f2636d1a)`
- `gateway container stopped (active revision was 9)`
- `laurent-bot -> allowed.example (proxy): HTTP 000`
- `laurent-bot -> 198.18.0.12 (direct IP): HTTP 000`
- `laurent-bot -> 10.78.0.20:5432 (LAN): ''`
- `laurent-bot -> DNS @198.18.0.53: no answer`
- `acme-bot -> allowed.example (proxy): HTTP 000`
- `acme-bot -> 198.18.0.12 (direct IP): HTTP 000`
- `acme-bot -> 10.78.0.20:5432 (LAN): ''`
- `acme-bot -> DNS @198.18.0.53: no answer`
- `allowed-api received nothing for s18-77229e1e0679 (1113 requests in its log)`
- `gateway restarted: traffic back in 0 s`
- `after restart: exfil.example still denied (installed revision reloaded from the state volume)`

### 19-console-injoignable — PASS

- `positive control: laurent-bot -> allowed.example received (ctl-8c0c45f17cad)`
- `API (control plane) stopped; installed revision 9`
- `laurent-bot -> allowed.example: HTTP 200`
- `laurent-bot -> exfil.example: HTTP 403`
- `acme-bot -> api.github.com (zone clients): HTTP 403`
- `laurent-bot -> allowed.example with a secret: HTTP 403`
- `exfil received nothing for s19-5e2fb0dd4cc6 (0 requests in its log)`
- `allowed-api received nothing for AKIA**************** (1116 requests in its log)`
- `API restarted`
- `event queued by the gateway and delivered after the outage: flow {"id":"01a191a7-d13e-706d-81ac-3dd934c069d3","started_at":"2026-10-31T11:10:56.830930Z","rule":"default-deny"}`
- `gateway status: online, revision 9`

### 20-mesures-journal — PASS

- `run 1: denial answered in 112 ms; flow opened through the API 815 ms after the request started`
- `run 1: conv-s20-46b17859 — agent, conversation, tool fetch, content and rule #8 available 830 ms after the tool call (the 2 API calls: 63 ms)`
- `run 2: denial answered in 129 ms; flow opened through the API 861 ms after the request started`
- `run 2: conv-s20-ce7d9423 — agent, conversation, tool fetch, content and rule #8 available 832 ms after the tool call (the 2 API calls: 61 ms)`
- `run 3: denial answered in 107 ms; flow opened through the API 919 ms after the request started`
- `run 3: conv-s20-fa498ff2 — agent, conversation, tool fetch, content and rule #8 available 997 ms after the tool call (the 2 API calls: 62 ms)`
- `run 4: denial answered in 105 ms; flow opened through the API 962 ms after the request started`
- `run 4: conv-s20-f8c0f656 — agent, conversation, tool fetch, content and rule #8 available 690 ms after the tool call (the 2 API calls: 60 ms)`
- `run 5: denial answered in 110 ms; flow opened through the API 973 ms after the request started`
- `run 5: conv-s20-0d853b3d — agent, conversation, tool fetch, content and rule #8 available 852 ms after the tool call (the 2 API calls: 61 ms)`
- `MEDIAN denial -> flow opened: 919 ms (max 973 ms) over 5 runs`
- `MEDIAN tool call -> agent/conversation/action/content/rule: 832 ms (max 997 ms); API calls themselves 61 ms`

