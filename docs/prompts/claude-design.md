# Brief de design de la console (Claude Design)

Conçois la console web d'agents-firewall, un pare-feu pour agents IA (lis le `README.md` et
`docs/cahier-des-charges.md`, sections 5.1 à 5.8, de https://github.com/aidalinfo/agents-firewall).

Esprit : une console de pare-feu d'entreprise façon Check Point SmartConsole / SmartLog, mais
moderne et simple. Critère n°1 : comprendre un refus et ouvrir le flux en quelques clics.
Stack cible : Nuxt 4 + Nuxt UI, thèmes clair et sombre, dense mais lisible.

Écrans à maquetter :

1. Journal en direct (flux, filtres agent / zone / verdict / règle, recherche) + panneau de
   détail d'un flux (requête et réponse HTTP, appel d'outil et conversation de l'agent, règle
   appliquée, bouton « Autoriser »).
2. Base de règles (socle commun puis règles par zone, sections, compteurs d'utilisation,
   expiration) avec barre de session : modifications en cours → Publier → Installer.
3. Objets et zones (« où est-il utilisé ? »).
4. Vue d'un agent (destinations habituelles, volumes, refus récents).
5. Carte des flux internes + alertes (mouvement latéral, nouvel hôte).
6. Révisions (différences, retour arrière) et journal d'audit.
7. Passerelles (état, version de politique installée).
