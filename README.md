# Veille cybersécurité vers Telegram

Un bot qui surveille les sources de référence en cybersécurité et envoie les nouveautés sur un canal Telegram, quasiment en temps réel. Il tourne sur GitHub Actions, sans serveur ni dépendance externe (Python standard uniquement).

## Fonctionnement

Le workflow s'exécute toutes les 20 minutes environ. À chaque passage, `cyber_watch.py` :

1. interroge une trentaine de flux RSS/Atom et le catalogue CISA KEV ;
2. écarte ce qui a déjà été envoyé (dédoublonnage par URL et par titre) ;
3. envoie immédiatement les **alertes** ;
4. envoie les autres nouveautés regroupées par catégorie ;
5. signale une source injoignable depuis plus de 12 heures.

Les articles en anglais sont traduits en français (titre, et résumé pour les alertes).

### Ce qui déclenche une alerte immédiate

- toute nouvelle alerte du CERT-FR ;
- toute nouvelle entrée du catalogue CISA KEV (vulnérabilité dont l'exploitation active est confirmée), avec l'échéance de correction et la mention d'un usage par des ransomwares le cas échéant ;
- les articles qui signalent un zero-day, une exploitation active, un correctif d'urgence, une faille critique ou une attaque sur la chaîne d'approvisionnement.

### Sources

| Catégorie | Sources |
|---|---|
| Alertes et avis officiels | CERT-FR (alertes, avis), CISA Advisories, NCSC UK |
| Cybersécurité | The Hacker News, BleepingComputer, SecurityWeek, The Record, Krebs on Security, Dark Reading, Help Net Security, Schneier, ZATAZ, LMI, Numerama, Global Security Mag |
| Menaces et CTI | CERT-FR CTI, SANS ISC, Unit 42, Cisco Talos, ESET, Microsoft Security, Sekoia, Check Point Research, Securelist, Malwarebytes, Rapid7 |
| Sécurité offensive et recherche | PortSwigger Research, Google Project Zero |
| Réglementation et conformité | ANSSI, CERT-FR actualités, CNIL, LINC CNIL |

La liste est dans `SOURCES` en haut de `cyber_watch.py`. Ajouter une source revient à ajouter une ligne.

## Mise en place

1. Créer un bot avec [@BotFather](https://t.me/BotFather) et récupérer son token.
2. Ajouter le bot comme administrateur du canal et récupérer l'identifiant du canal.
3. Dans les paramètres du dépôt, section Secrets and variables > Actions, créer :
   - `TELEGRAM_BOT_TOKEN_WATCH`
   - `TELEGRAM_CHAT_ID_WATCH`
4. Activer le workflow dans l'onglet Actions. Le premier passage envoie un message de confirmation et les alertes des dernières 24 heures, puis amorce l'historique sans inonder le canal.

## Exécution locale

```bash
cp .env.example .env            # renseigner le token et l'identifiant du canal
python cyber_watch.py --dry-run # affiche les messages sans rien envoyer
python cyber_watch.py           # envoi réel, état dans state/seen.json
```

Pour tester le dédoublonnage sans toucher à l'état réel : `python cyber_watch.py --dry-run --state /tmp/seen.json`.

## Persistance de l'état

L'historique des éléments déjà envoyés est stocké dans `seen.json` sur la branche `state` du dépôt (un seul commit, réécrit à chaque changement). Cela garde la branche principale propre et maintient une activité régulière sur le dépôt, ce qui empêche GitHub de désactiver les workflows planifiés après 60 jours d'inactivité.

## Réglages

Les constantes en haut de `cyber_watch.py` permettent d'ajuster le comportement : âge maximal des articles, nombre maximal d'alertes et d'éléments par passage, mots-clés des signaux critiques (`STRONG_RE`, `TITLE_RE`) et filtre promotionnel (`PROMO_RE`).

## Audit de logs

`security_audit.py` est un utilitaire indépendant qui détecte les attaques par force brute dans un fichier de journaux d'authentification (exemple : `mock_auth.log`). La veille d'actualités est désormais assurée par `cyber_watch.py`.
