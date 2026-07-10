# Veille Technologique & Préparation au TOEIC 🤖💼

Ce dépôt héberge une suite d'outils automatisés conçus pour la veille technologique (Informatique, IA, Cybersécurité et Réglementation) et l'entraînement quotidien au test d'anglais TOEIC. Le tout est orchestré par GitHub Actions et délivré directement sur des canaux Telegram sous forme de digests enrichis.

---

## 🌟 Fonctionnalités Principales

### 1. 🎓 Préparation Quotidienne au TOEIC (`english_toeic_bot.py`)
Ce bot envoie des exercices de préparation au TOEIC en deux sessions quotidiennes :
* ☀️ **Session du Matin (Part 5 - Incomplete Sentences) :** Questions à choix multiples portant sur la grammaire et le vocabulaire.
* 🌙 **Session du Soir (Part 7 - Reading Comprehension) :** Textes courts de compréhension écrite accompagnés de questions.
* 💡 **Correction masquée :** Les réponses et explications détaillées sont envoyées sous forme de **spoiler Telegram** pour encourager l'entraînement.

### 2. 📰 Veille Technologique Complète (`security_audit.py`)
Un agrégateur et traducteur automatique de flux d'actualités structuré en **6 catégories professionnelles** :
* 🔒 **Cybersécurité :** CERT-FR (Avis), The Hacker News, BleepingComputer, Krebs on Security, Dark Reading.
* 🤖 **Intelligence Artificielle :** OpenAI News, TechCrunch AI, Actu IA, Hugging Face, Google Research.
* 💻 **Actualités IT & Tech :** Le Monde Informatique, ZDNet Actualités, Wired, Ars Technica.
* 📜 **Conformité & Réglementation :** ANSSI Actualités, LINC CNIL (RGPD), Global Security Mag (GRC, ISO 27001).
* 🎯 **SÉCURITÉ OFFENSIVE & PENTEST :** Hack The Box Blog, PortSwigger Web Security.
* 🛡️ **THREAT INTEL & SOC :** CERT-FR Menaces (CTI), SANS Internet Storm Center, ESET WeLiveSecurity, Microsoft Security.

> [!TIP]
> **Traduction & Dédoublonnage :** Les actualités issues de sources anglophones sont automatiquement traduites en français à la volée. Les articles doublons sont exclus et les actualités promotionnelles (promos, ventes) sont filtrées.

### 3. 🚨 Audit de Sécurité des Logs (`security_audit.py`)
En plus de la veille, le script analyse les fichiers de journaux d'authentification (ex: `mock_auth.log`) pour détecter les attaques par force brute (adresses IP dépassant un seuil de tentative de connexions échouées) et envoie des rapports d'alertes par e-mail ou Telegram.

---

## 📂 Structure du Projet

```text
├── .github/workflows/
│   ├── cyber_watch.yml      # Workflow de la veille (Matin 09:00 / Soir 23:05)
│   ├── toeic_morning.yml    # Workflow TOEIC Matin (08:00)
│   └── toeic_evening.yml    # Workflow TOEIC Soir (20:00)
├── english_toeic_bot.py      # Script du bot TOEIC (exercices et corrections)
├── security_audit.py        # Script de veille d'actualités et d'audit de logs
├── mock_auth.log            # Fichier de log d'exemple pour l'audit
└── README.md                # Documentation principale
```

---

## 🛠️ Configuration & Variables d'Environnement

Les scripts utilisent uniquement la bibliothèque standard de Python (aucune dépendance externe requise pour garantir une portabilité et une exécution ultra-rapide).

### Variables d'environnement requises
Pour s'exécuter, les bots ont besoin des variables d'environnement suivantes dans les secrets GitHub ou dans votre environnement local :

* `TELEGRAM_BOT_TOKEN` : Token de votre bot Telegram (créé via @BotFather).
* `TELEGRAM_CHAT_ID` : ID du canal ou groupe Telegram de destination.
* `SMTP_SERVER` / `SMTP_PORT` / `SMTP_SENDER` / `SMTP_USER` / `SMTP_PASSWORD` : Optionnel, pour l'envoi d'alertes mail lors de l'audit de logs.

---

## 🚀 Utilisation en Local

### 1. Lancer la Veille Technologique
Pour récupérer les actualités des dernières 48 heures, les traduire et les envoyer sur Telegram :
```bash
python security_audit.py --fetch-news
```

### 2. Lancer les Questions TOEIC
* **Défi du Matin :**
  ```bash
  python english_toeic_bot.py --morning
  ```
* **Défi du Soir :**
  ```bash
  python english_toeic_bot.py --evening
  ```

### 3. Exécuter un Audit de Logs
Pour scanner un fichier log et lister les adresses IP suspectes :
```bash
python security_audit.py mock_auth.log --threshold 5 --telegram
```

---

## ⏰ Planification GitHub Actions

Les tâches s'exécutent automatiquement selon les planifications quotidiennes suivantes (Heure de Paris) :
* 📅 **08h00 :** Envoi du Défi TOEIC Matin (`toeic_morning.yml`)
* 📅 **09h00 :** Premier envoi de la Veille Techno (`cyber_watch.yml`)
* 📅 **20h00 :** Envoi du Défi TOEIC Soir (`toeic_evening.yml`)
* 📅 **23h05 :** Deuxième envoi de la Veille Techno (`cyber_watch.yml`)
