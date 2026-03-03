# Dev-secu-efrei

Travaux Pratiques – Développement Sécurisé Python  
**EFREI Paris** – Robert Bastien

Analyse de logs de sécurité en Python : détection d'attaques SSH et analyse comportementale SOC sur les logs FICOBA de la DGFiP.

---

## Structure du projet

```
.
├── auth.log              # Fichier de log SSH analysé
├── mission-1/
│   └── ssh.py            # Analyseur de logs SSH (script monolithique)
├── ssh_monitor/          # Mission 2 – version modulaire et sécurisée
│   ├── config.py
│   ├── detector.py
│   ├── logger_config.py
│   ├── main.py
│   ├── parser.py
│   └── realtime.py
├── mission-3/
│   ├── main.py           # Analyseur de logs FICOBA
│   ├── ficoba_logs.txt   # Fichier de log FICOBA
│   └── ficoba_alertes.csv
└── README.md
```

---

## Mission 1 – Analyseur de logs SSH

**Objectif :** détecter les comportements suspects dans un fichier `/var/log/auth.log` :
- Tentatives de brute force (fenêtre temporelle glissante)
- Utilisateurs invalides
- Échecs d'authentification répétés
- IPs trop actives
- Connexions SSH réussies
- Événements MaxStartups / throttling

**Exécution :**

```bash
cd mission-1
python3 ssh.py
```

> Le fichier `auth.log` doit être présent à la racine du projet. Le chemin est configurable dans le script (`LOG_FILE`).

---

## Mission 2 – SSH Monitor (outil sécurisé et modulaire)

**Objectif :** refonte de la Mission 1 en outil production-ready, conforme aux critères de développement sécurisé :
- Gestion des exceptions (FileNotFoundError, PermissionError)
- Protection contre le log flooding (deque bornée)
- Validation des adresses IP via le module `ipaddress`
- Journalisation professionnelle avec `logging`
- Mode temps réel (suivi live du fichier log, style `tail -f`)
- Configuration centralisée dans `config.py`

**Configuration (`ssh_monitor/config.py`) :**

```python
LOG_FILE = "/var/log/auth.log"   # Chemin du fichier de log
BRUTE_FORCE_THRESHOLD = 10       # Seuil de tentatives pour brute force
BRUTE_FORCE_WINDOW_MINUTES = 2   # Fenêtre temporelle (minutes)
IP_ACTIVITY_THRESHOLD = 50       # Seuil d'activité par IP
REALTIME_MODE = False            # True pour le mode temps réel (tail -f)
```

**Exécution :**

```bash
cd ssh_monitor
python3 main.py
```

> Passer `REALTIME_MODE = True` dans `config.py` pour surveiller le fichier en temps réel.

---

## Mission 3 – Analyse SOC : logs FICOBA (DGFiP)

**Objectif :** analyse post-incident sur les logs applicatifs du système FICOBA. Détection de :
- Usurpation d'identité (IP externe avec identifiants valides)
- Contournement ou échec MFA (`MFA_FAIL`, `MFA_BYPASS`)
- Accès hors horaires (avant 06h00 ou après 20h00)
- Extraction massive de données (exports > 1000 lignes)
- Rafales de requêtes (> 50 requêtes en moins de 10 secondes)

Les alertes sont exportées dans un fichier CSV (`ficoba_alertes.csv`) exploitable dans un SIEM.

**Exécution :**

```bash
cd mission-3
python3 main.py
```

> Le fichier `ficoba_logs.txt` doit être présent dans le dossier `mission-3/`. Le chemin est configurable dans le script (`file_path`).

**Format des logs attendu :**

```
[TIMESTAMP] USER | ROLE | IP | APP | ACTION | RESOURCE | QUERY_COUNT | STATUS | MFA | SESSION_ID
```

**Format du CSV généré (`ficoba_alertes.csv`) :**

| Timestamp | User | IP | Action | Query_Count | Session_ID | Anomalie |
|-----------|------|----|--------|-------------|------------|----------|

---

## Prérequis

Python 3.8+ — aucune dépendance externe, uniquement la bibliothèque standard.

```bash
python3 --version
```
