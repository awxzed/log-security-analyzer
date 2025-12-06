# Log Security Analyzer

Outil d'analyse de logs pour la détection d'anomalies et d'activités suspectes dans les fichiers de logs de serveurs web.

## Fonctionnalités

### Détection d'Anomalies

**1. Anomalie de Fréquence (Brute Force)**
- Détecte les tentatives de force brute
- Seuil : Plus de 50 requêtes en moins de 5 minutes depuis une même IP
- Indique une potentielle attaque par dictionnaire

**2. Anomalie de Contenu (Vulnérabilités)**
- Identifie les tentatives d'exploitation de failles
- Signatures détectées :
  - SQL Injection (`union select`, `select * from`)
  - Path Traversal (`../`, `/etc/passwd`)
  - Recherche de backdoors (`phpmyadmin`, `wp-admin`)
  - Exposition de fichiers sensibles (`.env`, `config.php`)

## Structure du Projet

```
log-security-analyzer/
├── log_analyzer.py       # Script principal d'analyse
├── test_access.log       # Fichier de logs de test
└── README.md            # Documentation
```

## Utilisation

### Exécution de base

```bash
python log_analyzer.py
```

Le script analyse le fichier `test_access.log` par défaut et affiche :
- Les anomalies détectées avec leurs détails
- Le type d'attaque identifiée
- L'adresse IP source
- Les requêtes suspectes
- Les statistiques globales

### Analyser un fichier personnalisé

Modifiez la variable `LOG_FILE` dans `log_analyzer.py` :

```python
LOG_FILE = 'votre_fichier.log'
```

## Format des Logs

Le script supporte le format Apache/Nginx Common Log Format (CLF) :

```
IP - - [timestamp] "METHOD /path HTTP/version" status_code size
```

Exemple :
```
192.168.1.100 - - [06/Dec/2025:10:30:15 +0100] "GET /index.html HTTP/1.1" 200 1234
```

## Résultats

Le script génère un rapport structuré incluant :
- Nombre total d'anomalies
- Détails par anomalie (type, IP, requête, timestamp)
- Statistiques de traitement (IPs analysées, requêtes totales)

## Cas d'Usage

- **Blue Team** : Surveillance proactive des logs
- **Incident Response** : Analyse post-intrusion
- **Forensics** : Investigation de sécurité
- **Monitoring** : Détection temps-réel d'activités malveillantes

## Prérequis

- Python 3.6+
- Aucune dépendance externe (utilise uniquement la bibliothèque standard)

## Améliorations Possibles

- Export des résultats en JSON/CSV
- Alertes en temps réel
- Intégration avec SIEM
- Dashboard de visualisation
- Machine Learning pour détection avancée
- Support de formats de logs multiples
