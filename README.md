# 🔍 NetVuln Scanner — Network Vulnerability Scanner

> **Auteur** : Jamein N. Dietrich A.  
> **Contexte** : Projet personnel en cybersécurité — Scan de ports et détection de vulnérabilités réseau

## 📋 Description

NetVuln Scanner est un outil Python de scan réseau qui permet de :

- **Découvrir les hôtes actifs** sur un réseau local (ARP Ping Sweep)
- **Scanner les ports ouverts** sur une cible (TCP Connect Scan + SYN-like Scan)
- **Identifier les services** tournant sur les ports ouverts (banner grabbing)
- **Détecter les vulnérabilités courantes** en comparant les services détectés à une base de signatures CVE locales
- **Générer un rapport HTML** détaillé avec les résultats du scan

## 🎯 Compétences cybersécurité démontrées

| Compétence | Mise en œuvre |
|-----------|---------------|
| Reconnaissance réseau | ARP sweep, découverte d'hôtes |
| Scan de ports | TCP Connect, détection de services |
| Banner Grabbing | Identification des versions de services |
| Analyse de vulnérabilités | Corrélation avec base CVE locale |
| Reporting de sécurité | Génération de rapports structurés |
| Éthique & légalité | Mode localhost par défaut, avertissements |

## ⚙️ Installation

```bash
# Cloner le dépôt
git clone https://github.com/<votre-username>/netvuln-scanner.git
cd netvuln-scanner

# Installer les dépendances
pip install -r requirements.txt
```

## 🚀 Utilisation

```bash
# Scan de base sur localhost (par défaut)
python scanner.py

# Scan d'une cible spécifique
python scanner.py -t 192.168.1.1

# Scan avec plage de ports personnalisée
python scanner.py -t 192.168.1.1 -p 1-1024

# Scan complet avec détection de vulnérabilités
python scanner.py -t 192.168.1.1 --vuln-scan

# Découverte d'hôtes sur le réseau local
python scanner.py --discover -s 192.168.1.0/24

# Générer un rapport HTML
python scanner.py -t 192.168.1.1 --vuln-scan --report rapport.html
```

## 📁 Structure du projet

```
netvuln-scanner/
├── scanner.py          # Script principal du scanner
├── vuln_db.py          # Base de données de vulnérabilités locale
├── report_generator.py # Générateur de rapports HTML
├── requirements.txt    # Dépendances Python
└── README.md           # Documentation
```

## ⚠️ Avertissement éthique

Cet outil est conçu à des fins **éducatives et de test uniquement**. Ne l'utilisez que sur des systèmes dont vous êtes le propriétaire ou pour lesquels vous avez une autorisation explicite. L'utilisation non autorisée de cet outil contre des systèmes tiers est illégale.

## 📜 Licence

MIT License — Libre d'utilisation à des fins éducatives.
