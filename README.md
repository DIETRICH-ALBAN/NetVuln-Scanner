# NetVuln Scanner - Scanner de vulnerabilites reseau

Auteur : Jamein N. Dietrich A.
Contexte : Projet personnel en cyberscurite - Scanner de vulnerabilites reseau educatif

## Description

NetVuln Scanner est un outil educatif de scan de vulnerabilites reseau. Il permet de decouvrir les hotes sur un reseau, d'identifier les ports ouverts et les services en cours d'execution, puis de correler ces informations avec une base de donnees locale de CVE (Common Vulnerabilities and Exposures) pour identifier les vulnerabilites potentielles.

Fonctionnalites principales :
- Decouverte d'hotes par simulation ARP ping sweep
- Scan de ports TCP avec recuperation de bannieres (banner grabbing)
- Correlation CVE avec base de donnees locale de vulnerabilites
- Generation de rapports HTML detailles avec statistiques de severite
- Mode simulation educative et mode scan reel
- Interface CLI complete avec argparse

## Competences cyberscurite demontrees

| Competence | Description |
|---|---|
| Reconnaissance reseau | Decouverte d'hotes et cartographie reseau |
| Scan de ports | Identification des services exposes |
| Banner grabbing | Recuperation d'informations sur les versions |
| Analyse CVE | Correlation avec les vulnerabilites connues |
| Reporting | Generation de rapports de securite |
| Ethique | Avertissement et responsabilisation |

## Installation

```bash
git clone <url-du-depot>
cd netvuln-scanner
pip install -r requirements.txt
```

## Utilisation

Scan en mode simulation (par defaut) :
```bash
python3 scanner.py -t 192.168.1.0
```

Scan avec masque personnalise :
```bash
python3 scanner.py -t 10.0.0.0 -m 16
```

Scan reel (requiert des droits et une autorisation) :
```bash
python3 scanner.py -t 192.168.1.0 --real
```

Specifier un fichier de sortie pour le rapport :
```bash
python3 scanner.py -t 192.168.1.0 -o rapport.html
```

Afficher les services suivis :
```bash
python3 scanner.py --services
```

## Structure du projet

```
netvuln-scanner/
  |-- scanner.py             # Script principal avec CLI
  |-- vuln_db.py             # Base de donnees locale de vulnerabilites
  |-- report_generator.py    # Generateur de rapports HTML
  |-- requirements.txt       # Dependances Python
  |-- README.md              # Documentation du projet
```

## Avertissement ethique

Cet outil est strictement destine a un usage educatif. Le scan de reseaux sans autorisation prealable est illgal et passible de sanctions penales. Vous devez toujours obtenir une autorisation ecrite avant de scanner un reseau qui ne vous appartient pas. L'auteur decline toute responsabilite quant a l'utilisation abusive de cet outil.

## Licence

MIT License
