#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Base de donnees de vulnerabilites locale pour NetVuln Scanner
Auteur : Jamein N. Dietrich A.
"""

# Base de donnees locale de vulnerabilites par service/port
# Format : port -> liste de vulnerabilites connues
VULN_DATABASE = {
    21: [
        {
            "service": "FTP",
            "cve": "CVE-2021-36159",
            "description": "VSFTPD 2.3.4 - Porte derobee (backdoor)",
            "severity": "CRITIQUE",
            "version_affectee": "2.3.4",
            "recommendation": "Mettre a jour vers vsftpd 3.0.5 ou superieur"
        },
        {
            "service": "FTP",
            "cve": "CVE-2019-12815",
            "description": "ProFTPD - Copie de fichier arbitraire",
            "severity": "ELEVEE",
            "version_affectee": "1.3.5",
            "recommendation": "Mettre a jour vers ProFTPD 1.3.6+"
        }
    ],
    22: [
        {
            "service": "SSH",
            "cve": "CVE-2020-15778",
            "description": "OpenSSH - Execution de commande via scp",
            "severity": "ELEVEE",
            "version_affectee": "< 8.4",
            "recommendation": "Mettre a jour OpenSSH a la derniere version"
        },
        {
            "service": "SSH",
            "cve": "CVE-2018-15473",
            "description": "OpenSSH - Enumeration d'utilisateurs",
            "severity": "MOYENNE",
            "version_affectee": "< 7.7",
            "recommendation": "Mettre a jour OpenSSH 7.7+"
        }
    ],
    23: [
        {
            "service": "Telnet",
            "cve": "CVE-2018-10547",
            "description": "Telnet - Transmission en clair",
            "severity": "CRITIQUE",
            "version_affectee": "Toutes",
            "recommendation": "Desactiver Telnet, utiliser SSH"
        }
    ],
    25: [
        {
            "service": "SMTP",
            "cve": "CVE-2020-7247",
            "description": "OpenSMTPD - Execution de commande a distance",
            "severity": "CRITIQUE",
            "version_affectee": "6.6.1",
            "recommendation": "Mettre a jour OpenSMTPD 6.8.0+"
        }
    ],
    53: [
        {
            "service": "DNS",
            "cve": "CVE-2020-1350",
            "description": "Windows DNS - Execution de commande a distance (SIGRed)",
            "severity": "CRITIQUE",
            "version_affectee": "Windows Server 2003-2019",
            "recommendation": "Appliquer le correctif Microsoft"
        }
    ],
    80: [
        {
            "service": "HTTP",
            "cve": "CVE-2021-41773",
            "description": "Apache 2.4.49 - Traversee de repertoire",
            "severity": "CRITIQUE",
            "version_affectee": "2.4.49",
            "recommendation": "Mettre a jour Apache 2.4.51+"
        },
        {
            "service": "HTTP",
            "cve": "CVE-2017-5638",
            "description": "Apache Struts 2 - Execution de commande a distance",
            "severity": "CRITIQUE",
            "version_affectee": "2.3.x-2.5.x",
            "recommendation": "Mettre a jour Apache Struts"
        }
    ],
    110: [
        {
            "service": "POP3",
            "cve": "CVE-2018-19536",
            "description": "POP3 - Transmission en clair des identifiants",
            "severity": "ELEVEE",
            "version_affectee": "Toutes",
            "recommendation": "Utiliser POP3S (port 995) avec TLS"
        }
    ],
    135: [
        {
            "service": "MSRPC",
            "cve": "CVE-2017-0144",
            "description": "Windows SMB/RPC - EternalBlue (WannaCry)",
            "severity": "CRITIQUE",
            "version_affectee": "Windows Vista-2016",
            "recommendation": "Appliquer MS17-010"
        }
    ],
    139: [
        {
            "service": "NetBIOS",
            "cve": "CVE-2017-0144",
            "description": "SMBv1 - EternalBlue",
            "severity": "CRITIQUE",
            "version_affectee": "SMBv1",
            "recommendation": "Desactiver SMBv1, appliquer MS17-010"
        }
    ],
    443: [
        {
            "service": "HTTPS",
            "cve": "CVE-2014-0160",
            "description": "OpenSSL - Heartbleed",
            "severity": "CRITIQUE",
            "version_affectee": "1.0.1-1.0.1f",
            "recommendation": "Mettre a jour OpenSSL 1.0.1g+"
        },
        {
            "service": "HTTPS",
            "cve": "CVE-2016-0800",
            "description": "OpenSSL - DROWN",
            "severity": "ELEVEE",
            "version_affectee": "SSLv2",
            "recommendation": "Desactiver SSLv2"
        }
    ],
    445: [
        {
            "service": "SMB",
            "cve": "CVE-2017-0144",
            "description": "SMBv1 - EternalBlue (WannaCry)",
            "severity": "CRITIQUE",
            "version_affectee": "Windows Vista-2016",
            "recommendation": "Appliquer MS17-010, desactiver SMBv1"
        },
        {
            "service": "SMB",
            "cve": "CVE-2020-0796",
            "description": "SMBv3 - SMBleed",
            "severity": "CRITIQUE",
            "version_affectee": "Windows 10/Server 2019",
            "recommendation": "Appliquer le correctif Microsoft"
        }
    ],
    1433: [
        {
            "service": "MSSQL",
            "cve": "CVE-2020-0618",
            "description": "SQL Server - Execution de code a distance",
            "severity": "ELEVEE",
            "version_affectee": "2012-2019",
            "recommendation": "Appliquer le correctif Microsoft"
        }
    ],
    3306: [
        {
            "service": "MySQL",
            "cve": "CVE-2021-2471",
            "description": "MySQL - Vulnarabilite d'execution de code",
            "severity": "ELEVEE",
            "version_affectee": "< 8.0.27",
            "recommendation": "Mettre a jour MySQL 8.0.27+"
        }
    ],
    3389: [
        {
            "service": "RDP",
            "cve": "CVE-2019-0708",
            "description": "RDP - BlueKeep",
            "severity": "CRITIQUE",
            "version_affectee": "Windows XP-7/Server 2008",
            "recommendation": "Appliquer le correctif, desactiver RDP si inutile"
        }
    ],
    5432: [
        {
            "service": "PostgreSQL",
            "cve": "CVE-2021-32027",
            "description": "PostgreSQL - Injection SQL via libpq",
            "severity": "ELEVEE",
            "version_affectee": "< 13.3",
            "recommendation": "Mettre a jour PostgreSQL 13.3+"
        }
    ],
    5900: [
        {
            "service": "VNC",
            "cve": "CVE-2019-15681",
            "description": "LibVNC - Contournement d'authentification",
            "severity": "CRITIQUE",
            "version_affectee": "< 0.9.12",
            "recommendation": "Mettre a jour LibVNC 0.9.12+"
        }
    ],
    6379: [
        {
            "service": "Redis",
            "cve": "CVE-2020-14155",
            "description": "Redis - Execution de commande non authentifiee",
            "severity": "CRITIQUE",
            "version_affectee": "< 6.0.4",
            "recommendation": "Activer l'authentification, mettre a jour 6.0.4+"
        }
    ],
    8080: [
        {
            "service": "HTTP-Proxy",
            "cve": "CVE-2019-0230",
            "description": "Apache Tomcat - Execution de commande via CGI",
            "severity": "ELEVEE",
            "version_affectee": "9.0.0-9.0.17",
            "recommendation": "Mettre a jour Apache Tomcat 9.0.18+"
        }
    ],
    27017: [
        {
            "service": "MongoDB",
            "cve": "CVE-2020-7699",
            "description": "MongoDB - Acces non authentifie par defaut",
            "severity": "CRITIQUE",
            "version_affectee": "Toutes (config par defaut)",
            "recommendation": "Activer l'authentification, restreindre l'acces reseau"
        }
    ]
}


def rechercher_vulnerabilites(port, banner=""):
    """
    Recherche les vulnerabilites connues pour un port et un service donnes.

    Args:
        port (int): Numero du port
        banner (str): Banniere du service recuperee

    Returns:
        list: Liste des vulnerabilites trouvees
    """
    vulns = []

    # Recherche par port
    if port in VULN_DATABASE:
        for vuln in VULN_DATABASE[port]:
            vuln_copy = vuln.copy()
            # Verification supplementaire avec la banniere si disponible
            if banner:
                vuln_copy["banner_match"] = vuln["version_affectee"].lower() in banner.lower()
            else:
                vuln_copy["banner_match"] = None
            vulns.append(vuln_copy)

    return vulns


def obtenir_stats_severite(vulns):
    """
    Calcule les statistiques de severite des vulnerabilites.

    Args:
        vulns (list): Liste des vulnerabilites

    Returns:
        dict: Statistiques par niveau de severite
    """
    stats = {"CRITIQUE": 0, "ELEVEE": 0, "MOYENNE": 0, "FAIBLE": 0}
    for vuln in vulns:
        sev = vuln.get("severity", "FAIBLE")
        if sev in stats:
            stats[sev] += 1
        else:
            stats["FAIBLE"] += 1
    return stats


def lister_services_connus():
    """
    Retourne la liste de tous les services suivis dans la base.

    Returns:
        dict: Dictionnaire port -> service
    """
    services = {}
    for port, vulns in VULN_DATABASE.items():
        if vulns:
            services[port] = vulns[0]["service"]
    return services
