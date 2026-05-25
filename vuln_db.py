#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Base de données de vulnérabilités locale pour NetVuln Scanner.
Contient les signatures CVE courantes pour la détection de vulnérabilités.
Auteur : Jamein N. Dietrich A.
"""

from typing import List, Dict, Optional


# ============================================================
# BASE DE DONNÉES DE VULNÉRABILITÉS
# ============================================================
VULNERABILITY_DB = [
    # ---- SSH ----
    {
        'cve_id': 'CVE-2023-38408',
        'title': 'OpenSSH ProxyJump Forwarding Vulnerability',
        'severity': 'High',
        'affected_service': 'SSH',
        'affected_port': 22,
        'version_pattern': ['OpenSSH_8', 'OpenSSH_9.0', 'OpenSSH_9.1', 'OpenSSH_9.2', 'OpenSSH_9.3'],
        'description': 'Vulnérabilité dans le agent forwarding d\'OpenSSH permettant une exécution de code à distance via un serveur SSH compromis.',
        'recommendation': 'Mettre à jour OpenSSH vers la version 9.4+ ou désactiver le ProxyJump.'
    },
    {
        'cve_id': 'CVE-2020-15778',
        'title': 'OpenSSH SCP Command Injection',
        'severity': 'High',
        'affected_service': 'SSH',
        'affected_port': 22,
        'version_pattern': ['OpenSSH_8', 'OpenSSH_7'],
        'description': 'Injection de commande possible via le client SCP dans OpenSSH. Un attaquant peut exécuter des commandes arbitraires sur le serveur.',
        'recommendation': 'Utiliser SFTP au lieu de SCP ou mettre à jour OpenSSH.'
    },
    
    # ---- FTP ----
    {
        'cve_id': 'CVE-2021-36356',
        'title': 'ProFTPD mod_copy Command Execution',
        'severity': 'Critical',
        'affected_service': 'FTP',
        'affected_port': 21,
        'version_pattern': ['ProFTPD'],
        'description': 'Le module mod_copy de ProFTPD permet la copie de fichiers sans authentification, pouvant mener à une exécution de code à distance.',
        'recommendation': 'Désactiver mod_copy ou migrer vers vsftpd.'
    },
    {
        'cve_id': 'CVE-2022-27201',
        'title': 'vsftpd Denial of Service',
        'severity': 'Medium',
        'affected_service': 'FTP',
        'affected_port': 21,
        'version_pattern': ['vsftpd 2', 'vsftpd 3.0'],
        'description': 'Vulnérabilité de déni de service dans vsftpd via des commandes FTP malformées.',
        'recommendation': 'Mettre à jour vsftpd vers la dernière version.'
    },
    
    # ---- HTTP / Apache ----
    {
        'cve_id': 'CVE-2021-41773',
        'title': 'Apache HTTP Server Path Traversal',
        'severity': 'Critical',
        'affected_service': 'HTTP',
        'affected_port': [80, 8080],
        'version_pattern': ['Apache/2.4.49', 'Apache/2.4.50'],
        'description': 'Vulnérabilité de traversal de chemin dans Apache 2.4.49-50 permettant l\'accès à des fichiers en dehors du répertoire racine.',
        'recommendation': 'Mettre à jour Apache vers 2.4.51+.'
    },
    {
        'cve_id': 'CVE-2023-25690',
        'title': 'Apache HTTP Server HTTP Request Smuggling',
        'severity': 'High',
        'affected_service': 'HTTP',
        'affected_port': [80, 8080],
        'version_pattern': ['Apache/2.4.55', 'Apache/2.4.56'],
        'description': 'Vulnérabilité de contrebande de requêtes HTTP dans le module mod_proxy d\'Apache.',
        'recommendation': 'Mettre à jour Apache vers 2.4.57+.'
    },
    
    # ---- HTTP / nginx ----
    {
        'cve_id': 'CVE-2022-41741',
        'title': 'nginx MP4 Module Heap Buffer Overflow',
        'severity': 'Medium',
        'affected_service': 'HTTP',
        'affected_port': [80, 443],
        'version_pattern': ['nginx/1.23.1', 'nginx/1.23.2'],
        'description': 'Débordement de tampon dans le module MP4 de nginx pouvant causer un déni de service.',
        'recommendation': 'Mettre à jour nginx vers 1.23.3+ ou désactiver le module MP4.'
    },
    
    # ---- SMB ----
    {
        'cve_id': 'CVE-2017-0144',
        'title': 'EternalBlue — SMB Remote Code Execution',
        'severity': 'Critical',
        'affected_service': 'SMB',
        'affected_port': 445,
        'version_pattern': ['SMB', 'Windows Server 2008', 'Windows 7', 'Windows 8'],
        'description': 'Vulnérabilité critique dans SMBv1 permettant l\'exécution de code à distance (exploit EternalBlue utilisé par WannaCry).',
        'recommendation': 'Désactiver SMBv1, appliquer les correctifs MS17-010, utiliser SMBv3.'
    },
    {
        'cve_id': 'CVE-2020-0796',
        'title': 'SMBv3 Compression Remote Code Execution (SMBleed)',
        'severity': 'Critical',
        'affected_service': 'SMB',
        'affected_port': 445,
        'version_pattern': ['SMB', 'Windows 10', 'Windows Server 2019'],
        'description': 'Vulnérabilité dans la compression SMBv3 permettant l\'exécution de code à distance.',
        'recommendation': 'Désactiver la compression SMB, appliquer les correctifs Microsoft.'
    },
    
    # ---- RDP ----
    {
        'cve_id': 'CVE-2019-0708',
        'title': 'BlueKeep — RDP Remote Code Execution',
        'severity': 'Critical',
        'affected_service': 'RDP',
        'affected_port': 3389,
        'version_pattern': ['Microsoft', 'RDP', 'Terminal Services'],
        'description': 'Vulnérabilité de code à distance dans RDP sans authentification (BlueKeep). Affecte Windows XP, 7, Server 2003/2008.',
        'recommendation': 'Activer NLA, désactiver RDP si inutile, appliquer les correctifs.'
    },
    
    # ---- MySQL ----
    {
        'cve_id': 'CVE-2023-21980',
        'title': 'MySQL Server Authentication Bypass',
        'severity': 'High',
        'affected_service': 'MySQL',
        'affected_port': 3306,
        'version_pattern': ['MySQL 8.0', 'MySQL 5.7'],
        'description': 'Vulnérabilité d\'authentification dans MySQL Server permettant un accès non autorisé.',
        'recommendation': 'Mettre à jour MySQL vers la dernière version corrective.'
    },
    
    # ---- Redis ----
    {
        'cve_id': 'CVE-2022-0543',
        'title': 'Redis Lua Sandbox Escape',
        'severity': 'High',
        'affected_service': 'Redis',
        'affected_port': 6379,
        'version_pattern': ['Redis'],
        'description': 'Évasion du bac à sable Lua dans Redis permettant l\'exécution de code arbitraire.',
        'recommendation': 'Mettre à jour Redis, désactiver EVAL si non nécessaire.'
    },
    {
        'cve_id': 'REDIS-UNAUTH',
        'title': 'Redis Instance sans authentification',
        'severity': 'Critical',
        'affected_service': 'Redis',
        'affected_port': 6379,
        'version_pattern': ['Redis'],
        'description': 'Instance Redis accessible sans mot de passe. Un attaquant peut lire/écrire des données, exécuter des commandes.',
        'recommendation': 'Configurer un mot de passe Redis (requirepass), restreindre l\'accès réseau.'
    },
    
    # ---- VNC ----
    {
        'cve_id': 'VNC-NOAUTH',
        'title': 'VNC sans authentification configurée',
        'severity': 'High',
        'affected_service': 'VNC',
        'affected_port': 5900,
        'version_pattern': ['VNC', 'RFB'],
        'description': 'Service VNC détecté sans authentification. Accès distant complet possible.',
        'recommendation': 'Configurer un mot de passe VNC, utiliser un tunnel SSH.'
    },
    
    # ---- Telnet ----
    {
        'cve_id': 'TELNET-INSECURE',
        'title': 'Telnet — Protocole non chiffré',
        'severity': 'High',
        'affected_service': 'Telnet',
        'affected_port': 23,
        'version_pattern': ['Telnet', 'BusyBox'],
        'description': 'Le protocole Telnet transmet les identifiants en clair. Vulnérable aux attaques de type sniffing/MitM.',
        'recommendation': 'Désactiver Telnet et utiliser SSH à la place.'
    },
    
    # ---- MongoDB ----
    {
        'cve_id': 'MONGO-UNAUTH',
        'title': 'MongoDB sans authentification',
        'severity': 'Critical',
        'affected_service': 'MongoDB',
        'affected_port': 27017,
        'version_pattern': ['MongoDB'],
        'description': 'Instance MongoDB accessible sans authentification. Risque de fuite de données complète.',
        'recommendation': 'Activer l\'authentification MongoDB, restreindre l\'accès réseau.'
    },
]


# ============================================================
# FONCTIONS DE RECHERCHE
# ============================================================
def lookup_vulnerabilities(port: int, service: str, version: str = '', banner: str = '') -> List[Dict]:
    """
    Recherche les vulnérabilités correspondant à un service détecté.
    
    Args:
        port: Numéro de port
        service: Nom du service détecté
        version: Version du service extraite du banner
        banner: Banner complet du service
    
    Returns:
        Liste des vulnérabilités correspondantes
    """
    matches = []
    
    for vuln in VULNERABILITY_DB:
        # Vérification du port
        affected_ports = vuln.get('affected_port', [])
        if isinstance(affected_ports, int):
            affected_ports = [affected_ports]
        
        port_match = port in affected_ports if affected_ports else False
        
        # Vérification du service
        service_match = vuln.get('affected_service', '').lower() == service.lower()
        
        # Vérification de la version (si des patterns sont définis)
        version_match = False
        version_patterns = vuln.get('version_pattern', [])
        
        if not version_patterns:
            # Pas de pattern de version = correspondance par service/port uniquement
            version_match = True
        else:
            search_text = f"{version} {banner}".lower()
            for pattern in version_patterns:
                if pattern.lower() in search_text:
                    version_match = True
                    break
        
        # Le port ou le service doit correspondre, et la version si spécifiée
        if (port_match or service_match) and version_match:
            matches.append(vuln.copy())
    
    return matches


def get_vuln_stats(vulnerabilities: List[Dict]) -> Dict[str, int]:
    """
    Calcule les statistiques de sévérité des vulnérabilités.
    
    Args:
        vulnerabilities: Liste des vulnérabilités détectées
    
    Returns:
        Dictionnaire des comptes par sévérité
    """
    stats = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'Info')
        stats[severity] = stats.get(severity, 0) + 1
    return stats


def get_all_services() -> List[str]:
    """Retourne la liste de tous les services dans la base."""
    return list(set(v['affected_service'] for v in VULNERABILITY_DB))


def get_all_cves() -> List[str]:
    """Retourne la liste de tous les identifiants CVE dans la base."""
    return [v['cve_id'] for v in VULNERABILITY_DB if v['cve_id'].startswith('CVE-')]


# ============================================================
# TESTS UNITAIRES
# ============================================================
if __name__ == '__main__':
    print("=== Test de la base de vulnérabilités ===\n")
    
    # Test de recherche par port
    print("1. Recherche par port 445 (SMB) :")
    results = lookup_vulnerabilities(445, 'SMB')
    for r in results:
        print(f"   [{r['severity']}] {r['cve_id']} — {r['title']}")
    
    # Test de recherche par version
    print("\n2. Recherche par version Apache/2.4.49 :")
    results = lookup_vulnerabilities(80, 'HTTP', version='Apache/2.4.49')
    for r in results:
        print(f"   [{r['severity']}] {r['cve_id']} — {r['title']}")
    
    # Statistiques
    print(f"\n3. Statistiques de la base :")
    all_stats = get_vuln_stats(VULNERABILITY_DB)
    for severity, count in all_stats.items():
        print(f"   {severity}: {count}")
    
    print(f"\n4. Services couverts : {', '.join(get_all_services())}")
    print(f"5. Nombre de CVE : {len(get_all_cves())}")
