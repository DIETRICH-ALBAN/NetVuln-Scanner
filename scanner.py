#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetVuln Scanner - Scanner de vulnerabilites reseau
Auteur : Jamein N. Dietrich A.

Outil educatif de scan de vulnerabilites reseau incluant :
- Decouverte d'hotes (simulation ARP ping sweep)
- Scan de ports TCP avec recuperation de bannieres
- Correlation CVE avec base de donnees locale
- Generation de rapports HTML
"""

import argparse
import socket
import struct
import random
import sys
import os
import time
from datetime import datetime

from vuln_db import rechercher_vulnerabilites, lister_services_connus
from report_generator import generer_rapport_html


BANNER = """
============================================
   NetVuln Scanner v1.0
   Scanner de vulnerabilites reseau
   Auteur : Jamein N. Dietrich A.
============================================
"""

AVERTISSEMENT = """
/!\\ AVERTISSEMENT ETHIQUE /!\\
Cet outil est destine UNIQUEMENT a un usage educatif et autorise.
Scanner un reseau sans autorisation est ILLEGAL.
Vous devez avoir une autorisation ecrite avant de scanner.
En utilisant cet outil, vous acceptez l'entiere responsabilite de vos actes.
"""


def afficher_avertissement():
    """Affiche l'avertissement ethique au demarrage."""
    print(AVERTISSEMENT)
    try:
        choix = input("Acceptez-vous les conditions ? (oui/non) : ").strip().lower()
        if choix not in ("oui", "o", "yes", "y"):
            print("Scan annule. Confirmation requise.")
            sys.exit(0)
    except (EOFError, KeyboardInterrupt):
        print("\nScan annule.")
        sys.exit(0)
    print()


def simuler_decouverte_hotes(reseau, masque=24):
    """
    Simule la decouverte d'hotes sur un reseau par ARP ping sweep.
    En mode educatif, genere des resultats simules.

    Args:
        reseau (str): Adresse reseau (ex: 192.168.1.0)
        masque (int): Masque de sous-reseau

    Returns:
        list: Liste des adresses IP detectees
    """
    print(f"[*] Decouverte d'hotes sur {reseau}/{masque}...")
    print("[*] Methode : ARP ping sweep (simulation)")

    # Extraction du prefixe reseau
    parties = reseau.split(".")
    if len(parties) != 4:
        print("[!] Adresse reseau invalide.")
        return []

    prefixe = ".".join(parties[:3])

    # Simulation : on genere entre 3 et 8 hotes
    random.seed(hash(reseau))
    nb_hotes = random.randint(3, 8)
    hotes_detectes = []

    for _ in range(nb_hotes):
        dernier_octet = random.randint(2, 254)
        ip = f"{prefixe}.{dernier_octet}"
        if ip != reseau:
            hotes_detectes.append(ip)

    hotes_detectes = sorted(set(hotes_detectes), key=lambda x: int(x.split(".")[-1]))

    for ip in hotes_detectes:
        print(f"    [+] Hote detecte : {ip}")

    print(f"[*] {len(hotes_detectes)} hotes detectes.")
    return hotes_detectes


def scanner_port(ip, port, timeout=2):
    """
    Tente une connexion TCP sur un port pour determiner s'il est ouvert.
    Recupere egalement la banniere du service si possible.

    Args:
        ip (str): Adresse IP de l'hote
        port (int): Numero du port
        timeout (float): Delai d'attente en secondes

    Returns:
        tuple: (ouvert: bool, banniere: str)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        resultat = sock.connect_ex((ip, port))

        if resultat == 0:
            # Port ouvert - tentative de recuperation de banniere
            banniere = ""
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n")
                banniere = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            except (socket.timeout, socket.error):
                pass
            sock.close()
            return True, banniere
        else:
            sock.close()
            return False, ""
    except socket.error:
        return False, ""
    except Exception:
        return False, ""


def simuler_scan_ports(ip, ports_communs=None):
    """
    Simule un scan de ports avec bannieres pour un hote.
    Utilise des resultats simules en mode educatif.

    Args:
        ip (str): Adresse IP de l'hote
        ports_communs (list): Liste des ports a scanner

    Returns:
        list: Liste des ports ouverts avec bannieres
    """
    if ports_communs is None:
        ports_communs = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 443,
            445, 993, 995, 1433, 3306, 3389, 5432,
            5900, 6379, 8080, 8443, 27017
        ]

    print(f"[*] Scan des ports sur {ip}...")

    # Simulation pour le mode educatif
    random.seed(hash(ip) + 42)
    ports_ouverts = []

    # Generer quelques ports ouverts aleatoires
    nb_ports = random.randint(2, 6)
    ports_selectionnes = random.sample(ports_communs, min(nb_ports, len(ports_communs)))

    bannieres_simulees = {
        21: "220 vsftpd 2.3.4",
        22: "SSH-2.0-OpenSSH_7.4",
        23: "Login:",
        25: "220 mail ESMTP Postfix",
        53: "DNS",
        80: "Apache/2.4.49",
        110: "+OK POP3 server ready",
        135: "Windows RPC",
        139: "NetBIOS Session Service",
        443: "Apache/2.4.49 (SSL)",
        445: "Windows SMB",
        3306: "mysql Ver 14.14 Distrib 5.7.33",
        3389: "Microsoft RDP",
        5432: "PostgreSQL 12.2",
        5900: "RFB 003.008",
        6379: "Redis v5.0.7",
        8080: "Apache Tomcat/9.0.17",
        27017: "MongoDB 4.2.8",
    }

    for port in sorted(ports_selectionnes):
        banniere = bannieres_simulees.get(port, "Service inconnu")
        ports_ouverts.append({
            "port": port,
            "banner": banniere,
            "service": identifier_service(port, banniere)
        })
        print(f"    [+] Port {port}/tcp OUVERT - {banniere}")

    return ports_ouverts


def identifier_service(port, banniere=""):
    """
    Identifie le service en fonction du port et de la banniere.

    Args:
        port (int): Numero du port
        banniere (str): Banniere recuperee

    Returns:
        str: Nom du service identifie
    """
    services_connus = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 135: "MSRPC",
        139: "NetBIOS", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
        8443: "HTTPS-Alt", 27017: "MongoDB"
    }

    if port in services_connus:
        return services_connus[port]

    # Tentative d'identification via la banniere
    banniere_lower = banniere.lower()
    if "ssh" in banniere_lower:
        return "SSH"
    elif "http" in banniere_lower or "apache" in banniere_lower:
        return "HTTP"
    elif "ftp" in banniere_lower:
        return "FTP"
    elif "smtp" in banniere_lower or "postfix" in banniere_lower:
        return "SMTP"

    return "Inconnu"


def analyser_hote(ip, scan_reel=False):
    """
    Analyse un hote : decouverte des ports et correlation CVE.

    Args:
        ip (str): Adresse IP de l'hote
        scan_reel (bool): Si True, effectue un scan reel (sinon simulation)

    Returns:
        dict: Resultats de l'analyse
    """
    print(f"\n{'='*50}")
    print(f"Analyse de l'hote : {ip}")
    print(f"{'='*50}")

    resultat_hote = {
        "ip": ip,
        "actif": True,
        "ports": []
    }

    if scan_reel:
        # Scan reel des ports communs
        ports_communs = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 443,
            445, 993, 995, 1433, 3306, 3389, 5432,
            5900, 6379, 8080, 8443, 27017
        ]
        for port in ports_communs:
            ouvert, banniere = scanner_port(ip, port, timeout=1)
            if ouvert:
                service = identifier_service(port, banniere)
                vulns = rechercher_vulnerabilites(port, banniere)
                resultat_hote["ports"].append({
                    "port": port,
                    "banner": banniere,
                    "service": service,
                    "vulnerabilites": vulns
                })
    else:
        # Scan simule
        ports_ouverts = simuler_scan_ports(ip)
        for port_info in ports_ouverts:
            vulns = rechercher_vulnerabilites(port_info["port"], port_info["banner"])
            port_info["vulnerabilites"] = vulns
            resultat_hote["ports"].append(port_info)

    # Affichage des vulnerabilites
    total_vulns = 0
    for port_info in resultat_hote["ports"]:
        for vuln in port_info.get("vulnerabilites", []):
            total_vulns += 1
            severity = vuln.get("severity", "FAIBLE")
            print(f"    [!] {vuln['cve']} [{severity}] - {vuln['description']}")

    print(f"\n[*] Total : {len(resultat_hote['ports'])} ports ouverts, {total_vulns} vulnerabilites")

    return resultat_hote


def lancer_scan(reseau, masque=24, scan_reel=False, fichier_rapport=None):
    """
    Lance un scan complet du reseau.

    Args:
        reseau (str): Adresse reseau a scanner
        masque (int): Masque de sous-reseau
        scan_reel (bool): Mode de scan
        fichier_rapport (str): Chemin du rapport HTML

    Returns:
        dict: Resultats complets du scan
    """
    print(BANNER)
    afficher_avertissement()

    print(f"[*] Cible : {reseau}/{masque}")
    print(f"[*] Mode : {'Reel' if scan_reel else 'Simulation educative'}")
    print(f"[*] Date : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print()

    # Decouverte des hotes
    hotes = simuler_decouverte_hotes(reseau, masque)

    if not hotes:
        print("[!] Aucun hote detecte.")
        return {"reseau": reseau, "masque": masque, "hotes": []}

    # Analyse de chaque hote
    resultats = {
        "reseau": f"{reseau}/{masque}",
        "masque": masque,
        "hotes": []
    }

    for ip in hotes:
        resultat_hote = analyser_hote(ip, scan_reel)
        resultats["hotes"].append(resultat_hote)

    # Resume global
    print(f"\n{'='*50}")
    print("RESUME DU SCAN")
    print(f"{'='*50}")
    print(f"[*] Reseau scanne : {reseau}/{masque}")
    print(f"[*] Hotes detectes : {len(hotes)}")

    total_ports = 0
    total_vulns = 0
    for hote in resultats["hotes"]:
        nb_ports = len(hote.get("ports", []))
        total_ports += nb_ports
        for port_info in hote.get("ports", []):
            total_vulns += len(port_info.get("vulnerabilites", []))

    print(f"[*] Ports ouverts totaux : {total_ports}")
    print(f"[*] Vulnerabilites totales : {total_vulns}")

    # Generation du rapport HTML
    if fichier_rapport is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        fichier_rapport = f"rapport_netvuln_{timestamp}.html"

    chemin_rapport = generer_rapport_html(resultats, fichier_rapport)
    print(f"\n[*] Rapport HTML genere : {chemin_rapport}")

    return resultats


def afficher_services():
    """Affiche la liste des services suivis dans la base de donnees."""
    services = lister_services_connus()
    print("\nServices suivis dans la base de donnees :")
    print(f"{'Port':<10} {'Service':<15}")
    print("-" * 25)
    for port, service in sorted(services.items()):
        print(f"{port:<10} {service:<15}")
    print(f"\nTotal : {len(services)} services")


def main():
    """Point d'entree principal du programme."""
    parser = argparse.ArgumentParser(
        description="NetVuln Scanner - Scanner de vulnerabilites reseau (educatif)",
        epilog="Auteur : Jamein N. Dietrich A. | Usage educatif uniquement"
    )

    parser.add_argument(
        "-t", "--target",
        type=str,
        default="192.168.1.0",
        help="Adresse reseau a scanner (defaut : 192.168.1.0)"
    )

    parser.add_argument(
        "-m", "--mask",
        type=int,
        default=24,
        help="Masque de sous-reseau (defaut : 24)"
    )

    parser.add_argument(
        "-r", "--real",
        action="store_true",
        help="Effectuer un scan reel (sinon mode simulation)"
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Fichier de sortie pour le rapport HTML"
    )

    parser.add_argument(
        "-s", "--services",
        action="store_true",
        help="Afficher les services suivis dans la base de donnees"
    )

    parser.add_argument(
        "--no-warn",
        action="store_true",
        help="Desactiver l'avertissement ethique (pour scripts)"
    )

    args = parser.parse_args()

    if args.services:
        afficher_services()
        return

    if args.no_warn:
        # Contourner l'avertissement pour l'utilisation en script
        global afficher_avertissement
        original = afficher_avertissement
        afficher_avertissement = lambda: None

    lancer_scan(
        reseau=args.target,
        masque=args.mask,
        scan_reel=args.real,
        fichier_rapport=args.output
    )


if __name__ == "__main__":
    main()
