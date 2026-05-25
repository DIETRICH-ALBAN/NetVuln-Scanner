#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetVuln Scanner — Network Vulnerability Scanner
Auteur : Jamein N. Dietrich A.
Projet personnel de cybersécurité

AVERTISSEMENT : Cet outil est destiné UNIQUEMENT à des fins éducatives
et de tests sur des systèmes dont vous êtes propriétaire ou pour lesquels
vous avez une autorisation explicite. L'utilisation non autorisée est illégale.
"""

import socket
import argparse
import sys
import ipaddress
import threading
import struct
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

# Imports locaux
try:
    from vuln_db import VULNERABILITY_DB, lookup_vulnerabilities
    from report_generator import generate_html_report
except ImportError:
    print("[!] Modules locaux non trouvés. Exécutez depuis le répertoire du projet.")
    sys.exit(1)


# ============================================================
# COULEURS TERMINAL
# ============================================================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_banner():
    """Affiche la bannière du scanner."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
  ╔═══════════════════════════════════════════════════════╗
  ║           🔍 NetVuln Scanner v1.0                    ║
  ║     Network Vulnerability Scanner                    ║
  ║     by Jamein N. Dietrich A.                         ║
  ╚═══════════════════════════════════════════════════════╝
{Colors.END}"""
    print(banner)
    print(f"{Colors.YELLOW}[⚠]  Utilisation autorisée uniquement sur vos propres systèmes.{Colors.END}\n")


# ============================================================
# DÉCOUVERTE D'HÔTES (ARP Ping Sweep simulé)
# ============================================================
def discover_hosts(subnet: str, timeout: float = 1.0) -> List[str]:
    """
    Découvre les hôtes actifs sur un réseau local en utilisant
    des pings ICMP (simulation d'un ARP Ping Sweep).
    
    Args:
        subnet: Sous-réseau CIDR (ex: 192.168.1.0/24)
        timeout: Délai d'attente en secondes
    
    Returns:
        Liste des adresses IP actives
    """
    print(f"\n{Colors.BLUE}[*] Découverte d'hôtes sur {subnet}...{Colors.END}")
    active_hosts = []
    network = ipaddress.ip_network(subnet, strict=False)
    total = sum(1 for _ in network.hosts())
    
    def check_host(ip: str) -> Optional[str]:
        """Vérifie si un hôte est actif via ICMP ping."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(timeout)
            # Envoi d'un paquet ICMP Echo Request
            packet = _create_icmp_packet()
            sock.sendto(packet, (str(ip), 0))
            sock.close()
            return str(ip)
        except (socket.error, socket.timeout, PermissionError):
            # Fallback : tentative de connexion TCP sur le port 80
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_sock.settimeout(timeout)
                result = test_sock.connect_ex((str(ip), 80))
                test_sock.close()
                if result == 0:
                    return str(ip)
            except:
                pass
            return None
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_host, ip): ip for ip in network.hosts()}
        for i, future in enumerate(as_completed(futures)):
            result = future.result()
            if result:
                active_hosts.append(result)
                print(f"  {Colors.GREEN}[+] Hôte actif trouvé : {result}{Colors.END}")
            
            # Barre de progression
            progress = (i + 1) / total * 100
            sys.stdout.write(f"\r  Progression : {progress:.1f}% ({i+1}/{total})")
            sys.stdout.flush()
    
    print(f"\n\n{Colors.GREEN}[✓] {len(active_hosts)} hôte(s) actif(s) découvert(s).{Colors.END}")
    return sorted(active_hosts, key=lambda ip: ipaddress.ip_address(ip))


def _create_icmp_packet() -> bytes:
    """Crée un paquet ICMP Echo Request basique."""
    # Type 8 (Echo Request), Code 0
    icmp_type = 8
    icmp_code = 0
    checksum = 0
    identifier = 0x1234
    sequence = 1
    
    # En-tête ICMP
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, identifier, sequence)
    
    # Calcul du checksum
    checksum = _calculate_checksum(header)
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, identifier, sequence)
    
    return header


def _calculate_checksum(data: bytes) -> int:
    """Calcule le checksum ICMP."""
    if len(data) % 2:
        data += b'\x00'
    
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    
    return ~total & 0xFFFF


# ============================================================
# SCAN DE PORTS
# ============================================================
class PortScanner:
    """Scanner de ports TCP avec banner grabbing."""
    
    # Ports courants et leurs services associés
    COMMON_PORTS = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
        443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
        5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt', 27017: 'MongoDB'
    }
    
    def __init__(self, target: str, timeout: float = 1.0, threads: int = 100):
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.results: Dict[int, Dict] = {}
    
    def scan_port(self, port: int) -> Optional[Dict]:
        """
        Scanne un port TCP unique avec banner grabbing.
        
        Returns:
            Dict avec les infos du port ou None si fermé
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                info = {
                    'port': port,
                    'state': 'open',
                    'service': self.COMMON_PORTS.get(port, 'unknown'),
                    'banner': '',
                    'version': ''
                }
                
                # Banner Grabbing
                try:
                    if port in (80, 8080, 8443):
                        sock.send(b'HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n'.format(self.target.encode()))
                    elif port == 21:
                        pass  # Le banner FTP est envoyé automatiquement
                    elif port == 22:
                        pass  # Le banner SSH est envoyé automatiquement
                    elif port == 25:
                        pass  # Le banner SMTP est envoyé automatiquement
                    
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    info['banner'] = banner
                    info['version'] = self._extract_version(banner)
                except (socket.timeout, socket.error):
                    pass
                
                sock.close()
                return info
            else:
                sock.close()
                return None
                
        except (socket.error, socket.timeout):
            return None
    
    def scan_range(self, start: int, end: int) -> Dict[int, Dict]:
        """
        Scanne une plage de ports avec multithreading.
        
        Args:
            start: Port de début
            end: Port de fin
        
        Returns:
            Dictionnaire des ports ouverts avec leurs infos
        """
        total = end - start + 1
        print(f"\n{Colors.BLUE}[*] Scan des ports {start}-{end} sur {self.target}...{Colors.END}")
        print(f"    {Colors.CYAN}Threads : {self.threads} | Timeout : {self.timeout}s{Colors.END}\n")
        
        open_count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, port): port 
                      for port in range(start, end + 1)}
            
            for i, future in enumerate(as_completed(futures)):
                result = future.result()
                if result:
                    self.results[result['port']] = result
                    open_count += 1
                    service = result['service']
                    version = f" ({result['version']})" if result['version'] else ""
                    print(f"  {Colors.GREEN}[PORT OUVERT] {result['port']}/tcp "
                          f"— {service}{version}{Colors.END}")
                
                # Progression
                progress = (i + 1) / total * 100
                bar_length = 40
                filled = int(bar_length * progress / 100)
                bar = '█' * filled + '░' * (bar_length - filled)
                sys.stdout.write(f"\r  [{bar}] {progress:.1f}% | {open_count} port(s) ouvert(s)")
                sys.stdout.flush()
        
        print(f"\n\n{Colors.GREEN}[✓] Scan terminé : {open_count} port(s) ouvert(s) sur {total} scannés.{Colors.END}")
        return self.results
    
    def scan_common_ports(self) -> Dict[int, Dict]:
        """Scanne les ports les plus courants."""
        ports = sorted(self.COMMON_PORTS.keys())
        print(f"\n{Colors.BLUE}[*] Scan des ports courants sur {self.target}...{Colors.END}\n")
        
        open_count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in ports}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results[result['port']] = result
                    open_count += 1
                    service = result['service']
                    version = f" ({result['version']})" if result['version'] else ""
                    print(f"  {Colors.GREEN}[PORT OUVERT] {result['port']}/tcp "
                          f"— {service}{version}{Colors.END}")
        
        print(f"\n{Colors.GREEN}[✓] {open_count} port(s) ouvert(s) sur {len(ports)} courants scannés.{Colors.END}")
        return self.results
    
    @staticmethod
    def _extract_version(banner: str) -> str:
        """Extrait la version du service depuis le banner."""
        if not banner:
            return ''
        
        # Patterns courants de banner
        keywords = ['SSH', 'FTP', 'HTTP', 'SMTP', 'MySQL', 'PostgreSQL', 
                     'Apache', 'nginx', 'OpenSSH', 'vsftpd', 'ProFTPD',
                     'Microsoft', 'Server']
        
        for line in banner.split('\n'):
            for keyword in keywords:
                if keyword.lower() in line.lower():
                    return line.strip()[:80]  # Limiter la longueur
        
        return banner.split('\n')[0][:80] if banner else ''


# ============================================================
# ANALYSE DE VULNÉRABILITÉS
# ============================================================
def analyze_vulnerabilities(scan_results: Dict[int, Dict]) -> List[Dict]:
    """
    Analyse les résultats du scan pour détecter des vulnérabilités
    connues en se basant sur les services et versions détectés.
    
    Args:
        scan_results: Résultats du scan de ports
    
    Returns:
        Liste des vulnérabilités détectées
    """
    print(f"\n{Colors.YELLOW}[*] Analyse des vulnérabilités...{Colors.END}")
    
    vulnerabilities = []
    
    for port, info in scan_results.items():
        service = info.get('service', '')
        version = info.get('version', '')
        banner = info.get('banner', '')
        
        # Recherche dans la base de vulnérabilités
        vulns = lookup_vulnerabilities(port, service, version, banner)
        
        for vuln in vulns:
            vuln['port'] = port
            vuln['service'] = service
            vulnerabilities.append(vuln)
            
            severity = vuln.get('severity', 'Low')
            severity_color = {
                'Critical': Colors.RED,
                'High': Colors.RED,
                'Medium': Colors.YELLOW,
                'Low': Colors.CYAN
            }.get(severity, Colors.END)
            
            print(f"  {severity_color}[{severity.upper()}] {vuln.get('cve_id', 'N/A')} "
                  f"— Port {port} ({service}){Colors.END}")
            print(f"         → {vuln.get('title', 'Pas de titre')}")
    
    if not vulnerabilities:
        print(f"  {Colors.GREEN}[✓] Aucune vulnérabilité connue détectée.{Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}[!] {len(vulnerabilities)} vulnérabilité(s) potentielle(s) détectée(s).{Colors.END}")
    
    return vulnerabilities


# ============================================================
# FONCTION PRINCIPALE
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description='NetVuln Scanner — Network Vulnerability Scanner',
        epilog='Exemple : python scanner.py -t 192.168.1.1 --vuln-scan --report rapport.html'
    )
    
    parser.add_argument('-t', '--target', type=str, default='127.0.0.1',
                        help='Adresse IP de la cible (défaut: 127.0.0.1)')
    parser.add_argument('-p', '--ports', type=str, default='common',
                        help='Plage de ports (ex: 1-1024) ou "common" (défaut: common)')
    parser.add_argument('--timeout', type=float, default=1.0,
                        help='Timeout en secondes (défaut: 1.0)')
    parser.add_argument('--threads', type=int, default=100,
                        help='Nombre de threads (défaut: 100)')
    parser.add_argument('--discover', action='store_true',
                        help='Mode découverte d\'hôtes sur le réseau')
    parser.add_argument('-s', '--subnet', type=str, default='192.168.1.0/24',
                        help='Sous-réseau pour la découverte (défaut: 192.168.1.0/24)')
    parser.add_argument('--vuln-scan', action='store_true',
                        help='Activer l\'analyse de vulnérabilités')
    parser.add_argument('--report', type=str, default=None,
                        help='Générer un rapport HTML (ex: rapport.html)')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Avertissement légal
    print(f"{Colors.YELLOW}{'='*60}")
    print("  ⚠️  AVERTISSEMENT LÉGAL")
    print(f"{'='*60}")
    print("  Cet outil est destiné UNIQUEMENT à des fins éducatives")
    print("  et de tests sur vos propres systèmes. L'utilisation non")
    print("  autorisée contre des systèmes tiers est ILLÉGALE.")
    print(f"{'='*60}{Colors.END}\n")
    
    start_time = datetime.now()
    scan_results = {}
    vulnerabilities = []
    
    # Mode découverte d'hôtes
    if args.discover:
        hosts = discover_hosts(args.subnet, args.timeout)
        if hosts:
            print(f"\n{Colors.GREEN}Hôtes découverts :{Colors.END}")
            for host in hosts:
                print(f"  → {host}")
        else:
            print(f"\n{Colors.YELLOW}[!] Aucun hôte actif découvert.{Colors.END}")
        
        if not args.target or args.target == '127.0.0.1':
            return
    
    # Validation de la cible
    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        print(f"{Colors.RED}[!] Adresse IP invalide : {args.target}{Colors.END}")
        sys.exit(1)
    
    # Scan de ports
    scanner = PortScanner(args.target, args.timeout, args.threads)
    
    if args.ports == 'common':
        scan_results = scanner.scan_common_ports()
    else:
        try:
            start, end = map(int, args.ports.split('-'))
            scan_results = scanner.scan_range(start, end)
        except ValueError:
            print(f"{Colors.RED}[!] Format de plage invalide. Utilisez : début-fin (ex: 1-1024){Colors.END}")
            sys.exit(1)
    
    # Analyse de vulnérabilités
    if args.vuln_scan and scan_results:
        vulnerabilities = analyze_vulnerabilities(scan_results)
    
    # Génération du rapport
    if args.report and scan_results:
        generate_html_report(
            target=args.target,
            scan_results=scan_results,
            vulnerabilities=vulnerabilities,
            output_file=args.report,
            scan_date=start_time
        )
    
    # Résumé
    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"\n{Colors.CYAN}{'='*60}")
    print(f"  📊 RÉSUMÉ DU SCAN")
    print(f"{'='*60}")
    print(f"  Cible         : {args.target}")
    print(f"  Ports ouverts : {len(scan_results)}")
    print(f"  Vulnérabilités: {len(vulnerabilities)}")
    print(f"  Durée         : {elapsed:.2f}s")
    if args.report:
        print(f"  Rapport       : {args.report}")
    print(f"{'='*60}{Colors.END}")


if __name__ == '__main__':
    main()
