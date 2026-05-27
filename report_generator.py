#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generateur de rapports HTML pour NetVuln Scanner
Auteur : Jamein N. Dietrich A.
"""

import os
from datetime import datetime
from vuln_db import obtenir_stats_severite


def generer_rapport_html(resultats, fichier_sortie="rapport_vuln.html"):
    """
    Genere un rapport HTML detaille des resultats du scan.

    Args:
        resultats (dict): Resultats du scan
        fichier_sortie (str): Chemin du fichier HTML a generer

    Returns:
        str: Chemin du fichier genere
    """
    date_str = datetime.now().strftime("%d/%m/%Y a %H:%M:%S")

    # Comptage total des vulnerabilites
    total_vulns = 0
    for hote in resultats.get("hotes", []):
        for port_info in hote.get("ports", []):
            total_vulns += len(port_info.get("vulnerabilites", []))

    # Calcul des stats globales
    toutes_vulns = []
    for hote in resultats.get("hotes", []):
        for port_info in hote.get("ports", []):
            toutes_vulns.extend(port_info.get("vulnerabilites", []))
    stats = obtenir_stats_severite(toutes_vulns)

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport NetVuln Scanner</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        header {{
            background: linear-gradient(135deg, #1a1f2e 0%, #2d333b 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            border: 1px solid #30363d;
        }}
        header h1 {{
            color: #58a6ff;
            font-size: 2em;
            margin-bottom: 10px;
        }}
        header p {{
            color: #8b949e;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: #161b22;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #30363d;
            text-align: center;
        }}
        .stat-card h3 {{
            font-size: 0.9em;
            color: #8b949e;
            margin-bottom: 10px;
        }}
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        .critique {{ color: #f85149; }}
        .elevee {{ color: #d29922; }}
        .moyenne {{ color: #58a6ff; }}
        .faible {{ color: #3fb950; }}
        .info {{ color: #8b949e; }}
        .host-section {{
            background: #161b22;
            border-radius: 8px;
            border: 1px solid #30363d;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .host-header {{
            background: #1c2128;
            padding: 15px 20px;
            border-bottom: 1px solid #30363d;
        }}
        .host-header h2 {{
            color: #58a6ff;
        }}
        .port-item {{
            padding: 15px 20px;
            border-bottom: 1px solid #21262d;
        }}
        .port-item:last-child {{
            border-bottom: none;
        }}
        .port-info {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .port-number {{
            color: #79c0ff;
            font-weight: bold;
            font-size: 1.1em;
        }}
        .service-name {{
            color: #d2a8ff;
            font-weight: bold;
        }}
        .severity-badge {{
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .badge-critique {{ background: #3d1a1a; color: #f85149; border: 1px solid #f85149; }}
        .badge-elevee {{ background: #3d2e00; color: #d29922; border: 1px solid #d29922; }}
        .badge-moyenne {{ background: #1a2d3d; color: #58a6ff; border: 1px solid #58a6ff; }}
        .badge-faible {{ background: #1a3d1a; color: #3fb950; border: 1px solid #3fb950; }}
        .vuln-card {{
            background: #0d1117;
            padding: 12px;
            border-radius: 6px;
            margin-top: 8px;
            border-left: 3px solid;
        }}
        .vuln-critique {{ border-left-color: #f85149; }}
        .vuln-elevee {{ border-left-color: #d29922; }}
        .vuln-moyenne {{ border-left-color: #58a6ff; }}
        .vuln-faible {{ border-left-color: #3fb950; }}
        .vuln-cve {{
            color: #79c0ff;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .vuln-desc {{
            color: #c9d1d9;
            margin-bottom: 8px;
        }}
        .vuln-reco {{
            color: #3fb950;
            font-size: 0.9em;
        }}
        .banner {{
            color: #8b949e;
            font-style: italic;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        footer {{
            text-align: center;
            padding: 20px;
            color: #484f58;
            font-size: 0.85em;
            margin-top: 30px;
            border-top: 1px solid #21262d;
        }}
        .warning-box {{
            background: #3d2e00;
            border: 1px solid #d29922;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            color: #d29922;
        }}
        .no-vuln {{
            color: #3fb950;
            padding: 10px;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Rapport NetVuln Scanner</h1>
            <p>Date du scan : {date_str}</p>
            <p>Reseau scanne : {resultats.get('reseau', 'Non specifie')}</p>
            <p>Auteur : Jamein N. Dietrich A.</p>
        </header>

        <div class="warning-box">
            <strong>AVERTISSEMENT :</strong> Ce rapport a ete genere dans un cadre educatif.
            L'utilisation de cet outil sur des reseaux sans autorisation est illegale.
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Hotes detectes</h3>
                <div class="number info">{len(resultats.get('hotes', []))}</div>
            </div>
            <div class="stat-card">
                <h3>Vulnerabilites totales</h3>
                <div class="number info">{total_vulns}</div>
            </div>
            <div class="stat-card">
                <h3>Critique</h3>
                <div class="number critique">{stats.get('CRITIQUE', 0)}</div>
            </div>
            <div class="stat-card">
                <h3>Elevee</h3>
                <div class="number elevee">{stats.get('ELEVEE', 0)}</div>
            </div>
            <div class="stat-card">
                <h3>Moyenne</h3>
                <div class="number moyenne">{stats.get('MOYENNE', 0)}</div>
            </div>
            <div class="stat-card">
                <h3>Faible</h3>
                <div class="number faible">{stats.get('FAIBLE', 0)}</div>
            </div>
        </div>
"""

    # Section pour chaque hote
    for hote in resultats.get("hotes", []):
        html += f"""
        <div class="host-section">
            <div class="host-header">
                <h2>Hote : {hote.get('ip', 'Inconnu')}</h2>
                <p>Statut : {'Actif' if hote.get('actif') else 'Inactif'} |
                   Ports ouverts : {len(hote.get('ports', []))}</p>
            </div>
"""
        if not hote.get("ports", []):
            html += """            <div class="no-vuln">Aucun port ouvert detecte.</div>
"""
        for port_info in hote.get("ports", []):
            port = port_info.get("port", "?")
            service = port_info.get("service", "Inconnu")
            banner = port_info.get("banner", "")
            vulns = port_info.get("vulnerabilites", [])

            html += f"""
            <div class="port-item">
                <div class="port-info">
                    <span class="port-number">Port {port}</span>
                    <span class="service-name">{service}</span>
                </div>
"""
            if banner:
                html += f"""                <div class="banner">Banniere : {banner}</div>
"""

            if not vulns:
                html += """                <div class="no-vuln">Aucune vulnerabilite connue dans la base.</div>
"""
            for vuln in vulns:
                severity = vuln.get("severity", "FAIBLE")
                badge_class = severity.lower()
                html += f"""
                <div class="vuln-card vuln-{badge_class}">
                    <div class="vuln-cve">{vuln.get('cve', 'N/A')} - {vuln.get('service', '')}</div>
                    <div class="vuln-desc">{vuln.get('description', '')}</div>
                    <span class="severity-badge badge-{badge_class}">{severity}</span>
                    <div class="vuln-reco">Recommandation : {vuln.get('recommendation', 'Aucune')}</div>
                </div>
"""
            html += """            </div>
"""

        html += """        </div>
"""

    html += f"""
        <footer>
            <p>NetVuln Scanner - Rapport genere le {date_str}</p>
            <p>Auteur : Jamein N. Dietrich A. | Projet educatif en cyberscurite</p>
            <p>L'utilisation non autorisee de cet outil est strictement interdite.</p>
        </footer>
    </div>
</body>
</html>
"""

    with open(fichier_sortie, "w", encoding="utf-8") as f:
        f.write(html)

    return fichier_sortie
