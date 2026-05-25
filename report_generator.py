#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Générateur de rapports HTML pour NetVuln Scanner.
Auteur : Jamein N. Dietrich A.
"""

from datetime import datetime
from typing import Dict, List, Optional


def generate_html_report(
    target: str,
    scan_results: Dict[int, Dict],
    vulnerabilities: List[Dict],
    output_file: str,
    scan_date: Optional[datetime] = None
) -> None:
    """
    Génère un rapport HTML détaillé des résultats du scan.
    
    Args:
        target: Adresse IP de la cible
        scan_results: Résultats du scan de ports
        vulnerabilities: Liste des vulnérabilités détectées
        output_file: Chemin du fichier de sortie HTML
        scan_date: Date/heure du scan
    """
    if scan_date is None:
        scan_date = datetime.now()
    
    # Statistiques
    open_ports = len(scan_results)
    vuln_count = len(vulnerabilities)
    severity_stats = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for v in vulnerabilities:
        sev = v.get('severity', 'Low')
        severity_stats[sev] = severity_stats.get(sev, 0) + 1
    
    # Construction du HTML
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport NetVuln Scanner — {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
            text-align: center;
        }}
        .header h1 {{
            color: #38bdf8;
            font-size: 28px;
            margin-bottom: 10px;
        }}
        .header .subtitle {{
            color: #94a3b8;
            font-size: 14px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .summary-card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .summary-card .number {{
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .summary-card .label {{
            color: #94a3b8;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .critical {{ color: #ef4444; border-left: 4px solid #ef4444; }}
        .high {{ color: #f97316; border-left: 4px solid #f97316; }}
        .medium {{ color: #eab308; border-left: 4px solid #eab308; }}
        .low {{ color: #22c55e; border-left: 4px solid #22c55e; }}
        .section {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
        }}
        .section h2 {{
            color: #38bdf8;
            font-size: 20px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #334155;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            background: #0f172a;
            color: #38bdf8;
            padding: 12px 15px;
            text-align: left;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        td {{
            padding: 10px 15px;
            border-bottom: 1px solid #334155;
            font-size: 14px;
        }}
        tr:hover {{
            background: #334155;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: #7f1d1d; color: #fca5a5; }}
        .badge-high {{ background: #7c2d12; color: #fdba74; }}
        .badge-medium {{ background: #713f12; color: #fde047; }}
        .badge-low {{ background: #14532d; color: #86efac; }}
        .vuln-item {{
            background: #0f172a;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid;
        }}
        .vuln-item h4 {{
            margin-bottom: 5px;
        }}
        .vuln-item .description {{
            color: #94a3b8;
            font-size: 13px;
            margin-bottom: 8px;
        }}
        .vuln-item .recommendation {{
            color: #22c55e;
            font-size: 13px;
        }}
        .footer {{
            text-align: center;
            color: #64748b;
            font-size: 12px;
            padding: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Rapport NetVuln Scanner</h1>
            <div class="subtitle">
                Cible : <strong>{target}</strong> | 
                Date : <strong>{scan_date.strftime('%d/%m/%Y %H:%M:%S')}</strong>
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <div class="number" style="color: #38bdf8;">{open_ports}</div>
                <div class="label">Ports Ouverts</div>
            </div>
            <div class="summary-card">
                <div class="number" style="color: #ef4444;">{vuln_count}</div>
                <div class="label">Vulnérabilités</div>
            </div>
            <div class="summary-card">
                <div class="number" style="color: #ef4444;">{severity_stats['Critical']}</div>
                <div class="label">Critiques</div>
            </div>
            <div class="summary-card">
                <div class="number" style="color: #f97316;">{severity_stats['High']}</div>
                <div class="label">Élevées</div>
            </div>
            <div class="summary-card">
                <div class="number" style="color: #eab308;">{severity_stats['Medium']}</div>
                <div class="label">Moyennes</div>
            </div>
        </div>
        
        <!-- Table des ports ouverts -->
        <div class="section">
            <h2>📡 Ports Ouverts</h2>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>État</th>
                    </tr>
                </thead>
                <tbody>
"""
    
    # Remplissage de la table des ports
    for port in sorted(scan_results.keys()):
        info = scan_results[port]
        version = info.get('version', '—')
        if not version:
            version = '—'
        service = info.get('service', 'unknown')
        html += f"""                    <tr>
                        <td>{port}/tcp</td>
                        <td>{service}</td>
                        <td style="color: #94a3b8; font-size: 12px;">{version[:60]}</td>
                        <td><span class="badge badge-low">Open</span></td>
                    </tr>
"""
    
    html += """                </tbody>
            </table>
        </div>
"""
    
    # Section vulnérabilités
    if vulnerabilities:
        html += """        <div class="section">
            <h2>🛡️ Vulnérabilités Détectées</h2>
"""
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low').lower()
            badge_class = f"badge-{severity}"
            html += f"""            <div class="vuln-item {severity}">
                <h4>
                    <span class="badge {badge_class}">{vuln.get('severity', 'Low')}</span>
                    {vuln.get('cve_id', 'N/A')} — {vuln.get('title', 'Pas de titre')}
                </h4>
                <div class="description">
                    <strong>Port :</strong> {vuln.get('port', 'N/A')} | 
                    <strong>Service :</strong> {vuln.get('service', 'N/A')}<br>
                    {vuln.get('description', '')}
                </div>
                <div class="recommendation">
                    ✅ <strong>Recommandation :</strong> {vuln.get('recommendation', 'Consulter l\'avis CVE officiel.')}
                </div>
            </div>
"""
        html += """        </div>
"""
    
    # Pied de page
    html += f"""
        <div class="footer">
            Rapport généré par NetVuln Scanner v1.0 | {scan_date.strftime('%d/%m/%Y %H:%M:%S')}<br>
            <em>Ce rapport est généré à des fins éducatives uniquement.</em>
        </div>
    </div>
</body>
</html>
"""
    
    # Écriture du fichier
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"\n[✓] Rapport HTML généré : {output_file}")


# ============================================================
# TEST
# ============================================================
if __name__ == '__main__':
    # Test avec des données simulées
    test_results = {
        22: {'port': 22, 'state': 'open', 'service': 'SSH', 'banner': 'OpenSSH_8.9', 'version': 'OpenSSH_8.9'},
        80: {'port': 80, 'state': 'open', 'service': 'HTTP', 'banner': 'Apache/2.4.49', 'version': 'Apache/2.4.49'},
        445: {'port': 445, 'state': 'open', 'service': 'SMB', 'banner': '', 'version': ''},
        3306: {'port': 3306, 'state': 'open', 'service': 'MySQL', 'banner': 'MySQL 8.0.32', 'version': 'MySQL 8.0.32'},
    }
    
    test_vulns = [
        {
            'cve_id': 'CVE-2021-41773',
            'title': 'Apache Path Traversal',
            'severity': 'Critical',
            'port': 80,
            'service': 'HTTP',
            'description': 'Traversal de chemin critique.',
            'recommendation': 'Mise à jour Apache 2.4.51+.'
        },
        {
            'cve_id': 'CVE-2017-0144',
            'title': 'EternalBlue SMB RCE',
            'severity': 'Critical',
            'port': 445,
            'service': 'SMB',
            'description': 'Exécution de code à distance via SMBv1.',
            'recommendation': 'Désactiver SMBv1.'
        }
    ]
    
    generate_html_report('192.168.1.1', test_results, test_vulns, 'test_report.html')
