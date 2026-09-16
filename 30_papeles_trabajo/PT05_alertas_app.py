"""Exporta alertas reales ZAP; el mapeo se completa y valida manualmente.
Uso: python PT05_alertas_app.py ruta/zap_full_juiceshop.json ruta/salida.csv
No necesita pandas. No fabrica alertas si faltan los reportes.
"""
import argparse
import csv
import json
from collections import Counter
from pathlib import Path

MAPPING = {
    'CORS Misconfiguration': ('WSTG-CLNT-07', 'A05 Security Misconfiguration', 'A.8.9'),
    'Content Security Policy (CSP) Header Not Set': ('WSTG-CONF-12', 'A05 Security Misconfiguration', 'A.8.9'),
    'Cross-Origin-Embedder-Policy Header Missing or Invalid': ('WSTG-CONF-14', 'A05 Security Misconfiguration', 'A.8.9'),
    'Cross-Origin-Opener-Policy Header Missing or Invalid': ('WSTG-CONF-14', 'A05 Security Misconfiguration', 'A.8.9'),
    'Deprecated Feature Policy Header Set': ('WSTG-CONF-14', 'A05 Security Misconfiguration', 'A.8.9'),
}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reporte', type=Path)
    parser.add_argument('salida', type=Path)
    args = parser.parse_args()
    data = json.loads(args.reporte.read_text(encoding='utf-8-sig'))
    rows = []
    for site in data.get('site', []):
        for alert in site.get('alerts', []):
            rows.append({
                'sitio': site.get('@name', ''),
                'pluginid': alert.get('pluginid', ''),
                'riesgo': alert.get('riskdesc', ''),
                'alerta': alert.get('alert', alert.get('name', '')),
                'cwe': alert.get('cweid', ''),
                'instancias': len(alert.get('instances', [])),
                'solucion': alert.get('solution', ''),
                'wstg': '', 'top10_2021': '', 'iso27001_2022': '',
                'estado_mapeo': 'PENDIENTE DE VALIDACION MANUAL',
                'archivo_fuente': str(args.reporte),
            })
    if not rows:
        raise SystemExit('El reporte no contiene alertas: no se genera un resultado ficticio.')
    rows.sort(key=lambda row: row['instancias'], reverse=True)
    for row in rows:
        if row['alerta'] in MAPPING:
            row['wstg'], row['top10_2021'], row['iso27001_2022'] = MAPPING[row['alerta']]
            row['estado_mapeo'] = 'ASOCIACION DE CRITERIOS; NO CONFIRMA EXPLOTABILIDAD'
    args.salida.parent.mkdir(parents=True, exist_ok=True)
    with args.salida.open('w', encoding='utf-8-sig', newline='') as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f'Alertas exportadas: {len(rows)}')
    print(dict(Counter(row['riesgo'] for row in rows)))
    print(f"Alertas con criterio asociado: {sum(bool(row['wstg']) for row in rows)}")


if __name__ == '__main__':
    main()
