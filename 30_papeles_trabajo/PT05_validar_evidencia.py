"""Valida artefactos reales E05, sin declarar cumplidas firmas o capturas."""
import csv
import json
import math
from pathlib import Path
import xml.etree.ElementTree as ET

root = Path('/repo')
for name in ('zap_baseline_juiceshop', 'zap_full_juiceshop', 'zap_full_portal'):
    folder = root / '20_evidencia/E05_app'
    data = json.loads((folder / f'{name}.json').read_text(encoding='utf-8-sig'))
    assert data.get('site'), f'{name}: faltan sitios'
    assert (folder / f'{name}.html').stat().st_size > 0
    print(f'OK {name}: HTML y JSON con sitios')
with (root / '40_hallazgos/PT05_alertas_zap.csv').open(encoding='utf-8-sig') as src:
    rows = list(csv.DictReader(src))
assert sum(all(r[k] for k in ('wstg', 'top10_2021', 'iso27001_2022')) for r in rows) >= 5
print('OK cinco alertas con criterios asociados')
with (root / '40_hallazgos/PT05_mttd.csv').open(encoding='utf-8-sig') as src:
    sample = list(csv.DictReader(src))
assert len(sample) == 5 and all(float(r['Segundos']) >= 0 for r in sample)
mean = sum(float(r['Segundos']) for r in sample) / len(sample)
assert math.isclose(mean, 0.9956, abs_tol=1e-6)
print(f'OK MTTD={mean:.4f} segundos, n={len(sample)}')
hashes = json.loads((root / '20_evidencia/E05_infra/hashes_restauracion_con_datos.json').read_text(encoding='utf-8-sig'))
assert len(hashes) == 2 and hashes[0]['Hash'] == hashes[1]['Hash']
out = root / 'docs/evidencias/S05/salidas'
assert (out / 'filas_originales.txt').read_bytes() == (out / 'filas_restauradas.txt').read_bytes()
assert len((out / 'filas_restauradas.txt').read_text().splitlines()) == 3
assert 'EXIT_CODE=0' in (out / 'importacion_restaurada_con_datos.txt').read_text()
assert 'no errors were found' in (out / 'restic_con_datos.txt').read_text()
print('OK restauracion: hashes, tres filas, importacion y check')
tree = ET.parse(root / '20_evidencia/E05_infra/nmap_servicios.xml')
assert tree.find('runstats/finished').get('exit') == 'success'
print('OK Nmap finalizado correctamente')
print('PENDIENTES: firma docente previa, inventario oficial, capturas, PDF, PR y URL final')
