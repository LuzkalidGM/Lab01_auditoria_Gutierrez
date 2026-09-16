# PT05-C — Acta de restauración

Ejecutada el 2026-09-16; pendiente de firma.

| Campo | Resultado |
|---|---|
| Sistema | ERP si084_db, entorno nuevo del repositorio |
| Fecha y snapshot | Ver snapshots_con_datos.json, último snapshot, campo time/id |
| RTO/RPO declarado | No informado; cumplimiento no evaluable |
| Tiempo recuperación archivo | 1,116055 segundos; incluye inicio/cierre de contenedor restic |
| SHA-256 original y restaurado | 90218BB82FF17BF7E43882F4F4BA48EEE7E3A6CE2277089D723BFBFF78C5C3C9 |
| Integridad | Coincide |
| Consistencia repositorio | restic check --read-data, 2 snapshots, sin errores |
| Importación | Base aislada erp_restauracion_e05_datos; psql ON_ERROR_STOP, código 0 |
| Validación de datos | Tres filas originales y restauradas coinciden |
| Auditor/firma | Ejecución asistida por Codex; integrante y firma pendientes |

La base nueva estaba vacía. Se agregó si084_e05_prueba con tres filas explícitamente sintéticas, DATO SINTETICO LAB-A/B/C. Se respalda el SQL de pg_dump guardado en UTF-8 sin BOM. No es recuperación del ERP histórico ni evidencia del RTO de una organización real. El tiempo de importación SQL no se midió como RTO operativo.

Prueba inicial del archivo SQL vacío: 1,3095365 segundos, hashes coincidentes; se conserva como prueba inicial. Dump y repositorio restic quedan locales y excluidos de Git.

Evidencias: 20_evidencia/E05_infra/tiempo_restauracion_con_datos.txt, hashes_restauracion_con_datos.json, snapshots_con_datos.json; docs/evidencias/S05/salidas/restic_con_datos.txt, importacion_restaurada_con_datos.txt, filas_originales.txt y filas_restauradas.txt.
