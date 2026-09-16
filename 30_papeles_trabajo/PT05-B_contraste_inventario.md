# PT05-B — Contraste de inventarios

Estado: escaneo E05 ejecutado, inventario oficial pendiente. El listado siguiente procede de entorno/docker-compose.yml, no de Nmap nuevo.

| Servicio declarado en Compose | Puerto esperado interno | Exposición anfitrión |
|---|---|---|
| si084_juiceshop | 3000/tcp | 127.0.0.1:3000 |
| si084_dvwa | 80/tcp | 127.0.0.1:8081 |
| si084_db | 5432/tcp | 127.0.0.1:5432 |
| si084_portal | 80/tcp | 127.0.0.1:8082 |
| si084_wpdb | 3306/tcp | Sin publicación explícita |
| si084_srdb | 3306/tcp | Sin publicación explícita |
| si084_simplerisk | 80 y 443/tcp | 127.0.0.1:8083 y 8443 |

| Servicio hallado E05 | IP | Puerto | Versión detectada | En inventario oficial | Dueño | Alcance SGSI | Evidencia y observación |
|---|---|---|---|---|---|---|---|
| Véase tabla E05 y PT05_inventario_real.csv | | | | Inventario oficial no recibido | No informado | No informado | Hallazgo H-002 respecto de Compose |

Referencia histórica: E03/nmap_servicios.txt muestra rpcbind (111/tcp) y status (45281/tcp) en 172.18.0.1 el 2026-09-02. Es un candidato a revisar en la pasarela; no es un hallazgo E05 confirmado. No reutilizar esa IP sin verificar la red actual ni afirmar que no está inventariado sin consultar el inventario oficial.

Para un servicio realmente omitido, redactar H-002.md con condición, criterio A.5.9, evidencia E05, causa comprobada o hipótesis explícita, efecto, recomendación, responsable y plazo. No crear un hallazgo ficticio para completar la rúbrica.

## Contraste E05 ejecutado contra declaración técnica Compose

| IP | Host | Puerto | Servicio | Versión detectada | Declarado en Compose | Dueño / SGSI |
|---|---|---|---|---|---|---|
| 172.18.0.6 | si084_db.si084-lab_audit_net | 5432 | postgresql | 9.6.0 or later | Sí, servicio del contenedor | No informados |
| 172.18.0.8 | si084_simplerisk.si084-lab_audit_net | 80 | http |  | Sí, servicio del contenedor | No informados |
| 172.18.0.8 | si084_simplerisk.si084-lab_audit_net | 443 | http |  | Sí, servicio del contenedor | No informados |
| 172.18.0.5 | si084_srdb.si084-lab_audit_net | 3306 | mysql | 11.8.9 | Sí, servicio del contenedor | No informados |
| 172.18.0.7 | si084_portal.si084-lab_audit_net | 80 | http | 2.4.68 | Sí, servicio del contenedor | No informados |
| 172.18.0.9 | laughing_banzai.si084-lab_audit_net | 45493 | unknown |  | Herramienta temporal ZAP, excluida del hallazgo | No informados |
| 172.18.0.4 | si084_dvwa.si084-lab_audit_net | 80 | http | 2.4.25 | Sí, servicio del contenedor | No informados |
| 172.18.0.3 | si084_juiceshop.si084-lab_audit_net | 3000 | ppp |  | Sí, servicio del contenedor | No informados |
| 172.18.0.2 | si084_wpdb.si084-lab_audit_net | 3306 | mysql | 11.8.9 | Sí, servicio del contenedor | No informados |
| 172.18.0.1 |  | 111 | rpcbind | 2-4 | No: pasarela, ver H-002 | No informados |
| 172.18.0.1 |  | 44359 | status | 1 | No: pasarela, ver H-002 | No informados |
