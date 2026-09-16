# Taller 05 — Estado de ejecución

Fecha: 2026-09-16. Rama taller-05. Docker Linux 29.8.0 operativo; siete servicios del Compose levantados en si084-lab_audit_net, subred 172.18.0.0/16.

| Resultado | Estado real |
|---|---|
| Alcance previo | Commit 2ab20c0 previo a pruebas; autorización del usuario registrada; firma docente pendiente |
| ZAP Juice Shop | Baseline y activo terminados, HTML/JSON; 7 advertencias baseline y 6 activo; 10 entradas de alertas en JSON activo |
| Mapeo | Cinco alertas reales con WSTG, Top 10 e ISO; resto pendiente de asociación |
| Nmap | Hosts, puertos TCP completos por objetivo y TLS; 9 IP, 11 puertos abiertos registrados |
| PT05-B y hallazgo | Contraste contra Compose; rpcbind/status de pasarela omitidos; inventario oficial, dueños y SGSI pendientes |
| Wazuh | Manager/indexer/dashboard y agente portal activos; tabla D-01 a D-05; MTTD 0,9956 s n=5; capturas del panel pendientes |
| Restic | Restauración 1,116055 s, hashes coincidentes, check sin errores; importación aislada con 3 filas sintéticas coincidentes |
| Custodia | Hashes y registro de archivos E05; ver manifiesto y cadena |
| PDF y anexos | Pendientes de plantilla del usuario, grupo/códigos, firmas y capturas |
| GitHub | Publicación/PR/etiqueta final pendientes; no asumir que enlaces propuestos ya funcionan |

## Problemas y mejoras

- El alcance del docente no estaba firmado antes de las pruebas. No se corregirá retroactivamente ni se declarará logrado ese criterio. Las pruebas locales fueron autorizadas por el usuario.
- No se recibió inventario oficial. La omisión demostrada es frente a Compose, no a todos los registros organizacionales.
- Se escanearon las IP identificadas en Docker y pasarela, no toda la /16. Un contenedor temporal ZAP se incluyó en el inventario real y se identificó como herramienta del auditor.
- WordPress estaba sin instalar. Se instaló como sitio local con usuario auditor_lab y contraseña aleatoria; siteurl/home se ajustaron a http://si084_portal para evitar redirección a localhost del contenedor ZAP. El primer intento fallido se conserva.
- El log Apache estaba enlazado a stdout. Se habilitó un archivo real y se enroló Wazuh 4.9.0 en el contenedor del portal. Las modificaciones del agente/WordPress son del contenedor actual; deben reproducirse tras recrearlo. La instalación inicial del agente requirió lsb-release; los intentos se conservan.
- Wazuh tiene puertos publicados sólo en 127.0.0.1. Código oficial v4.9.0, commit cb63566719ce2e78b9d3c111a0a61d743fc699fc, en work/wazuh-docker fuera del repositorio entregable. Certificados y claves quedan locales.
- vm.max_map_count ya era 262144: no se modificó. La habilitación previa de WSL/Docker fue realizada por el usuario.
- ERP nuevo vacío: se agregaron tres filas sintéticas para validar recuperación con contenido. No se representa como restauración de datos históricos.
- No se configuró sensor de red: el escaneo TCP no generó alerta específica de escaneo. No se notificó a personas reales ni se acreditó retención/inmutabilidad.
- Acceso automatizado al panel bloqueado por certificado local; el usuario confirmó que ve el login en su navegador. Esa sesión externa no está conectada a la herramienta de navegador disponible.

## Conclusiones

1. Inventariar únicamente los contenedores de Compose omite servicios accesibles de pasarela. La prueba local halló rpcbind/status; falta el inventario oficial para concluir omisión organizacional.
2. Wazuh detectó cinco cargas web con MTTD aproximado de un segundo, pero no el reconocimiento TCP como evento de red; correo desactivado y registros modificables por el administrador limitan la eficacia del control.
3. La recuperación de SQL y tres filas sintéticas se verificó mediante hash e importación aislada. Sin RTO/RPO declarados ni datos históricos no se puede afirmar continuidad operativa del ERP real.

## Transferencia

Pruebas sin alcance previo firmado pueden producir afectaciones y responsabilidades fuera de la autorización. Confundir alertas con notificaciones o recuperación de archivos con recuperación operativa puede ocultar fallas durante un incidente real.
