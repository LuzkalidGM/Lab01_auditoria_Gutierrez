# PT05-D — Detección del auditor

Prueba: 2026-09-16; Wazuh 4.9.0, agente 001 si084_portal activo, log Apache real /var/log/apache2/access.log. No se implementó IDS de red ni una regla que transforme la salida de Nmap en alertas.

| ID | Prueba | Veredicto | Evidencia |
|---|---|---|---|
| D-01 | Escaneo TCP | No detectado como escaneo de red durante ventana observada | nmap_deteccion.txt; inicio/fin y fin_observacion_wazuh_UTC.txt; wazuh_alertas.jsonl |
| D-02 | Peticiones maliciosas web | Detectadas | Cinco UNION SELECT, regla 31106; ZAP portal también produjo reglas 31110 y 31516 |
| D-03 | Tiempo | MTTD 0,9956 segundos, n=5 | PT05_mttd.csv, log y alertas originales |
| D-04 | Notificación | Correo desactivado; entrega no demostrada | email_notification=no; mail=false; no se enviaron mensajes reales |
| D-05 | Integridad | Inalterabilidad no acreditada | Directorio 750, archivo 640, dueño wazuh; root puede modificarlos. Retención completa no verificada |

| Evento | Evento UTC | Alerta UTC | Regla | Diferencia s |
|---|---|---|---|---|
| medicion01 | 21:16:37 | 21:16:38.150 | 31106 | 1,150 |
| medicion02 | 21:17:21 | 21:17:22.204 | 31106 | 1,204 |
| medicion03 | 21:17:21 | 21:17:22.206 | 31106 | 1,206 |
| medicion04 | 21:17:21 | 21:17:22.208 | 31106 | 1,208 |
| medicion05 | 21:17:22 | 21:17:22.210 | 31106 | 0,210 |

Fecha de todos los eventos: 2026-09-16. MTTD = 4,978/5. Cinco eventos detectados, ninguno de la muestra sin alerta. El log Apache tiene resolución de un segundo: el promedio no tiene precisión real milimétrica. Ambos contenedores usan reloj del mismo kernel Docker. Se utiliza timestamp de generación de alerta, no llegada al panel.

Las cinco cargas con marcador e05 se enviaron mediante curl al propio WordPress como prueba complementaria, no se atribuyen a ZAP. HTTP 200 y el nombre de la regla 31106 no demuestran explotación SQL exitosa. No se obtuvo acceso ni extracción de datos.

El escaneo dedicado empezó 21:17:22.332 UTC y terminó 21:17:23.935 UTC; ver cierre de observación en el archivo correspondiente. Errores web no equivalen a detección de SYN a puertos. Capturas del panel pendientes por certificado local y acceso del navegador.

Criterios del curso: A.8.15, A.8.16, A.5.25. Recomendación: sensor independiente de red, prueba autorizada de recepción de notificaciones y almacenamiento con separación de permisos y retención verificable.
