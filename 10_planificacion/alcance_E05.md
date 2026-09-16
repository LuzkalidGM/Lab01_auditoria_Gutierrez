# Alcance autorizado — E05 (BORRADOR SIN FIRMA)

Estado: pendiente de autorización del docente. Este documento no acredita autorización.

| Campo | Valor |
|---|---|
| Sistemas alcanzados | si084_juiceshop (127.0.0.1:3000), si084_portal (127.0.0.1:8082), si084_db y contenedores de la red audit_net del proyecto si084-lab |
| Red efectiva y subred | Pendientes de verificar en el anfitrión. Compose utiliza normalmente si084-lab_audit_net; no asumir IP antiguas. |
| Sistemas excluidos | Toda dirección fuera de 127.0.0.1 y la subred autorizada; universidad, nube y empresa real |
| Ventana autorizada | Pendiente: fecha, hora inicial y final; sesión Semana 05, 2 horas |
| Pruebas | ZAP pasivo y activo; Nmap; detección con Wazuh; respaldo y restauración con restic |
| Autorizado por | Docente SI-084: nombre y firma pendientes |
| Fecha y hora UTC de firma | Pendiente |
| Restricciones | Entorno desechable; sin pruebas contra empresa real; documentar modificaciones del anfitrión |

Antes de ejecutar: completar y firmar; archivar la autorización; registrar su hash y hacer commit. Conservar el hash del commit y la hora UTC. No firmar retrospectivamente.

## Autorización operativa del propietario
El usuario solicitó desarrollar la práctica y continuar las pruebas sobre el laboratorio local desechable de este repositorio. Registro UTC: 2026-09-16T21:09:50.9404749Z. Esta autorización del usuario no sustituye la firma académica del docente, pendiente.
Ventana operativa: próximas 2 horas desde este registro; destinos exclusivos contenedores si084-lab y su red audit_net. No usar objetivos externos.

