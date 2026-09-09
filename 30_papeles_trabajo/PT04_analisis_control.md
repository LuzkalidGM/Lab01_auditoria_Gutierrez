# PT04 - Análisis del control con mayor concentración de hallazgos

**Fecha de evaluación:** 2026-09-09  
**Control ISO/IEC 27001:2022:** A.8.8 Management of technical vulnerabilities  
**Objetivo COBIT 2019:** DSS05.07 Monitor the infrastructure for security-related events

## Condición encontrada

La matriz consolidada asignó 423 de 485 registros al control A.8.8. De ellos, 418 corresponden a ocurrencias de vulnerabilidades `HIGH` o `CRITICAL` identificadas por Trivy y 5 a advertencias o sugerencias de Lynis relacionadas con integridad de paquetes, consistencia de la base de paquetes, gestión de parches y actualización automática.

Trivy reportó 374 ocurrencias `HIGH` y 44 `CRITICAL` en las cuatro imágenes solicitadas:

| Imagen | HIGH | CRITICAL | Total | Con versión corregida informada |
| --- | ---: | ---: | ---: | ---: |
| `bkimminich/juice-shop:latest` | 45 | 8 | 53 | 51 |
| `postgres:16` | 98 | 14 | 112 | 25 |
| `wordpress:latest` | 210 | 21 | 231 | 43 |
| `mariadb:11` | 21 | 1 | 22 | 22 |
| **Total** | **374** | **44** | **418** | **141** |

Las imágenes se actualizaron con `docker pull` inmediatamente antes del escaneo. Los resultados describen los digests registrados el 2026-09-09 y la base de vulnerabilidades disponible para Trivy 0.74.0 en ese momento.

## Criterio

El control A.8.8 requiere gestionar información sobre vulnerabilidades técnicas, evaluar la exposición y aplicar acciones de tratamiento oportunas. DSS05.07 complementa este criterio mediante el monitoreo de la infraestructura para detectar eventos relacionados con la seguridad.

## Evidencia

- `20_evidencia/E04_config/trivy_juiceshop.json`
- `20_evidencia/E04_config/trivy_postgres16.json`
- `20_evidencia/E04_config/trivy_wordpress.json`
- `20_evidencia/E04_config/trivy_mariadb11.json`
- `20_evidencia/E04_config/trivy_resumen.txt`
- `20_evidencia/E04_config/trivy_vulnerabilidades.csv`
- `20_evidencia/E04_config/lynis-report.dat`
- `40_hallazgos/PT04_matriz_control.csv`

## Riesgo

Mantener componentes con vulnerabilidades de severidad alta o crítica aumenta la probabilidad de explotación de fallas conocidas. Según el componente afectado, una explotación podría comprometer la confidencialidad, integridad o disponibilidad de los servicios y datos procesados por los contenedores. Las 141 ocurrencias con versión corregida informada representan un subconjunto con una ruta de actualización identificable en el reporte.

## Causa posible

La evidencia es compatible con ciclos de reconstrucción y actualización que no retiran oportunamente todos los paquetes o componentes vulnerables de las imágenes. También puede influir la permanencia de dependencias de aplicación con versiones afectadas. Estas son causas posibles: la evidencia técnica no incluye políticas, procedimientos ni registros de gestión que permitan confirmar la causa organizacional.

## Tipo de deficiencia

**Eficacia operativa**

## Justificación

La prueba demuestra que el resultado esperado del control no se alcanzó en el inventario evaluado: las cuatro imágenes actualizadas y analizadas contienen vulnerabilidades `HIGH` o `CRITICAL`. La evidencia disponible no permite afirmar que el control carezca de diseño formal, porque no se revisaron políticas, responsables, frecuencias ni criterios de aceptación. Por ello, la conclusión se limita a la eficacia observada durante la ejecución.

## Recomendación

1. Priorizar las 44 ocurrencias `CRITICAL` y, dentro de ellas, las que Trivy asocia con una versión corregida.
2. Crear un backlog por imagen, paquete, CVE, versión instalada y versión corregida usando `trivy_vulnerabilidades.csv`, evitando contar una misma CVE sin considerar el paquete y el objetivo donde aparece.
3. Reconstruir las imágenes desde bases soportadas y actualizar las dependencias de aplicación que tengan corrección disponible.
4. Integrar el escaneo Trivy `HIGH,CRITICAL` en el proceso de construcción y establecer un criterio documentado para bloquear o aceptar excepciones con responsable y fecha de vencimiento.
5. Fijar imágenes por digest en los despliegues auditables y conservar el digest junto con cada resultado.
6. Repetir los cuatro escaneos después de la remediación y comparar ocurrencias, severidad y versiones corregidas contra esta línea base.

## Limitaciones

- Los conteos son una fotografía del 2026-09-09 y pueden cambiar cuando se actualicen las imágenes o la base de vulnerabilidades.
- Una ocurrencia representa la combinación reportada de vulnerabilidad, paquete y objetivo; no equivale necesariamente a un escenario de explotación confirmado.
- El análisis no evalúa si cada componente vulnerable es alcanzable durante la ejecución de la aplicación.
