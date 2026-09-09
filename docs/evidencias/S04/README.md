# Taller 04 - Índice de evidencia

**Curso:** SI-084 Auditoría de Sistemas  
**Taller:** Auditoría de configuración segura con Lynis, OpenSCAP, Docker Bench y Trivy  
**Fecha de ejecución:** 2026-09-09  
**Rama de trabajo:** `master`

## Resultados principales

- Lynis: hardening index 57, 230 pruebas, 2 warnings y 35 suggestions.
- OpenSCAP: 129 pass y 5 fail de severidad MEDIUM; no se observaron fallas HIGH.
- Docker Bench: 117 controles, 35 PASS, 25 WARN, 48 INFO y 9 NOTE; 5.31 obtuvo PASS.
- Trivy: 418 ocurrencias, 374 HIGH y 44 CRITICAL; 0 secretos detectados.
- SBOM Juice Shop: CycloneDX 1.7 con 709 componentes.
- Matriz consolidada: 485 registros y 13 sin clasificar (2.68 %). Meta menor al 20 % cumplida.

## Límites de cobertura

- Lynis y parte de Docker Bench observaron el host Linux virtualizado de Docker Desktop/WSL2, no la configuración nativa de Windows.
- OpenSCAP evaluó un contenedor mínimo Ubuntu 22.04; 264 reglas resultaron notapplicable.
- Trivy config detectó 0 archivos compatibles. Los dos archivos IaC presentes son Docker Compose, tipo no cubierto por los escáneres activos usados.
- Los resultados Trivy dependen de los digests de imagen y de la base de vulnerabilidades disponible el día de ejecución.

## Artefactos

| Artefacto | Herramienta | Descripción | Ruta | Fecha | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| docker-bench-consola.txt | Docker Bench | Salida de consola de la ejecución real. | `20_evidencia/E04_config/docker-bench-consola.txt` | 2026-09-09 | `33097392d09c514fd41ab2311e022a3cc5778b7fa2c0ca9738b813442b6b69d1` |
| docker-bench-consola_intento1.txt | Docker Bench | Salida preservada de un intento no válido, con el error y su causa. | `20_evidencia/E04_config/docker-bench-consola_intento1.txt` | 2026-09-09 | `0e45f54da0b771b214f6ae9374b7cb4199c1dbe090401f6ac336a21582dda0f8` |
| docker-bench-controles.csv | Docker Bench | Inventario tabular de controles Docker Bench. | `20_evidencia/E04_config/docker-bench-controles.csv` | 2026-09-09 | `42b37cf90df5a569fa5ba8d2654bf14a2f57eb75802fef262082d8f5bf4d559f` |
| docker-bench-preparacion.txt | Docker Bench | Registro de versión, fuente, comandos, entorno y ejecución. | `20_evidencia/E04_config/docker-bench-preparacion.txt` | 2026-09-09 | `a86375178d4febacc4f39c9b5d2b40281098374e0e9fc3cd926d385c3be3882d` |
| docker-bench-resumen.txt | Docker Bench | Resumen derivado de la salida estructurada o del log oficial. | `20_evidencia/E04_config/docker-bench-resumen.txt` | 2026-09-09 | `e13d93837f8c1acd792e451e377755720f7f96a4e0edca0ede934e63930c9730` |
| docker-bench-warn.txt | Docker Bench | Controles WARN extraídos del log oficial. | `20_evidencia/E04_config/docker-bench-warn.txt` | 2026-09-09 | `15dea5b3ea1a8e7062d15282d6ab582745bb77ddc91f1dfcd34ee66543155982` |
| docker-bench.json | Docker Bench | Salida JSON estructurada de la ejecución. | `20_evidencia/E04_config/docker-bench.json` | 2026-09-09 | `285c41fc1ce0126a533fc051d8cfc6c676b93eb76b199984f683fd979102dec6` |
| docker-bench.log | Docker Bench | Artefacto de evidencia del Taller 04. | `20_evidencia/E04_config/docker-bench.log` | 2026-09-09 | `0a7fdfcaac472be90516ababa2ecec3ca48682527205fc015cce16a7e782ba79` |
| lynis-consola-raw.txt | Lynis | Consola original antes de normalizar códigos de color. | `20_evidencia/E04_config/lynis-consola-raw.txt` | 2026-09-09 | `8ed995033c969093c7d104c216afc4fd5bc87af29e6e5f5c05b7199fcfbcfae7` |
| lynis-consola.txt | Lynis | Salida de consola de la ejecución real. | `20_evidencia/E04_config/lynis-consola.txt` | 2026-09-09 | `fee82c848381683eece261857a31551719856a7cc35fc72b72998f8b6dacf749` |
| lynis-consola_intento1.txt | Lynis | Salida preservada de un intento no válido, con el error y su causa. | `20_evidencia/E04_config/lynis-consola_intento1.txt` | 2026-09-09 | `da5c6693868dae1008501cb7d5fa025ed7cee89969671a8d8cd8ad5d21b5583a` |
| lynis-report.dat | Lynis | Reporte de datos original de la herramienta. | `20_evidencia/E04_config/lynis-report.dat` | 2026-09-09 | `fc83d1eb0f2c466cd39659459148a068e38b7dde71c5d0c06b023f4f484ba848` |
| lynis-report_intento1.dat | Lynis | Salida preservada de un intento no válido, con el error y su causa. | `20_evidencia/E04_config/lynis-report_intento1.dat` | 2026-09-09 | `776ad569e6269c8a5f65e754ffce9bbe96272a88ea906b1ecba3d48e4e5b637a` |
| lynis-resumen.txt | Lynis | Resumen derivado de la salida estructurada o del log oficial. | `20_evidencia/E04_config/lynis-resumen.txt` | 2026-09-09 | `731b7617453bd70d6cf5ba60fc3bcf21d138663f38dda3042f1c8a463994f271` |
| oscap-consola.txt | OpenSCAP | Salida de consola de la ejecución real. | `20_evidencia/E04_config/oscap-consola.txt` | 2026-09-09 | `61fff61e061feb35de7d37d07c1bb2384f2363685a3993bc815596ce658f5ac1` |
| oscap-info.txt | OpenSCAP | Artefacto de evidencia del Taller 04. | `20_evidencia/E04_config/oscap-info.txt` | 2026-09-09 | `c30de57949536bb035eaec08b81578693c76975a89138a48c605d4bbb207f1e2` |
| oscap-preparacion-consola.txt | OpenSCAP | Registro de versión, fuente, comandos, entorno y ejecución. | `20_evidencia/E04_config/oscap-preparacion-consola.txt` | 2026-09-09 | `58d10ae400fc680073fb26010d890bc4d98034dce63cd369b618e6682c3044f7` |
| oscap-preparacion-consola_intento1.txt | OpenSCAP | Salida preservada de un intento no válido, con el error y su causa. | `20_evidencia/E04_config/oscap-preparacion-consola_intento1.txt` | 2026-09-09 | `4e6d7ea7a45884d11ac785eb8bb0e1c72d4ab3f2469f849c5b5291a14124a626` |
| oscap-reglas.csv | OpenSCAP | Inventario tabular de reglas XCCDF y referencias. | `20_evidencia/E04_config/oscap-reglas.csv` | 2026-09-09 | `87d4785105fda031e474dd9242b0dbb99fe631864b578d6b95c554289722e4cc` |
| oscap-reporte.html | OpenSCAP | Reporte HTML navegable generado por la herramienta. | `20_evidencia/E04_config/oscap-reporte.html` | 2026-09-09 | `5444fbcebadff8c5d41088180f5170bc276bd1b9c53c39aee30960e8770eb30f` |
| oscap-resultados.xml | OpenSCAP | Resultado estructurado original de la herramienta. | `20_evidencia/E04_config/oscap-resultados.xml` | 2026-09-09 | `17b652e6532b476509077c6f7921b8c88566332fe793aa76638fd1f77a398661` |
| oscap-resumen.txt | OpenSCAP | Resumen derivado de la salida estructurada o del log oficial. | `20_evidencia/E04_config/oscap-resumen.txt` | 2026-09-09 | `5939ec7a77bb65ad9becb2524b5e87752d13948888f83eb611d3382dda4bd39d` |
| sbom_juiceshop.json | Trivy | SBOM CycloneDX de Juice Shop. | `20_evidencia/E04_config/sbom_juiceshop.json` | 2026-09-09 | `6fa50ddd555b1626521335cb09e0a14d02f82deca6d11c09e5d6f782a1e8eb48` |
| sbom_juiceshop_consola.txt | Trivy | Salida de consola de la ejecución real. | `20_evidencia/E04_config/sbom_juiceshop_consola.txt` | 2026-09-09 | `1243c4894232b0107f92d447d866b0a5f7839ee27ca0fc8df832bc0df9f5c333` |
| trivy-preparacion.txt | Trivy | Registro de versión, fuente, comandos, entorno y ejecución. | `20_evidencia/E04_config/trivy-preparacion.txt` | 2026-09-09 | `21ab70f9ea7d75230f5854d388c0ccabe4a845d87d67bf4eb4b70d498e5d269d` |
| trivy_iac.json | Trivy | Resultado de Trivy config para infraestructura como código. | `20_evidencia/E04_config/trivy_iac.json` | 2026-09-09 | `90c08e4d1959ce2537c76abf0f44415018e2d040cb29868e5baaa7d22bbccbe1` |
| trivy_iac.txt | Trivy | Resultado de Trivy config para infraestructura como código. | `20_evidencia/E04_config/trivy_iac.txt` | 2026-09-09 | `ac31c2c809da3337e3104c5b12a7b8576112410d43627849d9bd9e8f0dbcfc46` |
| trivy_iac_consola.txt | Trivy | Salida de consola de la ejecución real. | `20_evidencia/E04_config/trivy_iac_consola.txt` | 2026-09-09 | `0f201c2b8db386c9090d630968fe6706013856e38151e64522ddcde3abdd5a4a` |
| trivy_iac_tabla_consola.txt | Trivy | Salida de consola de la ejecución real. | `20_evidencia/E04_config/trivy_iac_tabla_consola.txt` | 2026-09-09 | `4b037ee902a89362354d15527fbfb76c7ba2151174056694c38df64654fc1042` |
| trivy_juiceshop.json | Trivy | Salida JSON estructurada de la ejecución. | `20_evidencia/E04_config/trivy_juiceshop.json` | 2026-09-09 | `104708a2c1c7d7038f887f0116b8c9591ae2e82b1a20b795806d5a4da73eed07` |
| trivy_juiceshop_consola.txt | Trivy | Salida de consola de la ejecución real. | `20_evidencia/E04_config/trivy_juiceshop_consola.txt` | 2026-09-09 | `e318ae0391a1b578b62ab7b11c2ef31b269ace79f9a668488aa42ed64fc3263f` |
| trivy_mariadb11.json | Trivy | Salida JSON estructurada de la ejecución. | `20_evidencia/E04_config/trivy_mariadb11.json` | 2026-09-09 | `f2abe64c36a2e81d47126c5565e0478e4b6a841c9e17899a07f7d6b351b045c5` |
| trivy_mariadb11_consola.txt | Trivy | Salida de consola de la ejecución real. | `20_evidencia/E04_config/trivy_mariadb11_consola.txt` | 2026-09-09 | `76e42daf2c8fb4c1f46aa9953dc1022af3935912eddd8403907fe44bfdd910be` |
| trivy_postgres16.json | Trivy | Salida JSON estructurada de la ejecución. | `20_evidencia/E04_config/trivy_postgres16.json` | 2026-09-09 | `83354c25845321066734ad6c026a4fcf02e23698a648dd078f6a03aed66c3f08` |
| trivy_postgres16_consola.txt | Trivy | Salida de consola de la ejecución real. | `20_evidencia/E04_config/trivy_postgres16_consola.txt` | 2026-09-09 | `7f376179cfce7fe2697fc7081fba77eadc841de350dc024eb2643cc1f5f1ad16` |
| trivy_resumen.txt | Trivy | Resumen derivado de la salida estructurada o del log oficial. | `20_evidencia/E04_config/trivy_resumen.txt` | 2026-09-09 | `f98ba1c400ec1fd3913f199b7466d0230f25a6e49bc1c81fd4c2b496c45f34bf` |
| trivy_secretos.json | Trivy | Resultado de secretos saneado; los valores se sustituyen por [REDACTED]. | `20_evidencia/E04_config/trivy_secretos.json` | 2026-09-09 | `8caf6fe6947722c798cb5f8791ed75964ddef79fcf7bfeec225fb1e2c004a8ac` |
| trivy_secretos.txt | Trivy | Resultado de secretos saneado; los valores se sustituyen por [REDACTED]. | `20_evidencia/E04_config/trivy_secretos.txt` | 2026-09-09 | `6e592cb627c13a659e55822db7e6d4822ef77782cf88ed027c7f4b16ba5256d0` |
| trivy_secretos_consola.txt | Trivy | Salida de consola de la ejecución real. | `20_evidencia/E04_config/trivy_secretos_consola.txt` | 2026-09-09 | `35a680317a2218dc0d31054d627df631be77eb5f0b42a0bf6beb3e41b5820712` |
| trivy_vulnerabilidades.csv | Trivy | Ocurrencias Trivy normalizadas por imagen, paquete y vulnerabilidad. | `20_evidencia/E04_config/trivy_vulnerabilidades.csv` | 2026-09-09 | `ba85394c4b58953c39970626116be27ab0a6dd0647ef5eb29d104c5aac7bb11f` |
| trivy_wordpress.json | Trivy | Salida JSON estructurada de la ejecución. | `20_evidencia/E04_config/trivy_wordpress.json` | 2026-09-09 | `700e3125d6407966f891b819bbc753929ce1aeef6ab9b79885d577a3e32a9b6a` |
| trivy_wordpress_consola.txt | Trivy | Salida de consola de la ejecución real. | `20_evidencia/E04_config/trivy_wordpress_consola.txt` | 2026-09-09 | `d57628a132b6f6da2bf474321385124d6f81ca571f13d0350280843fa2d248d5` |
| PT04_analisis_control.md | Análisis de control | Análisis de A.8.8 y clasificación de eficacia operativa. | `30_papeles_trabajo/PT04_analisis_control.md` | 2026-09-09 | `0af4f5aeb672a9f70e7827b839b043aac8f4d987073b010e4951d509eaf766d6` |
| PT04_matriz_control.py | Consolidación | Script reproducible que consolida y clasifica las cuatro fuentes. | `30_papeles_trabajo/PT04_matriz_control.py` | 2026-09-09 | `3278ebea818da593829225349b8ce938e1da68c3c4669fa5f6f28c6ef9fd0005` |
| PT04_clasificacion_manual.csv | Consolidación | Plantilla opcional para reclasificación manual por ID estable. | `40_hallazgos/PT04_clasificacion_manual.csv` | 2026-09-09 | `f9877182bba84f6f5b7f250b4a09556b680730a9f250a211081babfc60ceb884` |
| PT04_matriz_control.csv | Consolidación | Matriz consolidada ISO/IEC 27001:2022 y COBIT 2019. | `40_hallazgos/PT04_matriz_control.csv` | 2026-09-09 | `3a7acc06abd7bcc2198124a28041e100de71febf20624c3b7eb96894a8a54755` |
| PT04_validacion.txt | Consolidación | Conteos y porcentaje sin clasificar de la matriz final. | `40_hallazgos/PT04_validacion.txt` | 2026-09-09 | `b2dae8dd4a306d208ff2d4512a01d5bcb181f60d5dbe8bd0f8629867ee567102` |
| 04_lynis_resumen.png | Lynis | Resumen derivado de la salida estructurada o del log oficial. | `docs/evidencias/S04/04_lynis_resumen.png` | 2026-09-09 | `fc5c344dc5cb393ca580e936957f6c550cee074563821c73a32b839764d1c63b` |
| 05_openscap_resumen.png | OpenSCAP | Resumen derivado de la salida estructurada o del log oficial. | `docs/evidencias/S04/05_openscap_resumen.png` | 2026-09-09 | `e21498d11de01a9487281ace5bfcfe7f2e3027cf6ce926710fa56c94f52dd1e9` |
| 06_openscap_reporte_html.png | OpenSCAP | Captura visual para el informe del taller. | `docs/evidencias/S04/06_openscap_reporte_html.png` | 2026-09-09 | `4e0b66ea9f76c1f5b68d38f27efc324b07e6a5cc7e8b146a33605ab722929257` |
| 07_docker_bench_resumen.png | Taller 04 | Resumen derivado de la salida estructurada o del log oficial. | `docs/evidencias/S04/07_docker_bench_resumen.png` | 2026-09-09 | `fb4acda2ab4d2b7c48fe8d65ee48a042cf061c4e3bcd34d7426d3971f44611a0` |
| 08_docker_bench_log.png | Taller 04 | Captura visual para el informe del taller. | `docs/evidencias/S04/08_docker_bench_log.png` | 2026-09-09 | `97cb7535d448c35736ed5bfa6ea2f037a14cd3ae1a18e037c085a2a69ce4bf46` |
| 09_trivy_resumen.png | Trivy | Resumen derivado de la salida estructurada o del log oficial. | `docs/evidencias/S04/09_trivy_resumen.png` | 2026-09-09 | `1056434a24da0eaa9aaaca2ca0fbd3184f778f470a8d668fcf7b269105d3adeb` |
| 10_trivy_complementarios.png | Trivy | Captura visual para el informe del taller. | `docs/evidencias/S04/10_trivy_complementarios.png` | 2026-09-09 | `754b2cb0e2f90517aa6666ced200177599b3376b926740269fd44d5e9b9d30f6` |
| 11_matriz_validacion.png | Consolidación | Conteos y porcentaje sin clasificar de la matriz final. | `docs/evidencias/S04/11_matriz_validacion.png` | 2026-09-09 | `8c9fabc5b73ba1773febbc04de2a720e5d2d22a015b784ccdc2223040929e441` |
| 12_analisis_control.png | Análisis de control | Análisis de A.8.8 y clasificación de eficacia operativa. | `docs/evidencias/S04/12_analisis_control.png` | 2026-09-09 | `de368eab3bbc203a499f080f444befe80c3b0c71f7f337826c850786ac4d936c` |
| docker-bench-controles.csv | Docker Bench | Inventario tabular de controles Docker Bench. | `docs/evidencias/S04/salidas/docker-bench-controles.csv` | 2026-09-09 | `42b37cf90df5a569fa5ba8d2654bf14a2f57eb75802fef262082d8f5bf4d559f` |
| docker-bench-preparacion.txt | Docker Bench | Registro de versión, fuente, comandos, entorno y ejecución. | `docs/evidencias/S04/salidas/docker-bench-preparacion.txt` | 2026-09-09 | `a86375178d4febacc4f39c9b5d2b40281098374e0e9fc3cd926d385c3be3882d` |
| docker-bench-resumen.txt | Docker Bench | Resumen derivado de la salida estructurada o del log oficial. | `docs/evidencias/S04/salidas/docker-bench-resumen.txt` | 2026-09-09 | `e13d93837f8c1acd792e451e377755720f7f96a4e0edca0ede934e63930c9730` |
| docker-bench-warn.txt | Docker Bench | Controles WARN extraídos del log oficial. | `docs/evidencias/S04/salidas/docker-bench-warn.txt` | 2026-09-09 | `15dea5b3ea1a8e7062d15282d6ab582745bb77ddc91f1dfcd34ee66543155982` |
| lynis-resumen.txt | Lynis | Resumen derivado de la salida estructurada o del log oficial. | `docs/evidencias/S04/salidas/lynis-resumen.txt` | 2026-09-09 | `731b7617453bd70d6cf5ba60fc3bcf21d138663f38dda3042f1c8a463994f271` |
| oscap-reglas.csv | OpenSCAP | Inventario tabular de reglas XCCDF y referencias. | `docs/evidencias/S04/salidas/oscap-reglas.csv` | 2026-09-09 | `87d4785105fda031e474dd9242b0dbb99fe631864b578d6b95c554289722e4cc` |
| oscap-resumen.txt | OpenSCAP | Resumen derivado de la salida estructurada o del log oficial. | `docs/evidencias/S04/salidas/oscap-resumen.txt` | 2026-09-09 | `5939ec7a77bb65ad9becb2524b5e87752d13948888f83eb611d3382dda4bd39d` |
| PT04_matriz_control.csv | Consolidación | Matriz consolidada ISO/IEC 27001:2022 y COBIT 2019. | `docs/evidencias/S04/salidas/PT04_matriz_control.csv` | 2026-09-09 | `3a7acc06abd7bcc2198124a28041e100de71febf20624c3b7eb96894a8a54755` |
| PT04_validacion.txt | Consolidación | Conteos y porcentaje sin clasificar de la matriz final. | `docs/evidencias/S04/salidas/PT04_validacion.txt` | 2026-09-09 | `b2dae8dd4a306d208ff2d4512a01d5bcb181f60d5dbe8bd0f8629867ee567102` |
| trivy-preparacion.txt | Trivy | Registro de versión, fuente, comandos, entorno y ejecución. | `docs/evidencias/S04/salidas/trivy-preparacion.txt` | 2026-09-09 | `21ab70f9ea7d75230f5854d388c0ccabe4a845d87d67bf4eb4b70d498e5d269d` |
| trivy_iac.txt | Trivy | Resultado de Trivy config para infraestructura como código. | `docs/evidencias/S04/salidas/trivy_iac.txt` | 2026-09-09 | `ac31c2c809da3337e3104c5b12a7b8576112410d43627849d9bd9e8f0dbcfc46` |
| trivy_resumen.txt | Trivy | Resumen derivado de la salida estructurada o del log oficial. | `docs/evidencias/S04/salidas/trivy_resumen.txt` | 2026-09-09 | `f98ba1c400ec1fd3913f199b7466d0230f25a6e49bc1c81fd4c2b496c45f34bf` |
| trivy_secretos.txt | Trivy | Resultado de secretos saneado; los valores se sustituyen por [REDACTED]. | `docs/evidencias/S04/salidas/trivy_secretos.txt` | 2026-09-09 | `6e592cb627c13a659e55822db7e6d4822ef77782cf88ed027c7f4b16ba5256d0` |
| trivy_vulnerabilidades.csv | Trivy | Ocurrencias Trivy normalizadas por imagen, paquete y vulnerabilidad. | `docs/evidencias/S04/salidas/trivy_vulnerabilidades.csv` | 2026-09-09 | `ba85394c4b58953c39970626116be27ab0a6dd0647ef5eb29d104c5aac7bb11f` |

## Trazabilidad

El manifiesto `20_evidencia/SHA256SUMS_E04.txt` contiene los hashes finales de estos archivos y el hash de este README. El manifiesto no se incluye a sí mismo, como es habitual en archivos de sumas de comprobación.

No se almacenan valores de secretos en este índice ni en `trivy_secretos.txt` o `trivy_secretos.json`.
