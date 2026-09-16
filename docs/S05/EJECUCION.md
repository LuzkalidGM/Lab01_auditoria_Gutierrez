# Ejecución del taller 05

Estos comandos son un plan pendiente, no evidencia de ejecución. Ejecutar desde la raíz del repositorio en Linux con Docker, sólo después de firmar y versionar el alcance. No ejecutar contra redes ajenas. No destruir volúmenes de las semanas previas.

## A. Precondiciones

```bash
docker version
docker compose -f entorno/docker-compose.yml config
git log -1 --format='%H %cI' -- 10_planificacion/alcance_E05.md
docker compose -f entorno/docker-compose.yml up -d
docker compose -f entorno/docker-compose.yml ps
mkdir -p 20_evidencia/E05_app 20_evidencia/E05_infra docs/evidencias/S05/salidas
NET=$(docker inspect si084_juiceshop --format '{{range $name, $value := .NetworkSettings.Networks}}{{$name}}{{end}}')
docker network inspect "$NET"
```

Verificar manualmente que NET es la red audit_net del proyecto y su subred coincide con la autorización. Si hay varias redes, elegir explícitamente la autorizada. Registrar Compose efectivo, contenedores, imágenes/digests y fecha UTC. Antes del escaneo activo, confirmar que el entorno es desechable o preservar sus datos.

## B. ZAP

Usar la red de contenedores evita depender de network host de Docker Desktop. El destino es un contenedor de la red autorizada.

```bash
docker run --rm --network "$NET" -v "$PWD/20_evidencia/E05_app:/zap/wrk:rw" zaproxy/zap-stable zap-baseline.py -t http://si084_juiceshop:3000 -r zap_baseline_juiceshop.html -J zap_baseline_juiceshop.json -I
docker run --rm --network "$NET" -v "$PWD/20_evidencia/E05_app:/zap/wrk:rw" zaproxy/zap-stable zap-full-scan.py -t http://si084_juiceshop:3000 -r zap_full_juiceshop.html -J zap_full_juiceshop.json -I
python3 30_papeles_trabajo/PT05_alertas_app.py 20_evidencia/E05_app/zap_full_juiceshop.json 40_hallazgos/PT05_alertas_zap.csv
```

Guardar la consola y códigos de salida. Los avisos de ZAP pueden producir códigos distintos de cero: comprobar reportes y errores antes de concluir. Completar los mapeos del CSV usando la guía y referencias aplicables; conservar alertas sin correspondencia como pendientes. Un escaneo pasivo también produce tráfico de navegación, por lo que no se debe afirmar riesgo absoluto cero.

## C. Nmap

```bash
SUBNET=$(docker network inspect "$NET" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}')
printf '%s\n' "$NET $SUBNET" > 20_evidencia/E05_infra/alcance_red.txt
docker run --rm --network "$NET" -v "$PWD/20_evidencia/E05_infra:/evidencia" instrumentisto/nmap -sn "$SUBNET" -oN /evidencia/nmap_hosts.txt
docker run --rm --network "$NET" -v "$PWD/20_evidencia/E05_infra:/evidencia" instrumentisto/nmap -sV -sC -p- --open "$SUBNET" -oA /evidencia/nmap_servicios
docker run --rm --network "$NET" -v "$PWD/20_evidencia/E05_infra:/evidencia" instrumentisto/nmap --script ssl-enum-ciphers -p 443,8443 "$SUBNET" -oN /evidencia/nmap_tls.txt
```

La guía original no monta un directorio para Nmap: con --rm sus archivos pueden perderse. Aquí se guardan mediante /evidencia. Completar PT05-B contra inventario oficial y redactar únicamente omisiones comprobadas.

## D. Wazuh

Seguir el despliegue Docker indicado en la práctica (v4.9.0) y verificar requisitos antes de instalar. Registrar cualquier cambio de vm.max_map_count, su valor anterior y su valor nuevo. No registrar contraseñas del panel en evidencias públicas.

Enrolar un agente con acceso efectivo a logs web y eventos de red. Verificar recepción con un evento de prueba antes de repetir los escaneos. Confirmar WordPress operativo: depende de MariaDB y puede requerir finalizar su instalación.

Repetir el reconocimiento y ZAP contra si084_portal:80, guardar reportes con nombres diferentes. Capturar timestamps UTC del evento y de la alerta, ID/regla, configuración de notificaciones y permisos/retención. Completar PT05-D. Documentar la ventana sin alertas cuando no se detecta. No enviar mensajes a destinatarios reales sin autorización.

## E. Restic

Ejecutar desde la raíz; contraseña de laboratorio únicamente.

```bash
mkdir -p 20_evidencia/E05_infra/dump 20_evidencia/E05_infra/repo
SQL="erp_$(date -u +%Y%m%dT%H%M%SZ).sql"
docker exec si084_db pg_dump -U erp_app erp > "20_evidencia/E05_infra/dump/$SQL"
# Detenerse si pg_dump falla o el archivo está vacío.
test -s "20_evidencia/E05_infra/dump/$SQL" || exit 1
restic_lab() {
  docker run --rm -v "$PWD/20_evidencia/E05_infra/repo:/repo" -v "$PWD/20_evidencia/E05_infra/dump:/datos" -e RESTIC_REPOSITORY=/repo -e RESTIC_PASSWORD=lab-si084 restic/restic "$@"
}
# init sólo para un repositorio nuevo; no ignorar errores indiscriminadamente.
restic_lab init
sha256sum "20_evidencia/E05_infra/dump/$SQL" > 20_evidencia/E05_infra/hash_original.txt
restic_lab backup "/datos/$SQL"
restic_lab snapshots --json > 20_evidencia/E05_infra/snapshots.json
T0=$(date -u +%s)
restic_lab restore latest --target /datos/restaurado || exit 1
T1=$(date -u +%s)
printf '%s\n' "$((T1-T0))" > 20_evidencia/E05_infra/tiempo_restauracion.txt
sha256sum "20_evidencia/E05_infra/dump/restaurado/datos/$SQL" > 20_evidencia/E05_infra/hash_restaurado.txt
diff <(cut -d ' ' -f1 20_evidencia/E05_infra/hash_original.txt) <(cut -d ' ' -f1 20_evidencia/E05_infra/hash_restaurado.txt)
restic_lab check --read-data
```

Guardar todas las salidas y rellenar PT05-C. No incluir repositorio restic ni dumps con datos privados en GitHub. La igualdad de hashes prueba recuperación del archivo; validar importación en una base aislada si se concluye recuperación del ERP.

## F–G. Validación y entrega

1. Verificar alcance firmado y commit previos a cada prueba.
2. Revisar al menos 5 alertas mapeadas, contraste y hallazgo real.
3. Verificar D-01 a D-05, MTTD y acta con tiempo medido.
4. Copiar salidas públicas y capturas numeradas a docs/evidencias/S05; preservar originales y registrar SHA-256, fecha, origen y autor en cadena de custodia.
5. No versionar secretos, datos personales o repositorios de respaldo. Hashear sólo artefactos seleccionados y revisados, excluyendo el propio manifiesto.
6. Crear PR de taller-05 a develop. En este remoto sólo se observó master; acordar/crear develop conforme al flujo del equipo antes de fusionar.
7. Cuando esté completo, crear y publicar etiqueta taller-05 sobre el commit entregado. Cada resultado del informe debe enlazar a un archivo verificable en esa etiqueta.
8. Usar la plantilla Word recibida al final, actualizar índice y exportar SI084-S05-TALLER-Grupo<N>.pdf. Plazo: 48 horas tras sesión. No declarar este borrador como entrega final.
