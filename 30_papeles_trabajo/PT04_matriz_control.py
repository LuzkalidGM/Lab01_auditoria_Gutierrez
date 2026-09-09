from __future__ import annotations

import csv
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path


COLUMNS = [
    "herramienta",
    "tipo",
    "id_hallazgo",
    "severidad",
    "hallazgo",
    "archivo_evidencia",
    "control_iso27001",
    "objetivo_cobit",
    "metodo_clasificacion",
    "observacion",
]


CLASSIFICATION_RULES = [
    (r"running as root|user=root|root user|root access|privileg|capab", "A.8.2 Privileged access rights", "DSS05.04", "regla_inicial:privilegios"),
    (r"password|credential|secret|\bauth(?:entication|orization)?\b|pam_", "A.5.17 Authentication information", "DSS05.04", "regla_inicial:autenticacion"),
    (r"\blog(?:ging|s)?\b|audit|journal|syslog|klogd", "A.8.15 Logging", "DSS01.03", "regla_inicial:registro_auditoria"),
    (r"tls|ssl|cipher|encrypt|certificate", "A.8.24 Use of cryptography", "DSS05.03", "regla_inicial:criptografia"),
    (r"firewall|port|network|expose", "A.8.20 Networks security", "DSS05.02", "regla_inicial:redes"),
    (r"backup|restore", "A.8.13 Information backup", "DSS04.07", "regla_inicial:respaldo"),
    (r"healthcheck|health check|health is checked|monitor", "A.8.16 Monitoring activities", "DSS01.03", "regla_ampliada:monitoreo"),
    (r"permission|ownership|umask|access right", "A.5.15 Access control", "DSS05.04", "regla_ampliada:permisos_acceso"),
    (r"content trust|trusted base image|signed artifact", "A.5.21 Managing information security in the ICT supply chain", "APO10.04", "regla_ampliada:confianza_suministro"),
    (r"memory|cpu|cgroup|resource limit", "A.8.6 Capacity management", "BAI04.01", "regla_ampliada:capacidad"),
    (r"malware|antimalware|virus", "A.8.7 Protection against malware", "DSS05.01", "regla_ampliada:malware"),
    (r"usb|firewire|removable|storage media", "A.7.10 Storage media", "DSS05.06", "regla_ampliada:medios"),
    (r"process accounting|sysstat|accounting", "A.8.15 Logging", "DSS01.03", "regla_ampliada:contabilidad_sistema"),
    (r"update|upgrade|patch|package|apt-get|debsums", "A.8.8 Management of technical vulnerabilities", "DSS05.07", "regla_ampliada:parches_paquetes"),
    (r"filesystem|file system|partition|mount|sysctl", "A.8.9 Configuration management", "BAI10.02", "regla_ampliada:sistema_archivos"),
    (r"apparmor|selinux|seccomp", "A.8.9 Configuration management", "BAI10.02", "regla_ampliada:control_mandatorio"),
    (r"cve-|vulnerab|\boutdated\b|\bversion\b", "A.8.8 Management of technical vulnerabilities", "DSS05.07", "regla_inicial:vulnerabilidades"),
    (r"configur|default|hardening", "A.8.9 Configuration management", "BAI10.02", "regla_inicial:configuracion"),
]


def clean(value: object) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def stable_suffix(*values: str) -> str:
    payload = "|".join(values).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:10]


def classify(row: dict[str, str]) -> None:
    fields = [row["id_hallazgo"], row["hallazgo"], row["tipo"], row["severidad"]]
    if row["herramienta"] != "OpenSCAP":
        fields.append(row["observacion"])
    haystack = " ".join(fields).lower()
    if row["herramienta"] == "Trivy" and "cve-" in haystack:
        row["control_iso27001"] = "A.8.8 Management of technical vulnerabilities"
        row["objetivo_cobit"] = "DSS05.07"
        row["metodo_clasificacion"] = "regla_inicial:vulnerabilidades"
        return
    for pattern, iso, cobit, method in CLASSIFICATION_RULES:
        if re.search(pattern, haystack, flags=re.IGNORECASE):
            row["control_iso27001"] = iso
            row["objetivo_cobit"] = cobit
            row["metodo_clasificacion"] = method
            return
    row["control_iso27001"] = "Sin clasificar"
    row["objetivo_cobit"] = "Sin clasificar"
    row["metodo_clasificacion"] = "sin_coincidencia"


def make_row(**kwargs: str) -> dict[str, str]:
    row = {column: "" for column in COLUMNS}
    row.update(kwargs)
    classify(row)
    return row


def parse_lynis(path: Path, repo_root: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: Counter[str] = Counter()
    pattern = re.compile(r"^(warning|suggestion)\[\]=(.*)$")
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        match = pattern.match(line)
        if not match:
            continue
        kind, payload = match.groups()
        parts = payload.split("|")
        test_id = clean(parts[0])
        message = clean(parts[1] if len(parts) > 1 else "")
        detail = clean(parts[2] if len(parts) > 2 and parts[2] != "-" else "")
        remediation = clean(parts[4] if len(parts) > 4 and parts[4] != "-" else "")
        key = f"{kind}:{test_id}"
        seen[key] += 1
        finding_id = f"LYNIS-{kind.upper()}-{test_id}-{seen[key]}"
        rows.append(
            make_row(
                herramienta="Lynis",
                tipo=kind,
                id_hallazgo=finding_id,
                severidad="WARN" if kind == "warning" else "SUGGESTION",
                hallazgo=f"{test_id}: {message}",
                archivo_evidencia=path.relative_to(repo_root).as_posix(),
                observacion=" | ".join(part for part in (detail, remediation) if part),
            )
        )
    return rows


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def element_text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return clean("".join(element.itertext()))


def direct_children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in element if local_name(child.tag) == name]


def parse_oscap(path: Path, repo_root: Path) -> list[dict[str, str]]:
    root = ET.parse(path).getroot()
    rules = {
        element.attrib.get("id", ""): element
        for element in root.iter()
        if local_name(element.tag) == "Rule"
    }
    test_results = [element for element in root.iter() if local_name(element.tag) == "TestResult"]
    if len(test_results) != 1:
        raise RuntimeError(f"OpenSCAP: se esperaba un TestResult y se encontraron {len(test_results)}")
    rows: list[dict[str, str]] = []
    for result in direct_children(test_results[0], "rule-result"):
        result_node = next(iter(direct_children(result, "result")), None)
        if element_text(result_node).lower() != "fail":
            continue
        rule_id = result.attrib.get("idref", "")
        rule = rules.get(rule_id)
        title = element_text(next(iter(direct_children(rule, "title")), None)) if rule is not None else ""
        severity = result.attrib.get("severity") or (rule.attrib.get("severity", "unknown") if rule is not None else "unknown")
        references: list[str] = []
        if rule is not None:
            for reference in direct_children(rule, "reference"):
                href = clean(reference.attrib.get("href", ""))
                label = element_text(reference)
                references.append(f"{href}: {label}" if href else label)
        rows.append(
            make_row(
                herramienta="OpenSCAP",
                tipo="xccdf_fail",
                id_hallazgo=rule_id,
                severidad=clean(severity).upper(),
                hallazgo=title,
                archivo_evidencia=path.relative_to(repo_root).as_posix(),
                observacion="Referencias: " + (" || ".join(references) if references else "no declaradas"),
            )
        )
    return rows


def parse_docker_bench(path: Path, repo_root: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    control_pattern = re.compile(r"^\[WARN\]\s+(\d+(?:\.\d+)+)\s+-\s+(.*)$")
    detail_pattern = re.compile(r"^\[WARN\]\s+\*\s+(.*)$")
    current: dict[str, str] | None = None
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        control_match = control_pattern.match(line)
        if control_match:
            control_id, description = control_match.groups()
            current = make_row(
                herramienta="Docker Bench",
                tipo="cis_warn",
                id_hallazgo=f"DOCKER-CIS-{control_id}",
                severidad="WARN",
                hallazgo=f"{control_id}: {clean(description)}",
                archivo_evidencia=path.relative_to(repo_root).as_posix(),
                observacion=f"Seccion CIS Docker {control_id.split('.')[0]}",
            )
            rows.append(current)
            continue
        detail_match = detail_pattern.match(line)
        if detail_match and current is not None:
            detail = clean(detail_match.group(1))
            current["observacion"] = clean(f"{current['observacion']} | {detail}")
            classify(current)
            continue
        if re.match(r"^\[(?:PASS|INFO|NOTE|WARN)\]", line):
            current = None
    return rows


def parse_trivy_file(path: Path, repo_root: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    rows: list[dict[str, str]] = []
    artifact = clean(data.get("ArtifactName"))
    relative = path.relative_to(repo_root).as_posix()
    for result in data.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = clean(result.get("Target"))
        for vuln in result.get("Vulnerabilities") or []:
            vuln_id = clean(vuln.get("VulnerabilityID"))
            package = clean(vuln.get("PkgName"))
            installed = clean(vuln.get("InstalledVersion"))
            fixed = clean(vuln.get("FixedVersion"))
            title = clean(vuln.get("Title"))
            suffix = stable_suffix(artifact, target, vuln_id, package, installed)
            fixed_text = fixed if fixed else "no informada"
            rows.append(
                make_row(
                    herramienta="Trivy",
                    tipo="vulnerability",
                    id_hallazgo=f"TRIVY-{vuln_id}-{suffix}",
                    severidad=clean(vuln.get("Severity")).upper(),
                    hallazgo=f"{vuln_id}: {title} | paquete={package} | instalada={installed} | corregida={fixed_text}",
                    archivo_evidencia=relative,
                    observacion=f"Imagen: {artifact} | Objetivo: {target} | Estado: {clean(vuln.get('Status'))}",
                )
            )
        for misconfig in result.get("Misconfigurations") or []:
            check_id = clean(misconfig.get("ID"))
            title = clean(misconfig.get("Title"))
            rows.append(
                make_row(
                    herramienta="Trivy",
                    tipo="misconfiguration",
                    id_hallazgo=f"TRIVY-IAC-{check_id}-{stable_suffix(artifact, target, check_id)}",
                    severidad=clean(misconfig.get("Severity")).upper(),
                    hallazgo=f"{check_id}: {title}",
                    archivo_evidencia=relative,
                    observacion=f"Objetivo: {target} | Estado: {clean(misconfig.get('Status'))}",
                )
            )
        for secret in result.get("Secrets") or []:
            rule_id = clean(secret.get("RuleID"))
            rows.append(
                make_row(
                    herramienta="Trivy",
                    tipo="secret",
                    id_hallazgo=f"TRIVY-SECRET-{rule_id}-{stable_suffix(target, rule_id, clean(secret.get('StartLine')))}",
                    severidad=clean(secret.get("Severity")).upper(),
                    hallazgo=f"{rule_id}: {clean(secret.get('Title'))} | valor=[REDACTED]",
                    archivo_evidencia=relative,
                    observacion=f"Archivo: {target} | Lineas: {clean(secret.get('StartLine'))}-{clean(secret.get('EndLine'))}",
                )
            )
    return rows


def load_manual_classifications(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    return {clean(row.get("id_hallazgo")): row for row in rows if clean(row.get("id_hallazgo"))}


def apply_manual_classifications(rows: list[dict[str, str]], manual: dict[str, dict[str, str]]) -> None:
    for row in rows:
        override = manual.get(row["id_hallazgo"])
        if not override:
            continue
        iso = clean(override.get("control_iso27001"))
        cobit = clean(override.get("objetivo_cobit"))
        if not iso or not cobit:
            continue
        row["control_iso27001"] = iso
        row["objetivo_cobit"] = cobit
        row["metodo_clasificacion"] = "manual"
        note = clean(override.get("observacion"))
        if note:
            row["observacion"] = clean(f"{row['observacion']} | Clasificacion manual: {note}")


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def validation_lines(rows: list[dict[str, str]]) -> list[str]:
    unclassified = [row for row in rows if row["control_iso27001"] == "Sin clasificar"]
    percentage = (len(unclassified) / len(rows) * 100) if rows else 0.0
    lines = [
        f"Total de hallazgos: {len(rows)}",
        "Hallazgos por herramienta:",
    ]
    for name, count in sorted(Counter(row["herramienta"] for row in rows).items()):
        lines.append(f"  - {name}: {count}")
    lines.append("Hallazgos por severidad:")
    for name, count in sorted(Counter(row["severidad"] for row in rows).items()):
        lines.append(f"  - {name}: {count}")
    lines.append("Hallazgos por control ISO:")
    for name, count in Counter(row["control_iso27001"] for row in rows).most_common():
        lines.append(f"  - {name}: {count}")
    lines.extend(
        [
            f"Cantidad sin clasificar: {len(unclassified)}",
            f"Porcentaje sin clasificar: {percentage:.2f}%",
            f"Meta menor a 20%: {'CUMPLIDA' if percentage < 20 else 'NO CUMPLIDA'}",
        ]
    )
    return lines


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    evidence = repo_root / "20_evidencia" / "E04_config"
    output_dir = repo_root / "40_hallazgos"
    required = [
        evidence / "lynis-report.dat",
        evidence / "oscap-resultados.xml",
        evidence / "docker-bench.log",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError("Faltan fuentes obligatorias: " + ", ".join(missing))

    rows: list[dict[str, str]] = []
    rows.extend(parse_lynis(required[0], repo_root))
    rows.extend(parse_oscap(required[1], repo_root))
    rows.extend(parse_docker_bench(required[2], repo_root))
    trivy_files = sorted(evidence.glob("trivy_*.json"))
    if not trivy_files:
        raise FileNotFoundError("No se encontraron archivos trivy_*.json")
    for path in trivy_files:
        rows.extend(parse_trivy_file(path, repo_root))

    manual_path = output_dir / "PT04_clasificacion_manual.csv"
    apply_manual_classifications(rows, load_manual_classifications(manual_path))
    rows.sort(key=lambda row: (row["herramienta"], row["id_hallazgo"], row["archivo_evidencia"]))

    ids = [row["id_hallazgo"] for row in rows]
    duplicates = [item for item, count in Counter(ids).items() if count > 1]
    if duplicates:
        raise RuntimeError("IDs de hallazgo duplicados: " + ", ".join(duplicates[:10]))

    matrix_path = output_dir / "PT04_matriz_control.csv"
    write_csv(matrix_path, rows)
    lines = validation_lines(rows)
    validation_path = output_dir / "PT04_validacion.txt"
    validation_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    unclassified = [row for row in rows if row["control_iso27001"] == "Sin clasificar"]
    percentage = (len(unclassified) / len(rows) * 100) if rows else 0.0
    if percentage >= 20:
        write_csv(output_dir / "PT04_pendientes_clasificacion.csv", unclassified)

    print("\n".join(lines))
    print(f"Matriz: {matrix_path.relative_to(repo_root).as_posix()}")
    print(f"Clasificacion manual opcional: {manual_path.relative_to(repo_root).as_posix()}")


if __name__ == "__main__":
    main()
