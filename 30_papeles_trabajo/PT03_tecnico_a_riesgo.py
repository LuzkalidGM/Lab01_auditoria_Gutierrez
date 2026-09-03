import pandas as pd
from pathlib import Path

# ============================================================
# TALLER 03 - Conversión de hallazgos técnicos a riesgos
# ============================================================

BASE = Path(__file__).resolve().parent.parent

CSV_NO_AUTH = BASE / "20_evidencia" / "E03_scan" / "reporte_greenbone.csv"
CSV_AUTH = BASE / "20_evidencia" / "E03_scan" / "reporte_greenbone_autenticado.csv"
SALIDA = BASE / "40_hallazgos" / "PT03_registro_riesgos.csv"

# ------------------------------------------------------------
# 1. Cargar evidencia técnica
# ------------------------------------------------------------

noauth = pd.read_csv(CSV_NO_AUTH)
auth = pd.read_csv(CSV_AUTH)

noauth["tipo_escaneo"] = "No autenticado"
auth["tipo_escaneo"] = "Autenticado"

v = pd.concat([noauth, auth], ignore_index=True)

# Greenbone actual exporta:
# - CVSS     -> valor numérico
# - Severity -> Critical / Medium / Low, etc.
v["CVSS"] = pd.to_numeric(v["CVSS"], errors="coerce").fillna(0)

# Se descartan solamente resultados informativos/log.
# En esta ejecución real existen únicamente 2 hallazgos con CVSS >= 4,
# por lo que conservar solo esos impediría alcanzar los 10 riesgos
# solicitados por la guía.
v = v[v["CVSS"] > 0].copy()

# ------------------------------------------------------------
# 2. Normalizar hostname
# ------------------------------------------------------------

v["host"] = (
    v["Hostname"]
    .fillna("")
    .astype(str)
    .str.strip()
    .str.split(".")
    .str[0]
)

# El mismo hallazgo puede aparecer en ambos escaneos.
v = (
    v.sort_values("CVSS", ascending=False)
     .drop_duplicates(
         subset=["host", "NVT Name", "CVSS"],
         keep="first"
     )
)

# ------------------------------------------------------------
# 3. Contexto de negocio
# ------------------------------------------------------------

ACTIVOS = {
    "si084_db": dict(
        nombre="Base de datos ERP",
        dueno="dueno_finanzas",
        clasificacion="Restringida",
        expuesto=False,
        criticidad=5
    ),

    "si084_juiceshop": dict(
        nombre="Portal de clientes",
        dueno="dueno_ti",
        clasificacion="Confidencial",
        expuesto=True,
        criticidad=4
    ),

    "si084_portal": dict(
        nombre="Portal corporativo",
        dueno="dueno_ti",
        clasificacion="Pública",
        expuesto=True,
        criticidad=2
    ),

    "si084_dvwa": dict(
        nombre="Aplicación legada interna",
        dueno="dueno_operaciones",
        clasificacion="Interna",
        expuesto=False,
        criticidad=3
    ),
}

# ------------------------------------------------------------
# 4. Funciones de valoración
# ------------------------------------------------------------

def probabilidad(cvss, expuesto):
    """
    Probabilidad técnica basada en CVSS.
    La exposición incrementa un nivel la probabilidad.
    """
    base = (
        1 if cvss < 4
        else 2 if cvss < 7
        else 3 if cvss < 9
        else 4
    )

    return min(5, base + (1 if expuesto else 0))


def impacto(criticidad, clasificacion):
    """
    El impacto depende del valor del activo y su clasificación.
    """
    extra = {
        "Restringida": 1,
        "Confidencial": 0,
        "Interna": 0,
        "Pública": -1
    }

    return max(
        1,
        min(
            5,
            criticidad + extra.get(clasificacion, 0)
        )
    )


def nivel_riesgo(valor):
    if valor >= 20:
        return "Crítico"
    elif valor >= 12:
        return "Alto"
    elif valor >= 6:
        return "Medio"
    else:
        return "Bajo"


# ------------------------------------------------------------
# 5. Convertir hallazgos a riesgos
# ------------------------------------------------------------

filas = []

for _, r in v.iterrows():

    host = r["host"]
    activo = ACTIVOS.get(host)

    if activo is None:
        continue

    cvss = float(r["CVSS"])

    p = probabilidad(
        cvss,
        activo["expuesto"]
    )

    i = impacto(
        activo["criticidad"],
        activo["clasificacion"]
    )

    riesgo = p * i

    cve = r.get("CVEs", "")

    if pd.isna(cve) or str(cve).strip() == "":
        cve = "N/D"

    filas.append({
        "id_riesgo": f"R-{len(filas)+1:03d}",
        "host": host,
        "activo": activo["nombre"],
        "dueno_del_riesgo": activo["dueno"],
        "clasificacion": activo["clasificacion"],
        "amenaza": "Explotación de vulnerabilidad técnica identificada",
        "vulnerabilidad": r["NVT Name"],
        "cve": cve,
        "cvss": cvss,
        "severidad_tecnica": r["Severity"],
        "probabilidad": p,
        "impacto": i,
        "riesgo_inherente": riesgo,
        "nivel": nivel_riesgo(riesgo),
        "tipo_escaneo": r["tipo_escaneo"]
    })


# ------------------------------------------------------------
# 6. Registro final
# ------------------------------------------------------------

reg = pd.DataFrame(filas)

if reg.empty:
    raise RuntimeError(
        "No se generaron riesgos. Revise los hostnames del CSV."
    )

reg = reg.sort_values(
    ["riesgo_inherente", "cvss"],
    ascending=[False, False]
)

reg.to_csv(
    SALIDA,
    index=False,
    encoding="utf-8-sig"
)

print("\n=== REGISTRO DE RIESGOS ===\n")
print(reg.to_string(index=False))

print("\n=== TOTAL DE RIESGOS ===")
print(len(reg))

print("\n=== DISTRIBUCIÓN POR NIVEL ===")
print(reg["nivel"].value_counts().to_string())

print("\nArchivo generado:")
print(SALIDA)