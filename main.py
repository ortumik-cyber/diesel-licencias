"""
DIESEL LICENCIAS — Servidor de verificación de licencias
FastAPI + JWT + Firestore REST API (sin Admin SDK)
"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt
import secrets
import os
import json
import httpx
from datetime import datetime, timedelta
from typing import Optional

# ── Configuración ─────────────────────────────────────────────
JWT_SECRET    = os.environ.get("JWT_SECRET", "diesel-dev-secret-2024")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_H  = 24
ADMIN_KEY     = os.environ.get("ADMIN_KEY", "diesel-admin-2024")
# Firebase REST API — no necesita Admin SDK
FIREBASE_API_KEY  = os.environ.get("FIREBASE_API_KEY", "")
FIREBASE_PROJECT  = os.environ.get("FIREBASE_PROJECT", "diesel-licencias")
FIRESTORE_URL     = f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT}/databases/(default)/documents"

app = FastAPI(title="Diesel Licencias API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://ortumik-cyber.github.io",
        "http://localhost",
        "http://127.0.0.1",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Firestore REST helpers ─────────────────────────────────────
def fs_url(collection: str, doc: str = "") -> str:
    base = f"{FIRESTORE_URL}/{collection}"
    return f"{base}/{doc}" if doc else base

def fs_params() -> dict:
    return {"key": FIREBASE_API_KEY} if FIREBASE_API_KEY else {}

def to_fs(data: dict) -> dict:
    """Convierte dict Python a formato Firestore fields"""
    fields = {}
    for k, v in data.items():
        if v is None:
            fields[k] = {"nullValue": None}
        elif isinstance(v, bool):
            fields[k] = {"booleanValue": v}
        elif isinstance(v, int):
            fields[k] = {"integerValue": str(v)}
        elif isinstance(v, float):
            fields[k] = {"doubleValue": v}
        elif isinstance(v, list):
            fields[k] = {"arrayValue": {"values": [{"stringValue": str(i)} for i in v]}}
        else:
            fields[k] = {"stringValue": str(v)}
    return {"fields": fields}

def from_fs(doc: dict) -> dict:
    """Convierte respuesta Firestore a dict Python"""
    fields = doc.get("fields", {})
    result = {}
    for k, v in fields.items():
        if "stringValue" in v:
            result[k] = v["stringValue"]
        elif "booleanValue" in v:
            result[k] = v["booleanValue"]
        elif "integerValue" in v:
            result[k] = int(v["integerValue"])
        elif "doubleValue" in v:
            result[k] = v["doubleValue"]
        elif "nullValue" in v:
            result[k] = None
        elif "arrayValue" in v:
            result[k] = [i.get("stringValue", "") for i in v["arrayValue"].get("values", [])]
        else:
            result[k] = str(v)
    # Extraer ID del documento del nombre
    name = doc.get("name", "")
    if name:
        result["_id"] = name.split("/")[-1]
    return result

async def fs_get(collection: str, doc_id: str) -> Optional[dict]:
    async with httpx.AsyncClient() as client:
        r = await client.get(fs_url(collection, doc_id), params=fs_params())
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return from_fs(r.json())

async def fs_set(collection: str, doc_id: str, data: dict) -> dict:
    async with httpx.AsyncClient() as client:
        r = await client.patch(
            fs_url(collection, doc_id),
            params=fs_params(),
            json=to_fs(data)
        )
        r.raise_for_status()
        return from_fs(r.json())

async def fs_update(collection: str, doc_id: str, data: dict) -> dict:
    """Actualización parcial usando updateMask"""
    fields_mask = list(data.keys())
    params = dict(fs_params())
    for f in fields_mask:
        params[f"updateMask.fieldPaths"] = f
    # httpx no soporta múltiples valores con la misma key fácilmente — usar URL manual
    mask_str = "&".join([f"updateMask.fieldPaths={f}" for f in fields_mask])
    url = fs_url(collection, doc_id) + "?" + mask_str
    if FIREBASE_API_KEY:
        url += f"&key={FIREBASE_API_KEY}"
    async with httpx.AsyncClient() as client:
        r = await client.patch(url, json=to_fs(data))
        r.raise_for_status()
        return from_fs(r.json())

async def fs_delete(collection: str, doc_id: str):
    async with httpx.AsyncClient() as client:
        r = await client.delete(fs_url(collection, doc_id), params=fs_params())
        r.raise_for_status()

async def fs_list(collection: str) -> list:
    async with httpx.AsyncClient() as client:
        r = await client.get(fs_url(collection), params=fs_params())
        r.raise_for_status()
        docs = r.json().get("documents", [])
        return [from_fs(d) for d in docs]

# ── Utils ─────────────────────────────────────────────────────
def verificar_admin(admin_key: str):
    if admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Clave de administrador incorrecta")

def generar_codigo() -> str:
    parte = lambda: secrets.token_hex(2).upper()
    return f"DIESEL-{parte()}-{parte()}-{parte()}"

def crear_jwt(payload: dict) -> str:
    data = payload.copy()
    data["exp"] = datetime.utcnow() + timedelta(hours=JWT_EXPIRE_H)
    return jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)

def normalizar_dominio(d: str) -> str:
    d = d.lower().strip()
    d = d.replace("https://", "").replace("http://", "")
    return d.rstrip("/")

# ── Modelos ───────────────────────────────────────────────────
class VerificarRequest(BaseModel):
    licencia: str
    dominio: str

class CrearRequest(BaseModel):
    admin_key: str
    cliente_nombre: str
    cliente_email: str
    dominio: str
    max_profesores: int = 5
    max_alumnos: int = 200
    dias_validez: int = 365
    modulos: list = ["calendario", "firmas", "dashboard", "whatsapp", "onedrive"]

class ActualizarRequest(BaseModel):
    admin_key: str
    activa: Optional[bool] = None
    dias_validez: Optional[int] = None
    max_profesores: Optional[int] = None
    max_alumnos: Optional[int] = None

# ── Endpoints ─────────────────────────────────────────────────
@app.get("/")
def health():
    return {"status": "ok", "servicio": "Diesel Licencias API", "version": "1.0.0"}

@app.post("/verificar")
async def verificar(req: VerificarRequest, request: Request):
    codigo = req.licencia.strip().upper()
    dominio_cliente = normalizar_dominio(req.dominio)

    lic = await fs_get("licencias", codigo)
    if not lic:
        raise HTTPException(status_code=403, detail="Licencia no encontrada")

    if not lic.get("activa", False):
        raise HTTPException(status_code=403, detail="Licencia desactivada")

    expira = lic.get("expira_en")
    if expira and datetime.utcnow() > datetime.fromisoformat(expira):
        raise HTTPException(status_code=403, detail="Licencia caducada")

    dominio_reg = normalizar_dominio(lic.get("dominio", ""))
    if dominio_reg and dominio_cliente != dominio_reg:
        raise HTTPException(status_code=403, detail="Dominio no autorizado")

    # Registrar acceso
    try:
        await fs_update("licencias", codigo, {
            "ultimo_acceso": datetime.utcnow().isoformat(),
            "ultimo_ip": request.client.host if request.client else "unknown"
        })
    except:
        pass

    token = crear_jwt({
        "licencia": codigo,
        "cliente": lic.get("cliente_nombre", ""),
        "autoescuela_nombre": lic.get("autoescuela_nombre", lic.get("cliente_nombre", "Autoescuela")),
        "dominio": dominio_reg,
        "max_profesores": lic.get("max_profesores", 5),
        "max_alumnos": lic.get("max_alumnos", 200),
        "modulos": lic.get("modulos", []),
    })

    return {
        "ok": True,
        "token": token,
        "cliente": lic.get("cliente_nombre"),
        "autoescuela_nombre": lic.get("autoescuela_nombre", lic.get("cliente_nombre", "Autoescuela")),
        "expira_en": expira,
        "max_profesores": lic.get("max_profesores", 5),
        "max_alumnos": lic.get("max_alumnos", 200),
        "modulos": lic.get("modulos", []),
    }

@app.post("/admin/crear")
async def crear(req: CrearRequest):
    verificar_admin(req.admin_key)
    codigo = generar_codigo()
    expira = (datetime.utcnow() + timedelta(days=req.dias_validez)).isoformat()
    doc = {
        "codigo": codigo,
        "cliente_nombre": req.cliente_nombre,
        "cliente_email": req.cliente_email,
        "autoescuela_nombre": req.cliente_nombre,
        "dominio": normalizar_dominio(req.dominio),
        "max_profesores": req.max_profesores,
        "max_alumnos": req.max_alumnos,
        "modulos": req.modulos,
        "activa": True,
        "creada_en": datetime.utcnow().isoformat(),
        "expira_en": expira,
        "accesos_totales": 0,
        "ultimo_acceso": "",
    }
    await fs_set("licencias", codigo, doc)
    return {"ok": True, "codigo": codigo, "expira_en": expira}

@app.get("/admin/listar")
async def listar(admin_key: str):
    verificar_admin(admin_key)
    docs = await fs_list("licencias")
    docs.sort(key=lambda x: (not x.get("activa", False), x.get("cliente_nombre", "")))
    return {"ok": True, "total": len(docs), "licencias": docs}

@app.put("/admin/licencia/{codigo}")
async def actualizar(codigo: str, req: ActualizarRequest):
    verificar_admin(req.admin_key)
    update = {}
    if req.activa is not None:
        update["activa"] = req.activa
    if req.dias_validez is not None:
        update["expira_en"] = (datetime.utcnow() + timedelta(days=req.dias_validez)).isoformat()
    if req.max_profesores is not None:
        update["max_profesores"] = req.max_profesores
    if req.max_alumnos is not None:
        update["max_alumnos"] = req.max_alumnos
    if not update:
        raise HTTPException(status_code=400, detail="Nada que actualizar")
    await fs_update("licencias", codigo.upper(), update)
    return {"ok": True, "codigo": codigo.upper(), "actualizado": update}

@app.delete("/admin/licencia/{codigo}")
async def eliminar(codigo: str, admin_key: str):
    verificar_admin(admin_key)
    await fs_delete("licencias", codigo.upper())
    return {"ok": True, "mensaje": f"Licencia {codigo.upper()} eliminada"}
