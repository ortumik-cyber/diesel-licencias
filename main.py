"""
DIESEL LICENCIAS — Servidor de verificación de licencias
FastAPI + JWT + Firestore
"""
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt
import hashlib
import secrets
import os
import json
from datetime import datetime, timedelta
from typing import Optional
import firebase_admin
from firebase_admin import credentials, firestore

# ── Inicializar Firebase ──────────────────────────────────────
cred_json = os.environ.get("FIREBASE_CREDENTIALS")
if cred_json:
    cred_dict = json.loads(cred_json)
    cred = credentials.Certificate(cred_dict)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
else:
    db = None
    print("⚠️  Sin Firebase — modo desarrollo")

# ── Configuración ─────────────────────────────────────────────
JWT_SECRET     = os.environ.get("JWT_SECRET", "diesel-licencias-secret-dev")
JWT_ALGORITHM  = "HS256"
JWT_EXPIRE_H   = 24  # horas
ADMIN_KEY      = os.environ.get("ADMIN_KEY", "diesel-admin-2024")  # clave para el panel

app = FastAPI(title="Diesel Licencias API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # El dominio se verifica dentro de cada endpoint
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

# ── Modelos ───────────────────────────────────────────────────
class VerificarRequest(BaseModel):
    licencia: str
    dominio: str
    fingerprint: Optional[str] = None

class CrearLicenciaRequest(BaseModel):
    admin_key: str
    cliente_nombre: str
    cliente_email: str
    dominio: str              # ej: ortumik-cyber.github.io/diesel-cliente1
    max_profesores: int = 5
    max_alumnos: int = 200
    dias_validez: int = 365
    modulos: list = ["calendario", "firmas", "dashboard", "whatsapp", "onedrive"]

class ActualizarLicenciaRequest(BaseModel):
    admin_key: str
    activa: Optional[bool] = None
    dias_validez: Optional[int] = None
    max_profesores: Optional[int] = None
    max_alumnos: Optional[int] = None

class ListarRequest(BaseModel):
    admin_key: str

# ── Utils ─────────────────────────────────────────────────────
def verificar_admin(admin_key: str):
    if admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Clave de administrador incorrecta")

def generar_codigo_licencia() -> str:
    """Genera código tipo DIESEL-XXXX-XXXX-XXXX"""
    parte = lambda: secrets.token_hex(2).upper()
    return f"DIESEL-{parte()}-{parte()}-{parte()}"

def crear_jwt(payload: dict) -> str:
    data = payload.copy()
    data["exp"] = datetime.utcnow() + timedelta(hours=JWT_EXPIRE_H)
    data["iat"] = datetime.utcnow().isoformat()
    return jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verificar_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

def normalizar_dominio(dominio: str) -> str:
    """Quita protocolo y trailing slash para comparación"""
    d = dominio.lower().strip()
    d = d.replace("https://", "").replace("http://", "")
    d = d.rstrip("/")
    return d

def get_licencia_doc(codigo: str):
    if not db:
        raise HTTPException(status_code=503, detail="Base de datos no disponible")
    doc = db.collection("licencias").document(codigo).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")
    return doc

# ── Endpoints públicos ────────────────────────────────────────

@app.get("/")
def health():
    return {"status": "ok", "servicio": "Diesel Licencias API", "version": "1.0.0"}

@app.post("/verificar")
async def verificar_licencia(req: VerificarRequest, request: Request):
    """
    La app llama a este endpoint al arrancar.
    Devuelve un JWT válido 24h si la licencia es correcta.
    """
    codigo = req.licencia.strip().upper()
    dominio_cliente = normalizar_dominio(req.dominio)

    try:
        doc = get_licencia_doc(codigo)
    except HTTPException:
        raise HTTPException(status_code=403, detail="Licencia inválida")

    lic = doc.to_dict()

    # 1. ¿Activa?
    if not lic.get("activa", False):
        raise HTTPException(status_code=403, detail="Licencia desactivada")

    # 2. ¿Caducada?
    expiry = lic.get("expira_en")
    if expiry:
        if isinstance(expiry, str):
            expiry_dt = datetime.fromisoformat(expiry)
        else:
            expiry_dt = expiry  # Firestore Timestamp
        if datetime.utcnow() > expiry_dt.replace(tzinfo=None):
            raise HTTPException(status_code=403, detail="Licencia caducada")

    # 3. ¿Dominio autorizado?
    dominio_registrado = normalizar_dominio(lic.get("dominio", ""))
    if dominio_registrado and dominio_cliente != dominio_registrado:
        # Log del intento
        print(f"⚠️  Dominio no autorizado: {dominio_cliente} (esperado: {dominio_registrado})")
        raise HTTPException(status_code=403, detail="Dominio no autorizado para esta licencia")

    # 4. Registrar uso
    db.collection("licencias").document(codigo).update({
        "ultimo_acceso": datetime.utcnow().isoformat(),
        "ultimo_ip": request.client.host if request.client else "unknown",
        "accesos_totales": firestore.Increment(1)
    })

    # 5. Generar JWT con los permisos de la licencia
    token = crear_jwt({
        "licencia": codigo,
        "cliente": lic.get("cliente_nombre", ""),
        "dominio": dominio_registrado,
        "max_profesores": lic.get("max_profesores", 5),
        "max_alumnos": lic.get("max_alumnos", 200),
        "modulos": lic.get("modulos", []),
        "autoescuela_nombre": lic.get("autoescuela_nombre", "Autoescuela")
    })

    return {
        "ok": True,
        "token": token,
        "cliente": lic.get("cliente_nombre"),
        "autoescuela_nombre": lic.get("autoescuela_nombre", "Autoescuela"),
        "expira_en": lic.get("expira_en"),
        "max_profesores": lic.get("max_profesores", 5),
        "max_alumnos": lic.get("max_alumnos", 200),
        "modulos": lic.get("modulos", [])
    }

# ── Endpoints de administración ───────────────────────────────

@app.post("/admin/crear")
async def crear_licencia(req: CrearLicenciaRequest):
    verificar_admin(req.admin_key)
    if not db:
        raise HTTPException(status_code=503, detail="Base de datos no disponible")

    codigo = generar_codigo_licencia()
    expira = datetime.utcnow() + timedelta(days=req.dias_validez)

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
        "expira_en": expira.isoformat(),
        "accesos_totales": 0,
        "ultimo_acceso": None,
    }

    db.collection("licencias").document(codigo).set(doc)

    return {
        "ok": True,
        "codigo": codigo,
        "cliente": req.cliente_nombre,
        "dominio": req.dominio,
        "expira_en": expira.isoformat(),
        "mensaje": f"Licencia creada: {codigo}"
    }

@app.get("/admin/listar")
async def listar_licencias(admin_key: str):
    verificar_admin(admin_key)
    if not db:
        raise HTTPException(status_code=503, detail="Base de datos no disponible")

    docs = db.collection("licencias").stream()
    licencias = []
    for doc in docs:
        d = doc.to_dict()
        # No exponer datos sensibles innecesarios
        licencias.append({
            "codigo": d.get("codigo"),
            "cliente_nombre": d.get("cliente_nombre"),
            "cliente_email": d.get("cliente_email"),
            "dominio": d.get("dominio"),
            "activa": d.get("activa"),
            "expira_en": d.get("expira_en"),
            "accesos_totales": d.get("accesos_totales", 0),
            "ultimo_acceso": d.get("ultimo_acceso"),
            "max_profesores": d.get("max_profesores"),
            "max_alumnos": d.get("max_alumnos"),
        })

    # Ordenar: activas primero, luego por nombre
    licencias.sort(key=lambda x: (not x["activa"], x["cliente_nombre"] or ""))
    return {"ok": True, "total": len(licencias), "licencias": licencias}

@app.put("/admin/licencia/{codigo}")
async def actualizar_licencia(codigo: str, req: ActualizarLicenciaRequest):
    verificar_admin(req.admin_key)
    doc = get_licencia_doc(codigo.upper())

    update = {}
    if req.activa is not None:
        update["activa"] = req.activa
    if req.dias_validez is not None:
        nueva_expira = datetime.utcnow() + timedelta(days=req.dias_validez)
        update["expira_en"] = nueva_expira.isoformat()
    if req.max_profesores is not None:
        update["max_profesores"] = req.max_profesores
    if req.max_alumnos is not None:
        update["max_alumnos"] = req.max_alumnos

    if not update:
        raise HTTPException(status_code=400, detail="Nada que actualizar")

    update["modificada_en"] = datetime.utcnow().isoformat()
    db.collection("licencias").document(codigo.upper()).update(update)

    return {"ok": True, "codigo": codigo.upper(), "actualizado": update}

@app.delete("/admin/licencia/{codigo}")
async def eliminar_licencia(codigo: str, admin_key: str):
    verificar_admin(admin_key)
    get_licencia_doc(codigo.upper())  # verifica que existe
    db.collection("licencias").document(codigo.upper()).delete()
    return {"ok": True, "mensaje": f"Licencia {codigo.upper()} eliminada"}
