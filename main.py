import os
import json
import secrets
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import HTMLResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import httpx

from database import (
    init_db,
    get_db_connection,
    hash_password,
    verify_password,
    register_user_email,
    authenticate_email_password,
    purge_guest_user_data
)
from ai_engine import CASOS_EJEMPLO, analizar_caso_ia, get_groq_api_key
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Observatorio de Normatividad IA y Derechos Humanos")

# Configuración CORS permisiva incluyendo cabecera de bypass para ngrok
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "ngrok-skip-browser-warning"],
    expose_headers=["*", "ngrok-skip-browser-warning"]
)

@app.middleware("http")
async def add_ngrok_skip_header(request, call_next):
    response = await call_next(request)
    response.headers["ngrok-skip-browser-warning"] = "true"
    return response

init_db()

# ==============================================================================
# GESTIÓN DE SESIONES Y CONTROL ESTRICTO DE CONCURRENCIA (MÁXIMO 30 USUARIOS)
# ==============================================================================
MAX_CONCURRENT_USERS = 30
ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}

SERVER_CONFIG = {
    "groq_api_key": get_groq_api_key(),
    "allowed_domains": ".edu.mx,.ipn.mx,.unam.mx,.uaemex.mx,.tecnm.mx,.uam.mx,gmail.com,outlook.com,hotmail.com,yahoo.com",
    "smtp_host": os.getenv("SMTP_HOST", "smtp.gmail.com"),
    "smtp_port": int(os.getenv("SMTP_PORT", "587")),
    "smtp_user": os.getenv("SMTP_USER", ""),
    "smtp_pass": os.getenv("SMTP_PASS", "")
}

def clean_expired_sessions():
    """Elimina sesiones inactivas por más de 60 minutos para liberar cupo."""
    now = datetime.now()
    tokens_to_remove = []
    for token, sess in ACTIVE_SESSIONS.items():
        last_act = sess.get("last_activity", now)
        if (now - last_act) > timedelta(minutes=60):
            tokens_to_remove.append(token)

    for tok in tokens_to_remove:
        sess = ACTIVE_SESSIONS.pop(tok, None)
        if sess and sess.get("is_guest"):
            purge_guest_user_data(sess.get("username", ""))

def enforce_concurrency_limit():
    """Verifica que no se sobrepase el límite de 30 usuarios simultáneos."""
    clean_expired_sessions()
    if len(ACTIVE_SESSIONS) >= MAX_CONCURRENT_USERS:
        raise HTTPException(
            status_code=429,
            detail=f"Capacidad máxima alcanzada: El observatorio admite un límite estricto de {MAX_CONCURRENT_USERS} usuarios simultáneos. Por favor, intenta de nuevo en unos momentos."
        )

# ==============================================================================
# MODELOS PYDANTIC
# ==============================================================================
class LoginRequest(BaseModel):
    username: str
    password: str

class EmailLoginRequest(BaseModel):
    email: str
    password: str

class EmailRegisterRequest(BaseModel):
    full_name: str
    email: str
    password: str

class OTPRequest(BaseModel):
    institutional_email: str

class OTPVerifyRequest(BaseModel):
    institutional_email: str
    code: str

class CreateUserRequest(BaseModel):
    username: str
    full_name: str
    institutional_email: str
    password: str
    role: str = "usuario"

class ServerConfigRequest(BaseModel):
    allowed_domains: Optional[str] = None
    smtp_user: Optional[str] = None
    smtp_pass: Optional[str] = None

class EvaluateRequest(BaseModel):
    descripcion: Optional[str] = None
    caso_hechos: Optional[str] = None
    titulo: Optional[str] = None
    modo: str = "inferencia"  # "inferencia", "local", "nube", "keywords", "api"
    local_url: Optional[str] = "http://localhost:11434/v1/chat/completions"
    local_model: Optional[str] = "qwen2.5:7b"

# ==============================================================================
# AUTENTICACIÓN Y CONTROL DE ACCESO
# ==============================================================================
def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Sesión no iniciada o token inválido.")
    token = authorization.split(" ")[1]
    clean_expired_sessions()
    user = ACTIVE_SESSIONS.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Tu sesión ha expirado o fue cerrada. Vuelve a ingresar.")
    user["last_activity"] = datetime.now()
    return user

# ==============================================================================
# RUTAS DE INTERFAZ WEB
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/styles.css")
async def serve_css():
    if os.path.exists("styles.css"):
        return FileResponse("styles.css", media_type="text/css")
    return Response(content="/* styles.css fallback */", media_type="text/css")

@app.get("/favicon.ico")
@app.get("/img/favicon.ico")
async def serve_favicon():
    if os.path.exists("Lawfice/img/favicon.ico"):
        return FileResponse("Lawfice/img/favicon.ico", media_type="image/x-icon")
    return Response(status_code=204)

# Montaje de recursos estáticos de la plantilla Lawfice
if os.path.exists("Lawfice"):
    if os.path.exists("Lawfice/css"):
        app.mount("/css", StaticFiles(directory="Lawfice/css"), name="css")
    if os.path.exists("Lawfice/js"):
        app.mount("/js", StaticFiles(directory="Lawfice/js"), name="js")
    if os.path.exists("Lawfice/img"):
        app.mount("/img", StaticFiles(directory="Lawfice/img"), name="img")
    if os.path.exists("Lawfice/lib"):
        app.mount("/lib", StaticFiles(directory="Lawfice/lib"), name="lib")

# ==============================================================================
# RUTAS DE AUTENTICACIÓN
# ==============================================================================

# 1. Inicio de Sesión y Registro con Correo y Contraseña (Directo, sin OTP)
@app.post("/api/auth/email-login")
async def email_password_login(data: EmailLoginRequest):
    enforce_concurrency_limit()
    email = data.email.strip().lower()
    if "@" not in email or "." not in email:
        raise HTTPException(status_code=400, detail="Ingresa un correo electrónico válido.")

    user = authenticate_email_password(email, data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Correo o contraseña incorrectos. Si aún no te has registrado, crea tu cuenta abajo."
        )

    if not user.get("is_active", 1):
        raise HTTPException(status_code=403, detail="Tu cuenta está suspendida. Consulta con el Administrador.")

    token = secrets.token_hex(24)
    session_data = {
        "id": user["id"],
        "username": user["username"],
        "full_name": user["full_name"],
        "institutional_email": user["institutional_email"],
        "role": user["role"],
        "is_guest": False,
        "last_activity": datetime.now()
    }
    ACTIVE_SESSIONS[token] = session_data

    return {
        "token": token,
        "user": session_data,
        "active_users": len(ACTIVE_SESSIONS),
        "max_users": MAX_CONCURRENT_USERS
    }

@app.post("/api/auth/email-register")
async def email_password_register(data: EmailRegisterRequest):
    enforce_concurrency_limit()
    email = data.email.strip().lower()
    if "@" not in email or "." not in email:
        raise HTTPException(status_code=400, detail="Ingresa un correo electrónico válido.")
    if len(data.password.strip()) < 4:
        raise HTTPException(status_code=400, detail="La contraseña debe tener al menos 4 caracteres.")

    try:
        user = register_user_email(data.full_name, email, data.password)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    token = secrets.token_hex(24)
    session_data = {
        "id": user["id"],
        "username": user["username"],
        "full_name": user["full_name"],
        "institutional_email": user["institutional_email"],
        "role": user["role"],
        "is_guest": False,
        "last_activity": datetime.now()
    }
    ACTIVE_SESSIONS[token] = session_data

    return {
        "token": token,
        "user": session_data,
        "active_users": len(ACTIVE_SESSIONS),
        "max_users": MAX_CONCURRENT_USERS
    }

# 2. Usuario Local / Invitado Temporal (Sin persistencia, se destruye al cerrar sesión)
@app.post("/api/auth/local-guest")
async def login_local_guest():
    enforce_concurrency_limit()
    guest_suffix = secrets.token_hex(3)
    username = f"invitado_{guest_suffix}"
    full_name = f"Usuario Local Temporal ({guest_suffix})"

    token = secrets.token_hex(24)
    session_data = {
        "id": None,
        "username": username,
        "full_name": full_name,
        "institutional_email": None,
        "role": "invitado",
        "is_guest": True,
        "last_activity": datetime.now()
    }
    ACTIVE_SESSIONS[token] = session_data

    return {
        "token": token,
        "user": session_data,
        "active_users": len(ACTIVE_SESSIONS),
        "max_users": MAX_CONCURRENT_USERS
    }

# 3. Autenticación Tradicional con Contraseña (para Administrador)
@app.post("/api/login")
async def login_password(data: LoginRequest):
    enforce_concurrency_limit()
    conn = get_db_connection()
    user = conn.execute(
        "SELECT id, username, full_name, institutional_email, password_hash, role, is_active FROM users WHERE username = ?",
        (data.username.strip(),)
    ).fetchone()
    conn.close()

    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos.")

    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Esta cuenta ha sido suspendida.")

    token = secrets.token_hex(24)
    session_data = {
        "id": user["id"],
        "username": user["username"],
        "full_name": user["full_name"],
        "institutional_email": user["institutional_email"],
        "role": user["role"],
        "is_guest": False,
        "last_activity": datetime.now()
    }
    ACTIVE_SESSIONS[token] = session_data

    return {
        "token": token,
        "user": session_data,
        "active_users": len(ACTIVE_SESSIONS),
        "max_users": MAX_CONCURRENT_USERS
    }

# 4. Cerrar Sesión (Con destrucción inmediata si es usuario local/invitado)
@app.post("/api/auth/logout")
async def logout_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        return {"message": "Sesión cerrada."}
    token = authorization.split(" ")[1]
    sess = ACTIVE_SESSIONS.pop(token, None)
    if sess and sess.get("is_guest"):
        # Purga de datos del usuario local
        purge_guest_user_data(sess.get("username", ""))

    return {"message": "Sesión cerrada correctamente.", "active_users": len(ACTIVE_SESSIONS)}

# ==============================================================================
# AUDITORÍA JURÍDICA Y BITÁCORA
# ==============================================================================
@app.get("/api/cases")
@app.get("/api/casos")
async def list_cases(authorization: Optional[str] = Header(None)):
    res = []
    for c in CASOS_EJEMPLO:
        item = dict(c)
        item["hechos"] = c["descripcion"]
        item["articulos"] = "CPEUM / CADH"
        res.append(item)
    return res

@app.post("/api/evaluate")
@app.post("/api/analizar")
async def evaluate_case(req: EvaluateRequest, authorization: Optional[str] = Header(None)):
    user = None
    if authorization and authorization.startswith("Bearer "):
        try:
            user = get_current_user(authorization)
        except Exception:
            user = None

    if not user:
        user = {
            "username": "invitado_local",
            "full_name": "Usuario Local (Sesión Efímera)",
            "role": "guest",
            "is_guest": True
        }

    hechos = (req.caso_hechos or req.descripcion or "").strip()
    if not hechos:
        raise HTTPException(status_code=400, detail="Los hechos del caso a evaluar no pueden estar vacíos.")

    try:
        dictamen = await analizar_caso_ia(
            descripcion_caso=hechos,
            modo=req.modo,
            api_key="",  # Administrado de forma segura en servidor
            local_url=req.local_url,
            local_model=req.local_model
        )

        # Si el usuario o frontend proveyó un título (por ejemplo al cargar un ejemplo), priorizarlo
        if req.titulo and req.titulo.strip():
            dictamen["titulo_caso"] = req.titulo.strip()

        case_title = dictamen.get("titulo_caso") or "Caso Forense Particular"

        # Registro en la bitácora SQLite
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO audit_logs (username, full_name, case_title, case_description, ai_mode, veredicto, nivel_riesgo_eu, puntuacion_etica, dictamen_json, is_guest, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user["username"],
            user["full_name"],
            case_title,
            hechos,
            req.modo.upper(),
            dictamen.get("veredicto", "N/A"),
            dictamen.get("nivel_riesgo_eu", "N/A"),
            int(dictamen.get("puntuacion_etica", 50)),
            json.dumps(dictamen, ensure_ascii=False),
            1 if user.get("is_guest") else 0,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        conn.close()

        # Respuesta estructurada compatible con todos los esquemas del frontend
        response_data = dict(dictamen)
        response_data["status"] = "ok"
        response_data["dictamen"] = dictamen
        response_data["case_title"] = case_title
        response_data["titulo_caso"] = case_title
        return response_data
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error en la deliberación judicial: {str(e)}")

@app.get("/api/history")
@app.get("/api/bitacora")
async def get_history(authorization: Optional[str] = Header(None)):
    user = None
    if authorization and authorization.startswith("Bearer "):
        try:
            user = get_current_user(authorization)
        except Exception:
            user = None

    if not user:
        user = {"username": "invitado_local", "role": "guest"}

    conn = get_db_connection()
    if user.get("role") == "admin":
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 60").fetchall()
    else:
        # Los usuarios ven sus consultas y las consultas recientes no restringidas
        rows = conn.execute(
            "SELECT * FROM audit_logs WHERE username = ? OR is_guest = 1 ORDER BY id DESC LIMIT 40",
            (user["username"],)
        ).fetchall()
    conn.close()

    history = []
    for r in rows:
        d_json = json.loads(r["dictamen_json"])
        title = r["case_title"] if ("case_title" in r.keys() and r["case_title"]) else (d_json.get("titulo_caso") or "Caso Forense Particular")
        history.append({
            "id": r["id"],
            "username": r["username"],
            "full_name": r["full_name"],
            "case_title": title,
            "case_description": r["case_description"],
            "ai_mode": r["ai_mode"],
            "veredicto": r["veredicto"],
            "nivel_riesgo_eu": r["nivel_riesgo_eu"],
            "puntuacion_etica": r["puntuacion_etica"],
            "dictamen": d_json,
            "created_at": r["created_at"]
        })
    return {"history": history}

@app.get("/api/stats")
@app.get("/api/estadisticas")
async def get_stats(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        try:
            get_current_user(authorization)
        except Exception:
            pass
    clean_expired_sessions()
    conn = get_db_connection()
    total_audits = conn.execute("SELECT COUNT(*) as c FROM audit_logs").fetchone()["c"]
    vulnera_count = conn.execute("SELECT COUNT(*) as c FROM audit_logs WHERE veredicto LIKE 'VULNERA%'").fetchone()["c"]
    positivo_count = conn.execute("SELECT COUNT(*) as c FROM audit_logs WHERE veredicto LIKE '%NO VULNERA%'").fetchone()["c"]
    total_users = conn.execute("SELECT COUNT(*) as c FROM users WHERE is_active = 1").fetchone()["c"]
    conn.close()

    active_cnt = len(ACTIVE_SESSIONS)
    return {
        "total_audits": total_audits,
        "vulnera_count": vulnera_count,
        "positivo_count": positivo_count,
        "total_users": total_users,
        "active_sessions": active_cnt,
        "usuarios_activos": active_cnt,
        "max_sessions": MAX_CONCURRENT_USERS
    }

# Verificación de estado de Ollama local
@app.get("/api/health-ollama")
async def check_ollama(url: str = "http://localhost:11434"):
    clean_url = url.strip().rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{clean_url}/api/tags")
            if resp.status_code == 200:
                models = [m.get("name") for m in resp.json().get("models", [])]
                return {"online": True, "models": models}
    except Exception:
        pass
    return {"online": False, "models": []}

# ==============================================================================
# ADMINISTRACIÓN DE USUARIOS (SOLO ADMINISTRADOR)
# ==============================================================================
@app.get("/api/users")
async def list_users(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Exclusivo para el Administrador.")

    conn = get_db_connection()
    rows = conn.execute("""
        SELECT u.id, u.username, u.full_name, u.institutional_email, u.role, u.is_active, u.password_hash, u.created_at,
               (SELECT COUNT(*) FROM audit_logs a WHERE a.username = u.username) as total_evals
        FROM users u ORDER BY u.id ASC
    """).fetchall()
    conn.close()

    safe_users = []
    for r in rows:
        safe_users.append({
            "id": r["id"],
            "username": r["username"],
            "full_name": r["full_name"],
            "institutional_email": r["institutional_email"],
            "role": r["role"],
            "is_active": bool(r["is_active"]),
            "total_evals": r["total_evals"],
            "auth_type": "Contraseña Bcrypt" if not r["password_hash"].startswith("OTP_AUTH") else "Correo con OTP",
            "created_at": r["created_at"]
        })
    return {"users": safe_users}

@app.post("/api/users")
async def create_user(new_user: CreateUserRequest, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Exclusivo para el Administrador.")

    if len(new_user.username.strip()) < 3 or len(new_user.password) < 4:
        raise HTTPException(status_code=400, detail="El usuario debe tener al menos 3 caracteres y la contraseña 4.")

    conn = get_db_connection()
    try:
        pw_hash = hash_password(new_user.password)
        conn.execute("""
            INSERT INTO users (username, full_name, institutional_email, password_hash, role, is_verified, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, 1, 1, ?)
        """, (
            new_user.username.strip(),
            new_user.full_name.strip(),
            new_user.institutional_email.strip().lower(),
            pw_hash,
            new_user.role,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
    except Exception:
        conn.close()
        raise HTTPException(status_code=400, detail="El nombre de usuario o correo ya están registrados.")
    conn.close()
    return {"message": f"Usuario '{new_user.username}' registrado correctamente."}

@app.patch("/api/users/{user_id}/toggle")
async def toggle_user_status(user_id: int, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Exclusivo para el Administrador.")

    conn = get_db_connection()
    target = conn.execute("SELECT username, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")
    if target["username"] == "admin":
        conn.close()
        raise HTTPException(status_code=400, detail="No puedes suspender la cuenta del Administrador raíz.")

    new_status = 0 if target["is_active"] else 1
    conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    return {"message": f"Usuario '{target['username']}' {'activado' if new_status else 'suspendido'}."}

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int, authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Exclusivo para el Administrador.")

    conn = get_db_connection()
    target = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")
    if target["username"] == "admin":
        conn.close()
        raise HTTPException(status_code=400, detail="No puedes eliminar al Administrador raíz.")

    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"message": f"Usuario '{target['username']}' eliminado."}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)

