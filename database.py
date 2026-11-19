import sqlite3
import bcrypt
from datetime import datetime, timedelta
import random
from typing import Optional, Dict, Any, List

DB_NAME = "normatividad_ia.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME, check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row
    # Modo WAL y timeout para soportar alta concurrencia de hasta 30 usuarios simultáneos sin bloqueos
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn

def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain_password.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        if not hashed_password or hashed_password.startswith("OTP_AUTH"):
            return False
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Tabla de Usuarios Registrados en Base de Datos (Persistente)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            institutional_email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'usuario',
            is_verified INTEGER DEFAULT 1,
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    # Migraciones seguras
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass

    # 2. Tabla de Códigos OTP
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            code TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0
        )
    """)

    # 3. Bitácora de Auditorías Jurídicas de IA
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            full_name TEXT NOT NULL,
            case_description TEXT NOT NULL,
            ai_mode TEXT NOT NULL,
            veredicto TEXT NOT NULL,
            nivel_riesgo_eu TEXT NOT NULL,
            puntuacion_etica INTEGER DEFAULT 50,
            dictamen_json TEXT NOT NULL,
            is_guest INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    # Migración de is_guest y case_title si no existían
    try:
        cursor.execute("ALTER TABLE audit_logs ADD COLUMN is_guest INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE audit_logs ADD COLUMN case_title TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass

    # 4. Administrador por defecto
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        default_hash = hash_password("Admin123!")
        cursor.execute("""
            INSERT INTO users (username, full_name, institutional_email, password_hash, role, is_verified, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, 1, 1, ?)
        """, (
            "admin",
            "Oficial Mayor del Tribunal",
            "admin@institucion.edu.mx",
            default_hash,
            "admin",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        print("[OK] Admin por defecto listo -> Usuario: admin | Pass: Admin123!")

    conn.commit()
    conn.close()

def register_user_email(full_name: str, email: str, password: str) -> Dict[str, Any]:
    """
    Registra a un nuevo usuario con correo y contraseña cifrada con Bcrypt en SQLite.
    """
    clean_email = email.strip().lower()
    clean_name = full_name.strip()
    conn = get_db_connection()

    existing = conn.execute(
        "SELECT id FROM users WHERE LOWER(institutional_email) = ?", (clean_email,)
    ).fetchone()
    if existing:
        conn.close()
        raise ValueError("Este correo electrónico ya se encuentra registrado en el sistema.")

    prefijo = clean_email.split("@")[0].replace(".", "_").replace("-", "_")
    base_user = prefijo[:15]
    candidate = base_user
    counter = 1
    while True:
        exists = conn.execute("SELECT id FROM users WHERE username = ?", (candidate,)).fetchone()
        if not exists:
            break
        candidate = f"{base_user}_{counter}"
        counter += 1

    pw_hash = hash_password(password)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (username, full_name, institutional_email, password_hash, role, is_verified, is_active, created_at)
        VALUES (?, ?, ?, ?, 'usuario', 1, 1, ?)
    """, (candidate, clean_name or f"Lic. {prefijo.capitalize()}", clean_email, pw_hash, now_str))
    new_id = cursor.lastrowid
    conn.commit()

    new_user = {
        "id": new_id,
        "username": candidate,
        "full_name": clean_name or f"Lic. {prefijo.capitalize()}",
        "institutional_email": clean_email,
        "role": "usuario",
        "is_active": 1
    }
    conn.close()
    return new_user

def authenticate_email_password(email: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Verifica las credenciales por correo y contraseña con Bcrypt.
    """
    clean_email = email.strip().lower()
    conn = get_db_connection()
    user = conn.execute(
        "SELECT id, username, full_name, institutional_email, password_hash, role, is_active FROM users WHERE LOWER(institutional_email) = ?",
        (clean_email,)
    ).fetchone()
    conn.close()

    if not user:
        return None

    if not verify_password(password, user["password_hash"]):
        return None

    return dict(user)

def purge_guest_user_data(username: str):
    """
    Destruye y purga todos los registros y huellas generadas por un usuario local/invitado
    en cuanto este cierra su sesión.
    """
    conn = get_db_connection()
    conn.execute("DELETE FROM audit_logs WHERE username = ? AND is_guest = 1", (username,))
    conn.commit()
    conn.close()
