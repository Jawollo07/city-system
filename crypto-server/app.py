import os
import secrets
import sqlite3
import asyncio
import hashlib
import hmac
import json
import logging
import re
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Header, HTTPException
import uvicorn

# Konfiguration
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("crypto_server")
# API_TOKEN is an admin-only secret; never ship a default secret in source.
API_TOKEN = os.getenv("API_TOKEN", "")
if len(API_TOKEN) < 32:
    raise RuntimeError("Set API_TOKEN to a random admin secret of at least 32 characters")
DB_PATH = os.getenv("DB_PATH", "keys.db")
ROTATION_INTERVAL_HOURS = int(os.getenv("ROTATION_INTERVAL_HOURS", "24"))
if not 1 <= ROTATION_INTERVAL_HOURS <= 8760:
    raise RuntimeError("ROTATION_INTERVAL_HOURS must be between 1 and 8760")
try:
    NETWORK_CONFIG = json.loads(os.getenv("NETWORK_CONFIG_JSON", json.dumps({
        "ELEVATOR_NET": ["18", "22"], "DOORS_NET": ["11", "19"]
    })))
    DEVICE_TOKENS = json.loads(os.getenv("DEVICE_TOKENS_JSON", "{}"))
except json.JSONDecodeError as exc:
    raise RuntimeError("NETWORK_CONFIG_JSON and DEVICE_TOKENS_JSON must be valid JSON") from exc
if not isinstance(NETWORK_CONFIG, dict) or any(not isinstance(k, str) or not isinstance(v, list) for k, v in NETWORK_CONFIG.items()):
    raise RuntimeError("NETWORK_CONFIG_JSON must map network names to arrays of computer IDs")
NETWORK_CONFIG = {k: [str(v) for v in values] for k, values in NETWORK_CONFIG.items()}
if not isinstance(DEVICE_TOKENS, dict) or any(not isinstance(v, str) or len(v) < 32 for v in DEVICE_TOKENS.values()):
    raise RuntimeError("DEVICE_TOKENS_JSON must map computer IDs to random tokens of at least 32 characters")
DEVICE_TOKENS = {str(k): v for k, v in DEVICE_TOKENS.items()}
ID_RE = re.compile(r"^[0-9]{1,10}$")
NETWORK_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

def db_connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn

def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def require_admin(authorization):
    scheme, sep, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not sep or not hmac.compare_digest(supplied, API_TOKEN):
        raise HTTPException(status_code=401, detail="Ungültige Admin-Zugangsdaten")

def require_device(network_name, device_id, authorization):
    scheme, sep, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not sep or not supplied:
        raise HTTPException(status_code=401, detail="Fehlende Geräte-Zugangsdaten")
    with db_connect() as conn:
        row = conn.execute("""SELECT c.token_hash FROM device_credentials c
            JOIN network_devices n ON n.device_id=c.device_id
            WHERE c.device_id=? AND n.network_name=?""", (device_id, network_name)).fetchone()
    if row is None:
        raise HTTPException(status_code=403, detail="Gerät für dieses Netzwerk nicht freigegeben")
    if not hmac.compare_digest(token_hash(supplied), row["token_hash"]):
        raise HTTPException(status_code=401, detail="Ungültige Geräte-Zugangsdaten")

def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with db_connect() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS network_keys (
                network_name TEXT PRIMARY KEY,
                current_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

def generate_and_store_key(network_name: str):
    new_key = secrets.token_hex(32)
    with db_connect() as conn:
        conn.execute("""
            INSERT INTO network_keys (network_name, current_key, created_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(network_name) DO UPDATE SET
                current_key=excluded.current_key,
                created_at=CURRENT_TIMESTAMP
        """, (network_name, new_key))
    logger.warning("Key rotated for network %s", network_name)

async def key_rotation_task():
    while True:
        with db_connect() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT network_name FROM network_keys
                WHERE created_at <= datetime('now', '-{ROTATION_INTERVAL_HOURS} hours')
            """)
            expired_networks = cursor.fetchall()

        for (net,) in expired_networks:
            generate_and_store_key(net)

        await asyncio.sleep(3600)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    for net in NETWORK_CONFIG.keys():
        with db_connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT current_key FROM network_keys WHERE network_name = ?", (net,))
            if not cursor.fetchone():
                generate_and_store_key(net)

    task = asyncio.create_task(key_rotation_task())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

app = FastAPI(title="CC:Tweaked Auto-KMS", lifespan=lifespan)

# ---------------------------------------------------------
# ENDPUNKT 1: Key abrufen (Wird von den CC-Rechnern genutzt)
# ---------------------------------------------------------
@app.get("/v1/keys/{network_name}")
def get_network_key(
    network_name: str,
    authorization: str = Header(None),
    user_agent: str = Header("Unbekannt")
):
    if not NETWORK_RE.fullmatch(network_name) or network_name not in NETWORK_CONFIG:
        raise HTTPException(status_code=404, detail="Netzwerk nicht gefunden")
    match = re.fullmatch(r"CC-Tweaked-Node/([0-9]{1,10})", user_agent.strip())
    if not match:
        raise HTTPException(status_code=400, detail="Ungültiger User-Agent; erwartet CC-Tweaked-Node/<ID>")
    cc_id = match.group(1)
    require_device(network_name, cc_id, authorization)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT current_key FROM network_keys WHERE network_name = ?", (network_name,))
        result = cursor.fetchone()

    if not result:
        raise HTTPException(status_code=503, detail="Netzwerkschlüssel nicht initialisiert")
    return {"status": "success", "network": network_name, "key": result[0]}

# ---------------------------------------------------------
# ENDPUNKT 2: Manuelle Key-Rotation (Dein Panik-Schalter)
# ---------------------------------------------------------
@app.post("/v1/rotate/{network_name}")
def force_key_rotation(
    network_name: str,
    authorization: str = Header(None)
):
    """Erzwingt sofort die Generierung eines neuen Schlüssels für das gewählte Netzwerk."""
    require_admin(authorization)
    if not NETWORK_RE.fullmatch(network_name) or network_name not in NETWORK_CONFIG:
        raise HTTPException(status_code=404, detail="Netzwerk nicht gefunden")

    # Überschreibt den aktuellen Key sofort
    generate_and_store_key(network_name)

    return {"status": "success", "message": f"Schlüssel für {network_name} wurde rotiert."}
if __name__ == "__main__":
    uvicorn.run("app:app", host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "25560")), reload=False)
