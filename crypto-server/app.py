import os
import secrets
import sqlite3
import asyncio
import hmac
import json
import logging
import re
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Header, HTTPException
import uvicorn
from dotenv import load_dotenv

# Konfiguration
load_dotenv()
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("crypto_server")
# Shared API secret for admin and device requests; never ship a default secret in source.
API_TOKEN = os.getenv("API_TOKEN", "")
if len(API_TOKEN) < 32 or API_TOKEN.startswith("REPLACE_WITH_"):
    raise RuntimeError("Set API_TOKEN to a real random secret of at least 32 characters; placeholders are rejected")
DB_PATH = os.getenv("DB_PATH", "keys.db")
ROTATION_INTERVAL_HOURS = int(os.getenv("ROTATION_INTERVAL_HOURS", "24"))
if not 1 <= ROTATION_INTERVAL_HOURS <= 8760:
    raise RuntimeError("ROTATION_INTERVAL_HOURS must be between 1 and 8760")
try:
    NETWORK_CONFIG = json.loads(os.getenv("NETWORK_CONFIG_JSON", json.dumps({
        "ELEVATOR_NET": ["18", "22"], "DOORS_NET": ["11", "19"]
    })))
except json.JSONDecodeError as exc:
    raise RuntimeError("NETWORK_CONFIG_JSON must be valid JSON") from exc
if not isinstance(NETWORK_CONFIG, dict) or any(not isinstance(k, str) or not isinstance(v, list) for k, v in NETWORK_CONFIG.items()):
    raise RuntimeError("NETWORK_CONFIG_JSON must map network names to arrays of computer IDs")
NETWORK_CONFIG = {k: [str(v) for v in values] for k, values in NETWORK_CONFIG.items()}
ID_RE = re.compile(r"^[0-9]{1,10}$")
NETWORK_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

def db_connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn

def require_api_token(authorization):
    scheme, sep, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not sep or not hmac.compare_digest(supplied, API_TOKEN):
        raise HTTPException(status_code=401, detail="Ungültiger API-Key")

def require_device(network_name, device_id, authorization):
    require_api_token(authorization)
    with db_connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM network_devices WHERE device_id=? AND network_name=?",
            (device_id, network_name),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=403, detail="Gerät für dieses Netzwerk nicht freigegeben")

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
        conn.execute("""CREATE TABLE IF NOT EXISTS network_devices (
            network_name TEXT NOT NULL, device_id TEXT NOT NULL,
            PRIMARY KEY(network_name, device_id))""")
        conn.execute("CREATE TABLE IF NOT EXISTS app_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        seeded = conn.execute("SELECT value FROM app_metadata WHERE key='network_config_seeded'").fetchone()
        if seeded is None:
            for network_name, device_ids in NETWORK_CONFIG.items():
                for device_id in device_ids:
                    conn.execute("INSERT OR IGNORE INTO network_devices(network_name, device_id) VALUES (?, ?)",
                                 (network_name, device_id))
            conn.execute("INSERT INTO app_metadata(key, value) VALUES ('network_config_seeded', '1')")

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
        try:
            with db_connect() as conn:
                expired_networks = conn.execute(
                    "SELECT network_name FROM network_keys WHERE created_at <= datetime('now', ?)",
                    (f"-{ROTATION_INTERVAL_HOURS} hours",),
                ).fetchall()
            for row in expired_networks:
                generate_and_store_key(row["network_name"])
        except asyncio.CancelledError:
            raise
        except sqlite3.Error:
            logger.exception("Scheduled key rotation failed; will retry next hour")
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

    try:
        with db_connect() as conn:
            result = conn.execute("SELECT current_key FROM network_keys WHERE network_name = ?", (network_name,)).fetchone()
    except sqlite3.Error as exc:
        logger.exception("Key lookup failed")
        raise HTTPException(status_code=503, detail="Key store unavailable") from exc

    if not result:
        raise HTTPException(status_code=503, detail="Netzwerkschlüssel nicht initialisiert")
    return {"status": "success", "network": network_name, "key": result[0]}

@app.get("/v1/networks/{network_name}/devices")
def list_devices(network_name: str, authorization: str = Header(None)):
    require_api_token(authorization)
    if not NETWORK_RE.fullmatch(network_name) or network_name not in NETWORK_CONFIG:
        raise HTTPException(status_code=404, detail="Netzwerk nicht gefunden")
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT device_id FROM network_devices WHERE network_name=? ORDER BY CAST(device_id AS INTEGER)",
            (network_name,),
        ).fetchall()
    return {"network": network_name, "authorized_devices": [row["device_id"] for row in rows]}


@app.get("/v1/networks/{network_name}/devices/{device_id}")
def get_device(network_name: str, device_id: str, authorization: str = Header(None)):
    require_api_token(authorization)
    if not NETWORK_RE.fullmatch(network_name) or network_name not in NETWORK_CONFIG:
        raise HTTPException(status_code=404, detail="Netzwerk nicht gefunden")
    if not ID_RE.fullmatch(device_id):
        raise HTTPException(status_code=400, detail="Ungültige Computer-ID")
    with db_connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM network_devices WHERE network_name=? AND device_id=?",
            (network_name, device_id),
        ).fetchone()
    return {"network": network_name, "device_id": device_id, "authorized": row is not None}


@app.post("/v1/networks/{network_name}/devices/{device_id}")
def authorize_device(network_name: str, device_id: str, authorization: str = Header(None)):
    require_api_token(authorization)
    if not NETWORK_RE.fullmatch(network_name) or network_name not in NETWORK_CONFIG:
        raise HTTPException(status_code=404, detail="Netzwerk nicht gefunden")
    if not ID_RE.fullmatch(device_id):
        raise HTTPException(status_code=400, detail="Ungültige Computer-ID")
    with db_connect() as conn:
        conn.execute("INSERT OR IGNORE INTO network_devices(network_name, device_id) VALUES (?, ?)",
                     (network_name, device_id))
    return {"status": "success", "message": "Gerät freigegeben.", "network": network_name,
            "device_id": device_id, "authorized": True}


@app.delete("/v1/networks/{network_name}/devices/{device_id}")
def revoke_device(network_name: str, device_id: str, authorization: str = Header(None)):
    require_api_token(authorization)
    if not NETWORK_RE.fullmatch(network_name) or network_name not in NETWORK_CONFIG:
        raise HTTPException(status_code=404, detail="Netzwerk nicht gefunden")
    if not ID_RE.fullmatch(device_id):
        raise HTTPException(status_code=400, detail="Ungültige Computer-ID")
    with db_connect() as conn:
        conn.execute("DELETE FROM network_devices WHERE network_name=? AND device_id=?", (network_name, device_id))
    return {"status": "success", "message": "Gerät gesperrt.", "network": network_name,
            "device_id": device_id, "authorized": False}


# ---------------------------------------------------------
# ENDPUNKT 2: Manuelle Key-Rotation (Dein Panik-Schalter)
# ---------------------------------------------------------
@app.post("/v1/rotate/{network_name}")
def force_key_rotation(
    network_name: str,
    authorization: str = Header(None),
):
    """Erzwingt sofort die Generierung eines neuen Schlüssels für das gewählte Netzwerk."""
    require_api_token(authorization)
    if not NETWORK_RE.fullmatch(network_name) or network_name not in NETWORK_CONFIG:
        raise HTTPException(status_code=404, detail="Netzwerk nicht gefunden")

    # Rotation is immediate; clients may need to refresh their in-memory key.
    try:
        generate_and_store_key(network_name)
    except sqlite3.Error as exc:
        logger.exception("Manual key rotation failed")
        raise HTTPException(status_code=503, detail="Schlüsselrotation fehlgeschlagen") from exc

    return {"status": "success", "message": f"Schlüssel für {network_name} wurde rotiert."}
if __name__ == "__main__":
    uvicorn.run("app:app", host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "25560")), reload=False)
