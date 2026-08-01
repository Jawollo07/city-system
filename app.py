import os
import secrets
import sqlite3
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Header, HTTPException

# Konfiguration
API_TOKEN = os.getenv("API_TOKEN", "cxGXKxWkZBYNQQyx6wx&uq&Fpqgeyj*MaDEbE%Y#WiVRBM^!f*4r$8jf#g#3!%ig5^aKM!5CpeHpjR5Ap$8AgeLGhbq6Q2PkehT93bm4ay8VkuPbAV2Gz7YvFdKtyTSv")
DB_PATH = os.getenv("DB_PATH", "keys.db")
ROTATION_INTERVAL_HOURS = 24

NETWORK_CONFIG = {
    "ELEVATOR_NET": ["18", "22"],
    "DOORS_NET": ["11", "19"]
}

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS network_keys (
                network_name TEXT PRIMARY KEY,
                current_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

def generate_and_store_key(network_name: str):
    new_key = secrets.token_hex(32)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO network_keys (network_name, current_key, created_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(network_name) DO UPDATE SET
                current_key=excluded.current_key,
                created_at=CURRENT_TIMESTAMP
        """, (network_name, new_key))
    print(f"🔄 [ROTATION] Neuer Schlüssel für '{network_name}' aktiv.")

async def key_rotation_task():
    while True:
        with sqlite3.connect(DB_PATH) as conn:
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
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT current_key FROM network_keys WHERE network_name = ?", (net,))
            if not cursor.fetchone():
                generate_and_store_key(net)

    task = asyncio.create_task(key_rotation_task())
    yield
    task.cancel()

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
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Fehlender Auth-Header")

    if authorization.split(" ")[1] != API_TOKEN:
        raise HTTPException(status_code=401, detail="Ungültiges API-Token")

    if network_name not in NETWORK_CONFIG:
        raise HTTPException(status_code=404, detail="Netzwerk nicht gefunden")

    try:
        cc_id = user_agent.split("/")[-1]
    except Exception:
        cc_id = "unknown"

    if cc_id not in NETWORK_CONFIG[network_name]:
        raise HTTPException(status_code=403, detail="Keine Berechtigung")

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT current_key FROM network_keys WHERE network_name = ?", (network_name,))
        result = cursor.fetchone()

    return {
        "status": "success",
        "network": network_name,
        "key": result[0] if result else None
    }

# ---------------------------------------------------------
# ENDPUNKT 2: Manuelle Key-Rotation (Dein Panik-Schalter)
# ---------------------------------------------------------
@app.post("/v1/rotate/{network_name}")
def force_key_rotation(
    network_name: str,
    authorization: str = Header(None)
):
    """Erzwingt sofort die Generierung eines neuen Schlüssels für das gewählte Netzwerk."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Fehlender Auth-Header")

    if authorization.split(" ")[1] != API_TOKEN:
        raise HTTPException(status_code=401, detail="Ungültiges API-Token")

    if network_name not in NETWORK_CONFIG:
        raise HTTPException(status_code=404, detail="Netzwerk nicht gefunden")

    # Überschreibt den aktuellen Key sofort
    generate_and_store_key(network_name)

    return {
        "status": "success",
        "message": f"Schlüssel für {network_name} wurde manuell rotiert und ist ab sofort aktiv."
    }
if __name__ == "__main__":
    import uvicorn
    # Startet den Server auf http://127.0.0.1:8000
    uvicorn.run("app:app", host="127.0.0.1", port=25560, reload=True)
