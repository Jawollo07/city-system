-- ==================================================
-- CC:Tweaked Secure E2EE Crypto Library
-- Features: API Key Fetch, RC4, HMAC, Anti-Replay, Auto-Recovery
-- Compatibility: Rednet Helper & Admin-Terminal Integration
-- ==================================================
local crypto = {}

----------------------------------------------------
-- KONFIGURATION
----------------------------------------------------
local API_URL      = "http://192.168.178.85:25559/v1/"
-- Use the same secret configured as API_TOKEN on the KMS server and admin terminal.
local API_TOKEN    = "tJkXzQUdhlDUQWNawBg-9n1COQzpttKuq66rOqCXJT3ja3s0VJIyI93HwdT_xzk6"
local NETWORK_NAME = os.getComputerLabel() or "UNCONFIGURED_NETWORK"
local DEBUG_MODE   = true

crypto.API_TOKEN = API_TOKEN
crypto.API_URL = API_URL
crypto.NETWORK_NAME = NETWORK_NAME

----------------------------------------------------
-- 1. SCHLÜSSEL-VERWALTUNG (HTTP API)
----------------------------------------------------
local function fetchKey()
    if not http then
        print("[Crypto] FEHLER: HTTP-API deaktiviert; unsicherer Fallback verweigert.")
        return nil
    end
    if API_TOKEN == "" or API_TOKEN == "REPLACE_WITH_SHARED_API_TOKEN" then
        print("[Crypto] FEHLER: API-Token nicht konfiguriert.")
        return nil
    end

    local myID = tostring(os.getComputerID())
    local headers = {
        ["Authorization"] = "Bearer " .. API_TOKEN,
        ["User-Agent"]    = "CC-Tweaked-Node/" .. myID,
        ["Accept"]        = "application/json"
    }

    local ok, response = pcall(http.get, API_URL .. "keys/" .. NETWORK_NAME, headers)
    if ok and response then
        local body = response.readAll()
        response.close()

        local data = textutils.unserializeJSON(body)
        if data and data.key then
            return data.key
        end
    end
    print("[Crypto] FEHLER: API nicht erreichbar; kein Fallback-Schlüssel.")
    return nil
end

local function debugSessionKey(key)
    if DEBUG_MODE then
        if type(key) == "string" then
            print("[Crypto][DEBUG] Session Key: " .. key)
        else
            print("[Crypto][DEBUG] Session Key nicht verfügbar.")
        end
    end
end

-- Holt den Key beim Laden des Moduls und speichert ihn im RAM
local SESSION_KEY = fetchKey()
debugSessionKey(SESSION_KEY)

local function requireSessionKey()
    if type(SESSION_KEY) ~= "string" or #SESSION_KEY < 16 then
        return nil, "Kein gültiger Sitzungsschlüssel verfügbar; Anfrage wird abgebrochen."
    end
    return SESSION_KEY
end

----------------------------------------------------
-- 2. KRYPTO-HILFSFUNKTIONEN (RC4 & HMAC)
----------------------------------------------------
local bxor = (bit32 and bit32.bxor) or (bit and bit.bxor)

local function cipherRC4(key, str)
    local S = {}
    for i = 0, 255 do S[i] = i end
    local j = 0
    for i = 0, 255 do
        j = (j + S[i] + key:byte((i % #key) + 1)) % 256
        S[i], S[j] = S[j], S[i]
    end
    local i, j = 0, 0
    local res = {}
    for k = 1, #str do
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        local K = S[(S[i] + S[j]) % 256]
        res[k] = string.char(bxor(str:byte(k), K))
    end
    return table.concat(res)
end

local function generateHMAC(key, message)
    local hash = 5381
    local combined = key .. ":" .. message .. ":" .. key
    for i = 1, #combined do
        local b = combined:byte(i)
        hash = ((hash * 33) + b) % 0xFFFFFFFF
    end
    return string.format("%08x", hash)
end

local function generateNonce()
    local chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    local nonce = {}
    for i = 1, 16 do
        local r = math.random(1, #chars)
        table.insert(nonce, chars:sub(r, r))
    end
    return table.concat(nonce)
end

----------------------------------------------------
-- 3. HAUPTFUNKTIONEN (ENCRYPT / DECRYPT)
----------------------------------------------------
local seenNonces = {} -- Replay-Cache, begrenzt gegen unbegrenztes RAM-Wachstum
local nonceOrder = {}
local MAX_SEEN_NONCES = 512

--- Verschlüsselt die Daten lokal (Encrypt-then-MAC)
function crypto.encrypt(payload)
    local key, keyErr = requireSessionKey()
    if not key then return nil, keyErr end
    if type(payload) ~= "table" then return nil, "Payload muss eine Tabelle sein." end
    local serialized = textutils.serialize(payload)
    local nonce = generateNonce()
    local timestamp = os.epoch("utc")

    -- 1. Verschlüsseln
    local encryptedData = cipherRC4(key .. nonce, serialized)

    -- 2. Signieren (HMAC)
    local checkString = tostring(timestamp) .. nonce .. encryptedData
    local hmac = generateHMAC(key, checkString)

    return {
        v = 1,
        ts = timestamp,
        nonce = nonce,
        enc = encryptedData,
        hmac = hmac
    }
end

--- Entschlüsselt und prüft die Integrität lokal inkl. Auto-Recovery
function crypto.decrypt(packet)
    local key, keyErr = requireSessionKey()
    if not key then return nil, keyErr end
    -- Fallback, falls das Paket direkt als rednet Message-Tabelle übergeben wurde
    if type(packet) == "table" and packet.cipherText then packet = packet.cipherText end

    if type(packet) ~= "table"
        or type(packet.ts) ~= "number"
        or type(packet.nonce) ~= "string"
        or #packet.nonce ~= 16
        or type(packet.enc) ~= "string"
        or type(packet.hmac) ~= "string" then
        return nil, "Ungültiges Paketformat."
    end

    -- A. Replay-Schutz: Zeitfenster validieren.
    local now = os.epoch("utc")
    if math.abs(now - packet.ts) > 5000 then
        return nil, "Paket verworfen: Zu alt (Replay-Angriff?)"
    end

    -- B. Replay-Schutz: Nonce prüfen
    if seenNonces[packet.nonce] then
        return nil, "Paket verworfen: Bereits verarbeitet (Replay-Angriff!)"
    end

    -- C. Integrität prüfen (HMAC) mit aktuellem RAM-Schlüssel
    local checkString = tostring(packet.ts) .. packet.nonce .. packet.enc
    local expectedHMAC = generateHMAC(SESSION_KEY, checkString)

    -- D. AUTO-RECOVERY: Wenn der HMAC nicht stimmt, frage die API nach einem neuen Key
    if packet.hmac ~= expectedHMAC then
        print("[Crypto] HMAC-Fehler. Versuche neuen Key von API abzurufen...")
        local newKey = fetchKey()
        if type(newKey) ~= "string" or #newKey < 16 then
            return nil, "Paket verworfen: API liefert keinen gültigen Schlüssel."
        end

        -- Erneuter Versuch mit dem frisch abgerufenen Key
        local newExpectedHMAC = generateHMAC(newKey, checkString)
        if packet.hmac == newExpectedHMAC then
            print("[Crypto] Key erfolgreich aktualisiert!")
            SESSION_KEY = newKey -- Neuen Key dauerhaft im RAM speichern
            debugSessionKey(SESSION_KEY)
        else
            return nil, "Paket verworfen: HMAC auch mit neuem Key ungueltig! (Manipulation erkannt)"
        end
    end

    -- E. Nachricht als gültig markieren & Entschlüsseln
    seenNonces[packet.nonce] = true
    nonceOrder[#nonceOrder + 1] = packet.nonce
    if #nonceOrder > MAX_SEEN_NONCES then
        local expired = table.remove(nonceOrder, 1)
        seenNonces[expired] = nil
    end
    local decryptedStr = cipherRC4(SESSION_KEY .. packet.nonce, packet.enc)
    local decoded = textutils.unserialize(decryptedStr)
    if type(decoded) ~= "table" then return nil, "Entschlüsselte Nachricht ist ungültig." end
    return decoded
end

----------------------------------------------------
-- 4. KOMPATIBILITÄT & REDNET HELPER
----------------------------------------------------
-- Funktions-Aliase für Abwärtskompatibilität & Gebäudesysteme
crypto.seal           = crypto.encrypt
crypto.unseal         = crypto.decrypt
crypto.encryptPayload = crypto.encrypt
crypto.decryptPayload = crypto.decrypt
crypto.pack           = crypto.encrypt
crypto.unpack         = crypto.decrypt

--- Öffnet automatisch alle Modems an allen Seiten für Rednet
function crypto.ensureRednet()
    for _, side in ipairs(peripheral.getNames()) do
        if peripheral.getType(side) == "modem" then
            rednet.open(side)
        end
    end
end

return crypto
