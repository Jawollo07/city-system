-- ====================================================
-- DATENBANK-SERVER (db.lua)
-- ====================================================
-- Aufgaben:
--  - Speichern & Verwalten von Etagen-Konfigurationen
--  - Speichern & Verwalten von Keycards (Besitzer, Clearance)
--  - Aufzeichnen von Log-Einträgen (Audit-Trail)
--  - Speichert Daten dauerhaft in lokalen Dateien (textutils)
--  - Sichere Kommunikation mit Keller-Server via HSM
-- ====================================================

local crypto = require("crypto")

-- ================= CONFIGURATION ====================
local PROTOCOL   = "GEBAEUDE-1-SEC"
local DATA_FILE  = "db_data.txt"
local LOG_FILE   = "system_logs.txt"
local KELLER_SERVER_ID = 18 -- only this server may issue DB commands
-- ====================================================

-- Modems initialisieren (Funk & Kabel)
crypto.ensureRednet()

-- Standard-Datenbankstruktur (wird geladen oder neu erstellt)
local db = {
    etagen = {
        [0] = { name = "Erdgeschoss",    clearance = 0, locked = false, relayID = 10 },
        [1] = { name = "1. Obergeschoss", clearance = 1, locked = false, relayID = 11 },
        [2] = { name = "2. Obergeschoss", clearance = 2, locked = false, relayID = 12 },
        [3] = { name = "Serverraum/HDQ", clearance = 3, locked = false, relayID = 13 }
    },
    keycards = {
        ["ADMIN-001"] = { owner = "Administrator", level = 5 },
        ["GUEST-000"] = { owner = "Gast-Karte",    level = 0 }
    }
}

-- ----------------------------------------------------
-- Datenbank laden & speichern (Persistenz)
-- ----------------------------------------------------
local function saveDB()
    local file = fs.open(DATA_FILE, "w")
    if file then
        file.write(textutils.serialize(db))
        file.close()
    end
end

local function loadDB()
    if fs.exists(DATA_FILE) then
        local file = fs.open(DATA_FILE, "r")
        if file then
            local content = file.readAll()
            file.close()
            local loaded = textutils.unserialize(content)
            if type(loaded) == "table" and loaded.etagen and loaded.keycards then
                db = loaded
            end
        end
    else
        saveDB() -- Standard-DB anlegen
    end
end

-- ----------------------------------------------------
-- Log-Einträge schreiben
-- ----------------------------------------------------
local function addLog(category, msg)
    local timestamp = textutils.formatTime(os.time(), true)
    local logLine = string.format("[%s] [%s] %s", timestamp, category or "INFO", msg or "")

    -- In Log-Datei schreiben
    local file = fs.open(LOG_FILE, "a")
    if file then
        file.writeLine(logLine)
        file.close()
    end

    -- Auf Bildschirm ausgeben
    if category == "SECURITY" or category == "ACCESS_DENIED" then
        term.setTextColor(colors.red)
    elseif category == "ACCESS_GRANTED" then
        term.setTextColor(colors.green)
    else
        term.setTextColor(colors.lightGray)
    end
    print(logLine)
    term.setTextColor(colors.white)
end

-- ----------------------------------------------------
-- UI-Anzeige aktualisieren
-- ----------------------------------------------------
local function updateDisplay()
    term.clear()
    term.setCursorPos(1,1)
    term.setTextColor(colors.yellow)
    print("==================================================")
    print("      DATENBANK-SERVER :: ZENTRALES ARCHIV        ")
    print("==================================================")
    term.setTextColor(colors.white)
    print(" Server-ID:     " .. os.getComputerID())
    print(" Protokoll:     " .. PROTOCOL)
    print(" Speicherdatei: " .. DATA_FILE)
    print("==================================================")
    term.setTextColor(colors.cyan)
    print(" Letzte Aktivitäten / Audit Log:")
    term.setTextColor(colors.white)
end

-- ----------------------------------------------------
-- SERVER STARTUP
-- ----------------------------------------------------
loadDB()
updateDisplay()
addLog("SYSTEM", "Datenbank-Server erfolgreich gestartet (ID: " .. os.getComputerID() .. ")")

-- ----------------------------------------------------
-- HAUPTSCHLEIFE (EVENT LISTENER)
-- ----------------------------------------------------
while true do
    local senderID, encryptedMessage, protocol = rednet.receive(PROTOCOL)

    if protocol == PROTOCOL and encryptedMessage ~= nil then
        if senderID ~= KELLER_SERVER_ID then
            addLog("SECURITY", "DB-Anfrage von nicht freigegebener Computer-ID " .. tostring(senderID) .. " abgelehnt")
        else
        -- Paket über Crypto-HSM entschlüsseln
        local payload, err = crypto.decrypt(encryptedMessage)

        if not payload then
            addLog("SECURITY", string.format("🚨 Ungültiges/Fehlerhaftes Paket von Computer ID %d (%s)", senderID, tostring(err)))
        else
            local cmd = payload.cmd
            local responsePayload = nil

            -- ================================================
            -- 1. ETAGEN-DATEN ABFRAGEN
            -- ================================================
            if cmd == "DB_GET_FLOORS" then
                responsePayload = { status = "OK", etagen = db.etagen }

            -- ================================================
            -- 2. KEYCARD-DATEN ABFRAGEN
            -- ================================================
            elseif cmd == "DB_GET_KEYCARD" then
                local cardId = payload.cardId or ""
                local cardInfo = db.keycards[cardId]

                if cardInfo then
                    responsePayload = { status = "OK", owner = cardInfo.owner, level = cardInfo.level }
                else
                    responsePayload = { status = "NOT_FOUND", owner = "Unbekannt", level = 0 }
                end

            -- ================================================
            -- 3. KEYCARD REGISTRIEREN / AKTUALISIEREN
            -- ================================================
            elseif cmd == "DB_SET_KEYCARD" then
                local cardId = payload.cardId
                local owner = payload.owner
                local level = tonumber(payload.level)
                if type(cardId) == "string" and #cardId > 0 and #cardId <= 64
                    and type(owner) == "string" and #owner <= 80
                    and level and level == math.floor(level) and level >= 0 and level <= 5 then
                    db.keycards[cardId] = { owner = owner ~= "" and owner or "Unbekannt", level = level }
                    saveDB()
                    addLog("ADMIN", string.format("Keycard '%s' gespeichert (Besitzer: %s, Level: %d)", cardId, db.keycards[cardId].owner, db.keycards[cardId].level))
                    responsePayload = { status = "OK" }
                else
                    responsePayload = { status = "ERROR", msg = "Ungültige Keycard-ID" }
                end

            -- ================================================
            -- 4. ETAGEN-SPERRSTATUS ÄNDERN
            -- ================================================
            elseif cmd == "DB_SET_FLOOR_LOCK" then
                local floorId = tonumber(payload.floorId)
                if floorId and db.etagen[floorId] then
                    db.etagen[floorId].locked = (payload.state == true)
                    saveDB()
                    addLog("ADMIN", string.format("Etage %d Sperrstatus geändert auf: %s", floorId, tostring(db.etagen[floorId].locked)))
                    responsePayload = { status = "OK" }
                else
                    responsePayload = { status = "ERROR", msg = "Etage nicht gefunden" }
                end

            -- ================================================
            -- 5. ETAGEN-CLEARANCE LEVEL ÄNDERN
            -- ================================================
            elseif cmd == "DB_SET_FLOOR_CLEARANCE" then
                local floorId = tonumber(payload.floorId)
                local level   = tonumber(payload.level)
                if floorId and db.etagen[floorId] and level
                    and level == math.floor(level) and level >= 0 and level <= 5 then
                    db.etagen[floorId].clearance = level
                    saveDB()
                    addLog("ADMIN", string.format("Etage %d clearance geändert auf Level: %d", floorId, level))
                    responsePayload = { status = "OK" }
                else
                    responsePayload = { status = "ERROR", msg = "Etage oder Level ungültig" }
                end

            -- ================================================
            -- 6. LOG-EINTRAG HINZUFÜGEN
            -- ================================================
            elseif cmd == "DB_ADD_LOG" then
                addLog(payload.category, payload.msg)
                responsePayload = { status = "OK" }
            end

            -- Antwort verschlüsseln und zurücksenden
            if responsePayload then
                local packed = crypto.encrypt(responsePayload)
                if packed then
                    rednet.send(senderID, packed, PROTOCOL)
                end
            end
        end
        end -- KELLER_SERVER_ID gate
    end
end
