-- ====================================================
-- ADMIN-TERMINAL (admin.lua)
-- ====================================================
-- Aufgaben:
--  - Systemstatus überwachen
--  - Globalen Lockdown steuern
--  - Etagen verwalten & Keycards registrieren
--  - Sichere Kommunikation mit Keller-Server & HSM
--  - KMS API Schlüsselverwaltung & Panik-Rotation
-- ====================================================

local crypto = require("crypto")

-- ================= CONFIGURATION ====================
local PROTOCOL  = "GEBAEUDE-1-SEC"
local SERVER_ID = 18  -- ⚙️ Computer-ID deines Keller-Servers (server.lua)

-- API KMS Konfiguration
-- Uses the shared API key configured once in crypto.lua.
local API_URL   = crypto.API_URL
local API_TOKEN = crypto.API_TOKEN
-- ====================================================

-- Stellen sicher, dass alle Modems (Kabel/Funk) aktiviert sind
crypto.ensureRednet()

-- ----------------------------------------------------
-- Hilfsfunktionen
-- ----------------------------------------------------
local function sendServer(payload)
    -- 1. Payload verpacken / verschlüsseln
    local packed, encErr = crypto.pack(payload)
    if not packed then
        return nil, "Verschlüsselungsfehler: " .. tostring(encErr)
    end

    -- 2. An Keller-Server senden
    rednet.send(SERVER_ID, packed, PROTOCOL)

    -- 3. Antwort empfangen
    local senderID, replyMsg = rednet.receive(PROTOCOL, 3)
    if senderID == SERVER_ID and replyMsg ~= nil then
        local data, decErr = crypto.unpack(replyMsg)
        if data then
            return data
        end
        return nil, "Entschlüsselungsfehler: " .. tostring(decErr)
    end

    return nil, "Keine Antwort vom Keller-Server (ID " .. SERVER_ID .. ")"
end

local function makeApiRequest(url, method)
    if not http then return nil, "HTTP-API auf diesem Rechner deaktiviert!" end
    if API_TOKEN == "" or API_TOKEN == "REPLACE_WITH_SHARED_API_TOKEN" then
        return nil, "API-Token nicht konfiguriert; Anfrage verweigert."
    end

    local headers = {
        ["Authorization"] = "Bearer " .. API_TOKEN,
        ["Accept"]        = "application/json"
    }

    http.request({ url = url, method = method, headers = headers })

    while true do
        local event, p1, p2 = os.pullEvent()
        if event == "http_success" and p1 == url then
            local body = p2.readAll()
            p2.close()
            return textutils.unserializeJSON(body)
        elseif event == "http_failure" and p1 == url then
            -- In CC:Tweaked, http_failure's second argument is usually an error string,
            -- not a response handle. Never call readAll/getResponseCode on it.
            return nil, "API-Anfrage fehlgeschlagen: " .. tostring(p2 or "unbekannter Fehler")
        end
    end
end

-- ----------------------------------------------------
-- Menü-Funktionen
-- ----------------------------------------------------

local function showStatus()
    term.clear()
    term.setCursorPos(1,1)
    term.setTextColor(colors.yellow)
    print("==================================")
    print("        SYSTEM-STATUS             ")
    print("==================================")
    term.setTextColor(colors.white)

    print("Sende Statusabfrage an Server...\n")
    local res, err = sendServer({ cmd = "GET_STATUS" })

    term.clear()
    term.setCursorPos(1,1)
    term.setTextColor(colors.yellow)
    print("==================================")
    print("        SYSTEM-STATUS             ")
    print("==================================")
    term.setTextColor(colors.white)

    if not res then
        term.setTextColor(colors.red)
        print("[X] Fehler: " .. tostring(err))
        term.setTextColor(colors.white)
    else
        local statusText = res.isLockdown and "[!] GLOBALER LOCKDOWN AKTIV [!]" or "[✓] Normalbetrieb (Inaktiv)"
        term.setTextColor(res.isLockdown and colors.red or colors.green)
        print("Lockdown-Status: " .. statusText)
        term.setTextColor(colors.white)

        print("\nEtagen-Übersicht:")
        print("----------------------------------")

        local floorCount = 0
        if res.etagen then
            for id, info in pairs(res.etagen) do
                floorCount = floorCount + 1
                local status = info.locked and "[GESPERRT]" or "[FREI]"
                local col = info.locked and colors.red or colors.green
                term.setTextColor(colors.white)
                write(string.format(" [%d] %-18s (Lvl %d) ", id, info.name or ("Etage " .. id), info.clearance or 0))
                term.setTextColor(col)
                print(status)
            end
        end

        if floorCount == 0 then
            print(" Keine Etageninformationen empfangen.")
        end
    end

    term.setTextColor(colors.gray)
    print("\n----------------------------------")
    print("Beliebige Taste drücken für Menü...")
    term.setTextColor(colors.white)
    os.pullEvent("key")
end

local function toggleLockdown()
    term.clear()
    term.setCursorPos(1,1)
    term.setTextColor(colors.yellow)
    print("==================================")
    print("    GLOBALEN LOCKDOWN STEUERN     ")
    print("==================================")
    term.setTextColor(colors.white)

    write("Lockdown aktivieren? (j/n): ")
    local input = read()

    local state = (input == "j" or input == "J" or input == "ja" or input == "JA")
    print("\nSende Lockdown-Befehl...")
    local res, err = sendServer({ cmd = "SET_LOCKDOWN", state = state })

    if res and res.status == "OK" then
        term.setTextColor(colors.green)
        print("\n[✓] Lockdown-Status erfolgreich geändert auf: " .. tostring(state))
    else
        term.setTextColor(colors.red)
        print("\n[X] Fehler beim Ändern des Lockdown-Status: " .. tostring(err))
    end
    term.setTextColor(colors.white)
    sleep(2)
end

local function manageFloors()
    term.clear()
    term.setCursorPos(1,1)
    term.setTextColor(colors.yellow)
    print("==================================")
    print("        ETAGEN VERWALTEN          ")
    print("==================================")
    term.setTextColor(colors.white)

    write("Etagen-ID eingeben (z.B. 0, 1, 2): ")
    local floorId = tonumber(read())
    if not floorId then
        print("Ungültige Eingabe!")
        sleep(1)
        return
    end

    print("\nAktion wählen:")
    print("1. Sperrstatus umschalten (Lock / Unlock)")
    print("2. Clearance Level (Rechte-Stufe) ändern")
    write("> ")
    local choice = read()

    if choice == "1" then
        write("Etage sperren? (j/n): ")
        local lockInput = read()
        local lockState = (lockInput == "j" or lockInput == "J" or lockInput == "ja")

        local res, err = sendServer({ cmd = "TOGGLE_FLOOR", floorId = floorId, state = lockState })
        if res and res.status == "OK" then
            term.setTextColor(colors.green)
            print("[✓] Sperrstatus erfolgreich geändert!")
        else
            term.setTextColor(colors.red)
            print("[X] Fehler: " .. tostring(err))
        end
    elseif choice == "2" then
        write("Neues Clearance Level (0-5): ")
        local lvl = tonumber(read())
        if lvl and lvl >= 0 and lvl <= 5 then
            local res, err = sendServer({ cmd = "SET_CLEARANCE", floorId = floorId, level = lvl })
            if res and res.status == "OK" then
                term.setTextColor(colors.green)
                print("[✓] Clearance Level aktualisiert!")
            else
                term.setTextColor(colors.red)
                print("[X] Fehler: " .. tostring(err))
            end
        else
            print("Ungültiges Level!")
        end
    end
    term.setTextColor(colors.white)
    sleep(2)
end

local function registerKeycard()
    term.clear()
    term.setCursorPos(1,1)
    term.setTextColor(colors.yellow)
    print("==================================")
    print("  KEYCARD REGISTRIEREN / EDIT     ")
    print("==================================")
    term.setTextColor(colors.white)

    write("Card-ID / Code: ")
    local cardId = read()
    if cardId == "" then return end

    write("Name des Besitzers: ")
    local owner = read()
    if owner == "" then owner = "Unbekannt" end

    write("Freigabe-Level / Clearance (0-5): ")
    local level = tonumber(read()) or 0

    print("\nRegistriere Keycard...")
    local res, err = sendServer({
        cmd = "DB_SET_KEYCARD",
        cardId = cardId,
        owner = owner,
        level = level
    })

    if res and res.status == "OK" then
        term.setTextColor(colors.green)
        print("\n[✓] Keycard erfolgreich gespeichert!")
    else
        term.setTextColor(colors.red)
        print("\n[X] Fehler beim Speichern der Keycard: " .. tostring(err))
    end
    term.setTextColor(colors.white)
    sleep(2)
end

-- NEU: KMS API Schlüsselverwaltung & Panik-Rotation
local function manageKMS()
    term.clear()
    term.setCursorPos(1,1)
    term.setTextColor(colors.yellow)
    print("==================================")
    print("   API KEY-MANAGEMENT (KMS)       ")
    print("==================================")
    term.setTextColor(colors.white)

    write("Netzwerk-Name (z.B. ELEVATOR_NET): ")
    local netName = read()
    if netName == "" then return end

    print("\nAktion wählen:")
    print("1. Berechtigte Geräte auflisten")
    print("2. Computer-ID hinzufügen")
    print("3. Computer-ID entfernen (Sperren)")
    print("4. Sofortige Key-Rotation (Panik-Schalter)")
    write("> ")
    local choice = read()

    if choice == "1" then
        local res, err = makeApiRequest(API_URL .. "networks/" .. netName .. "/devices", "GET")
        if res and res.authorized_devices then
            term.setTextColor(colors.lime)
            print("\nRegistrierte IDs in " .. netName .. ":")
            term.setTextColor(colors.white)
            for _, id in ipairs(res.authorized_devices) do
                print(" • ID " .. id)
            end
        else
            term.setTextColor(colors.red)
            print("\n[X] Fehler: " .. tostring(err))
        end

    elseif choice == "2" then
        write("Aktivierungs-ID eingeben: ")
        local devId = read()
        local res, err = makeApiRequest(API_URL .. netName .. "/devices/" .. devId, "POST")
        if res then
            term.setTextColor(colors.green)
            print("\n[✓] " .. tostring(res.message or "Anfrage erfolgreich."))
            if res.device_token then
                term.setTextColor(colors.yellow)
                print("\nNEUES GERÄTE-TOKEN (wird nur einmal angezeigt):")
                print(res.device_token)
                print("Jetzt sicher auf Computer-ID " .. tostring(devId) .. " hinterlegen.")
                print("Nicht teilen und nicht in Git committen.")
            end
        else
            term.setTextColor(colors.red)
            print("\n[X] Fehler: " .. tostring(err))
        end

    elseif choice == "3" then
        write("Zu sperrende ID eingeben: ")
        local devId = read()
        local res, err = makeApiRequest(API_URL .. "networks/" .. netName .. "/devices/" .. devId, "DELETE")
        if res then
            term.setTextColor(colors.green)
            print("\n[✓] " .. tostring(res.message))
        else
            term.setTextColor(colors.red)
            print("\n[X] Fehler: " .. tostring(err))
        end

    elseif choice == "4" then
        print("\nRotieren...")
        local res, err = makeApiRequest(API_URL .. "rotate/" .. netName, "POST")
        if res then
            term.setTextColor(colors.green)
            print("\n[✓] " .. tostring(res.message))
        else
            term.setTextColor(colors.red)
            print("\n[X] Fehler: " .. tostring(err))
        end
    end

    term.setTextColor(colors.white)
    sleep(2.5)
end

-- ----------------------------------------------------
-- HAUPTMENÜ SCHLEIFE
-- ----------------------------------------------------
while true do
    term.clear()
    term.setCursorPos(1,1)
    term.setTextColor(colors.yellow)
    print("==================================")
    print("     ADMINISTRATIONSTERMINAL      ")
    print("==================================")
    term.setTextColor(colors.white)
    print(" Server-ID: " .. SERVER_ID)
    print(" Protokoll: " .. PROTOCOL)
    print("----------------------------------")
    print(" 1. System-Status anzeigen")
    print(" 2. Globalen Lockdown umschalten")
    print(" 3. Etagen verwalten")
    print(" 4. Keycard registrieren")
    print(" 5. API Schlüsselverwaltung (KMS)")
    print(" 6. Beenden")
    print("----------------------------------")
    write("Option wählen [1-6]: ")

    local choice = read()

    if choice == "1" then
        showStatus()
    elseif choice == "2" then
        toggleLockdown()
    elseif choice == "3" then
        manageFloors()
    elseif choice == "4" then
        registerKeycard()
    elseif choice == "5" then
        manageKMS()
    elseif choice == "6" then
        term.clear()
        term.setCursorPos(1,1)
        term.setTextColor(colors.yellow)
        print("Admin-Terminal beendet.")
        term.setTextColor(colors.white)
        break
    end
end
