-- ====================================================
-- SICHERHEITS-SERVER / MONITORING (sec_server.lua)
-- ====================================================
-- Aufgaben:
--  - Überwachung des Sicherheitsstatus & Alarmierung
--  - Schnellauslösung / Aufhebung des Lockdown-Modus
--  - Live-Anzeige von Log-Einträgen & Sicherheitswarnungen
--  - Optionales Steuern lokaler Redstone-Alarme (Sirenen/Lichter)
-- ====================================================

local crypto = require("crypto")

-- ================= CONFIGURATION ====================
local PROTOCOL      = "GEBAEUDE-1-SEC"
local SERVER_ID     = 18    -- ⚙️ Computer-ID deines Keller-Servers (server.lua)
local DB_SERVER_ID  = 19    -- ⚙️ Computer-ID deines DB-Servers (db.lua)
local REDSTONE_SIDE = "top" -- ⚙️ Seite für Alarmsirene/Warnlicht (z.B. "top", "back", "left")
-- ====================================================

-- Modems initialisieren (Funk & Kabel)
crypto.ensureRednet()

-- Redstone-Alarm schalten
local function setAlarm(state)
    if redstone and REDSTONE_SIDE then
        redstone.setOutput(REDSTONE_SIDE, state)
    end
end

-- ----------------------------------------------------
-- Hilfsfunktion: Sichere Kommunikation mit Keller-Server
-- ----------------------------------------------------
local function sendServer(payload)
    local packed, encErr = crypto.encrypt(payload)
    if not packed then
        return nil, "Verschlüsselungsfehler: " .. tostring(encErr)
    end

    rednet.send(SERVER_ID, packed, PROTOCOL)

    local senderID, replyMsg = rednet.receive(PROTOCOL, 3)
    if senderID == SERVER_ID and replyMsg ~= nil then
        local data, decErr = crypto.decrypt(replyMsg)
        if data then return data end
        return nil, "Entschlüsselungsfehler: " .. tostring(decErr)
    end

    return nil, "Keller-Server (ID " .. SERVER_ID .. ") reagiert nicht."
end

-- ----------------------------------------------------
-- Menü-Funktionen
-- ----------------------------------------------------

local function quickLockdown(enable)
    term.clear()
    term.setCursorPos(1,1)
    term.setTextColor(colors.yellow)
    print("==================================")
    print("     LOCKDOWN-SCHNELLAUSLÖSUNG    ")
    print("==================================")
    term.setTextColor(colors.white)

    print(enable and "Aktiviere NOTFALL-LOCKDOWN..." or "Hebe Lockdown auf...")
    local res, err = sendServer({ cmd = "SET_LOCKDOWN", state = enable })

    if res and res.status == "OK" then
        setAlarm(enable)
        if enable then
            term.setTextColor(colors.red)
            print("\n[!] GLOBALER LOCKDOWN AKTIVIERT! [!]")
            print("[!] Sirenen & Relais wurden geschaltet.")
        else
            term.setTextColor(colors.green)
            print("\n[✓] LOCKDOWN ERFOLGREICH AUFGEHOBEN.")
            print("[✓] Normalbetrieb wiederhergestellt.")
        end
    else
        term.setTextColor(colors.red)
        print("\n[X] Fehler beim Ändern des Lockdown-Status: " .. tostring(err))
    end

    term.setTextColor(colors.white)
    sleep(2)
end

local function showSecurityStatus()
    term.clear()
    term.setCursorPos(1,1)
    term.setTextColor(colors.yellow)
    print("==================================")
    print("    SICHERHEITS-STATUSÜBERSICHT   ")
    print("==================================")
    term.setTextColor(colors.white)

    print("Frage Systemstatus ab...\n")
    local res, err = sendServer({ cmd = "GET_STATUS" })

    term.clear()
    term.setCursorPos(1,1)
    term.setTextColor(colors.yellow)
    print("==================================")
    print("    SICHERHEITS-STATUSÜBERSICHT   ")
    print("==================================")
    term.setTextColor(colors.white)

    if not res then
        term.setTextColor(colors.red)
        print("[X] Fehler: " .. tostring(err))
        term.setTextColor(colors.white)
    else
        local isLock = res.isLockdown
        term.setTextColor(isLock and colors.red or colors.green)
        print("LOCKDOWN STATUS: " .. (isLock and "!!! AKTIV !!!" or "INAKTIV (Normalbetrieb)"))
        term.setTextColor(colors.white)

        print("\nEtagenzustand:")
        print("----------------------------------")
        if res.etagen then
            for id, info in pairs(res.etagen) do
                local status = info.locked and "[GESPERRT]" or "[OK]"
                local col = info.locked and colors.red or colors.green
                term.setTextColor(colors.white)
                write(string.format(" Etage %d (%-16s): ", id, info.name or "Etage " .. id))
                term.setTextColor(col)
                print(status)
            end
        end
    end

    term.setTextColor(colors.gray)
    print("\n----------------------------------")
    print("Beliebige Taste drücken für Menü...")
    term.setTextColor(colors.white)
    os.pullEvent("key")
end

local function monitorLiveEvents()
    term.clear()
    term.setCursorPos(1,1)
    term.setTextColor(colors.yellow)
    print("==================================")
    print("    LIVE SECURITY EVENT MONITOR   ")
    print("==================================")
    term.setTextColor(colors.gray)
    print(" Drücke 'q' zum Beenden...\n")
    term.setTextColor(colors.white)

    while true do
        local timerId = os.startTimer(0.5)
        local event, p1, p2, p3 = os.pullEvent()

        if event == "key" and p1 == keys.q then
            break
        elseif event == "rednet_message" and p3 == PROTOCOL then
            local senderID = p1
            local msg = p2
            local payload = crypto.decrypt(msg)

            if payload then
                local timeStr = textutils.formatTime(os.time(), true)
                term.setTextColor(colors.gray)
                write("[" .. timeStr .. "] ")

                if payload.cmd == "SECURITY_ALERT" or payload.category == "SECURITY" then
                    term.setTextColor(colors.red)
                    print("🚨 ALERT (ID " .. senderID .. "): " .. tostring(payload.msg or payload.cmd))
                elseif payload.category == "ACCESS_DENIED" then
                    term.setTextColor(colors.yellow)
                    print("⛔ DENIED (ID " .. senderID .. "): " .. tostring(payload.msg))
                elseif payload.category == "ACCESS_GRANTED" then
                    term.setTextColor(colors.green)
                    print("✓ ACCESS (ID " .. senderID .. "): " .. tostring(payload.msg))
                else
                    term.setTextColor(colors.lightGray)
                    print("ℹ LOG (ID " .. senderID .. "): " .. tostring(payload.msg or payload.cmd))
                end
                term.setTextColor(colors.white)
            end
        end
    end
end

-- ----------------------------------------------------
-- HAUPTSCHLEIFE
-- ----------------------------------------------------
while true do
    term.clear()
    term.setCursorPos(1,1)
    term.setTextColor(colors.red)
    print("==================================")
    print("    SICHERHEITS-ZENTRALE / MONITOR")
    print("==================================")
    term.setTextColor(colors.white)
    print(" Keller-Server ID: " .. SERVER_ID)
    print(" DB-Server ID:     " .. DB_SERVER_ID)
    print("----------------------------------")
    term.setTextColor(colors.red)
    print(" 1. [!] NOTFALL-LOCKDOWN AKTIVIEREN")
    term.setTextColor(colors.green)
    print(" 2. [✓] Lockdown aufheben")
    term.setTextColor(colors.white)
    print(" 3. System- & Etagenstatus anzeigen")
    print(" 4. Live Event-Monitor starten")
    print(" 5. Beenden")
    print("----------------------------------")
    write("Option wählen [1-5]: ")

    local choice = read()

    if choice == "1" then
        quickLockdown(true)
    elseif choice == "2" then
        quickLockdown(false)
    elseif choice == "3" then
        showSecurityStatus()
    elseif choice == "4" then
        monitorLiveEvents()
    elseif choice == "5" then
        term.clear()
        term.setCursorPos(1,1)
        term.setTextColor(colors.yellow)
        print("Sicherheits-Terminal beendet.")
        term.setTextColor(colors.white)
        break
    end
end
