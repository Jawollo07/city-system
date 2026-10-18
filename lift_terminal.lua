-- ====================================================
-- FAHRSTUHL-TERMINAL (lift_terminal.lua)
-- ====================================================
local crypto = require("crypto")

-- ================= CONFIGURATION ====================
local PROTOCOL = "GEBAEUDE-1-SEC"
local SERVER_ID = 29        -- ⚙️ Keller-Server ID

-- ====================================================
crypto.ensureRednet()

local function sendServer(payload)
    local packed, encErr = crypto.encrypt(payload)
    if not packed then
        return nil, "Krypto-Fehler (Encrypt): " .. tostring(encErr)
    end

    rednet.send(SERVER_ID, packed, PROTOCOL)

    local senderID, replyMsg = rednet.receive(PROTOCOL, 4) -- etwas längeres Timeout
    if senderID ~= SERVER_ID or not replyMsg then
        return nil, "Keine Antwort vom Keller-Server"
    end

    local data, decErr = crypto.decrypt(replyMsg)
    if data then
        return data
    else
        return nil, "Entschlüsselungsfehler: " .. tostring(decErr)
    end
end

-- ====================================================
while true do
    term.clear()
    term.setCursorPos(1, 1)
    term.setTextColor(colors.yellow)
    print("==================================")
    print("   FAHRSTUHL TERMINAL")
    print("==================================")
    term.setTextColor(colors.white)

    print(" Lade Etagenliste...")

    local res, err = sendServer({ cmd = "GET_FLOORS" })

    term.clear()
    term.setCursorPos(1, 1)
    print("==================================")
    print("   FAHRSTUHL TERMINAL")
    print("==================================")

    if not res or res.status ~= "OK" or not res.etagen then
        term.setTextColor(colors.red)
        print("[X] Fehler beim Laden der Etagen:")
        print(tostring(err or (res and res.msg) or "Unbekannt"))
        term.setTextColor(colors.white)
        print("\nDrücke eine Taste zum Wiederholen...")
        os.pullEvent("key")
    else
        -- Etagen anzeigen
        print(" Verfügbare Etagen:")
        print("----------------------------------")
        for id, info in pairs(res.etagen) do
            local status = info.locked and "[GESPERRT]" or "(Lvl " .. (info.clearance or 0) .. ")"
            local col = info.locked and colors.red or colors.cyan
            term.setTextColor(colors.white)
            write(string.format(" [%d] %-15s ", id, info.name or ("Etage "..id)))
            term.setTextColor(col)
            print(status)
        end
        term.setTextColor(colors.white)
        print("----------------------------------")

        write("Ziel-Etage: ")
        local selected = tonumber(read())

        if selected and res.etagen[selected] then
            write("Keycard-ID (Enter = Gast): ")
            local cardId = read()

            print("\nAnfrage wird gesendet...")
            local driveRes, driveErr = sendServer({
                cmd = "REQUEST_ELEVATOR",
                targetFloor = selected,
                cardId = cardId
            })

            term.clear()
            term.setCursorPos(1, 1)
            print("==================================")
            print("       FAHRT-STATUS")
            print("==================================")

            if driveRes and driveRes.status == "OK" then
                term.setTextColor(colors.green)
                print("\n [✓] FAHRT GENEHMIGT!")
                print(" " .. (driveRes.msg or "Gute Fahrt!"))
            else
                term.setTextColor(colors.red)
                print("\n [⛔] ZUGRIFF VERWEIGERT!")
                print(" " .. (driveErr or (driveRes and driveRes.msg) or "Unbekannter Fehler"))
            end

            term.setTextColor(colors.gray)
            print("\n\nZurück in 4 Sekunden...")
            sleep(4)
        else
            term.setTextColor(colors.red)
            print("Ungültige Etage!")
            sleep(1.5)
        end
    end
end
