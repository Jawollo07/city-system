-- ====================================================
-- ETAGEN-RELAIS / TÜRSTEUERUNG (relay.lua)
-- ====================================================
local crypto = require("crypto")

-- ================= CONFIGURATION ====================
local PROTOCOL = "GEBAEUDE-1-SEC"
local REDSTONE_SIDE = "bottom"   -- ⚙️ Anpassen!
local PULSE_TIME = 18          -- Sekunden

-- ====================================================
crypto.ensureRednet()
redstone.setOutput(REDSTONE_SIDE, false)

local function updateDisplay(active, lastTarget)
    term.clear()
    term.setCursorPos(1, 1)
    term.setTextColor(colors.yellow)
    print("==================================================")
    print(" ETAGEN-RELAIS :: SCHALT-KNOTENPUNKT ")
    print("==================================================")
    term.setTextColor(colors.white)
    print(" Computer-ID: " .. os.getComputerID())
    print(" Redstone-Seite: " .. REDSTONE_SIDE)
    print(" Impulsdauer: " .. PULSE_TIME .. "s")
    print("==================================================")

    if active then
        term.setTextColor(colors.green)
        print(" Status: [⚡] REDSTONE AKTIV (TÜR OFFEN)")
    else
        term.setTextColor(colors.gray)
        print(" Status: [ ] Bereitschaft (Tür verriegelt)")
    end

    if lastTarget then
        term.setTextColor(colors.white)
        print("\n Letzter Impuls: Etage " .. tostring(lastTarget))
    end
    print("\n Warte auf TRIGGER_RELAY...")
end

updateDisplay(false, nil)

-- ====================================================
while true do
    local senderID, encryptedMessage, protocol = rednet.receive(PROTOCOL)

    if protocol == PROTOCOL and encryptedMessage then
        local payload, err = crypto.decrypt(encryptedMessage)

        if payload and payload.cmd == "TRIGGER_RELAY" then
            local targetFloor = payload.floor or "?"

            redstone.setOutput(REDSTONE_SIDE, true)
            updateDisplay(true, targetFloor)

            sleep(PULSE_TIME)

            redstone.setOutput(REDSTONE_SIDE, false)
            updateDisplay(false, targetFloor)

            -- Optional: Log an Server senden
            -- crypto.encrypt({cmd = "DB_ADD_LOG", category = "RELAY", msg = "Impuls für Etage "..targetFloor.." ausgeführt"})
        else
            if err then
                print("Decrypt-Fehler: " .. tostring(err))
            end
        end
    end
end
