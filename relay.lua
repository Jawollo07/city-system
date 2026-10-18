-- ====================================================
-- ETAGEN-RELAIS / TÜRSTEUERUNG (relay.lua)
-- ====================================================
local crypto = require("crypto")

-- ================= CONFIGURATION ====================
local PROTOCOL = "GEBAEUDE-1-SEC"
local SERVER_ID = 18 -- only accept relay triggers from the Keller-Server
local FLOOR_ID = 0   -- configure per relay: 0=ground, 1=first floor, etc.
local REDSTONE_SIDE = "bottom"
local PULSE_TIME = 18

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

        if senderID ~= SERVER_ID then
            print("Sicherheitswarnung: Relay-Befehl von nicht freigegebener ID " .. tostring(senderID))
        elseif payload and payload.cmd == "TRIGGER_RELAY" then
            local targetFloor = payload.floor
            if type(targetFloor) ~= "number" or targetFloor ~= FLOOR_ID then
                print("Sicherheitswarnung: falsche Ziel-Etage; Relay bleibt aus.")
            else
                redstone.setOutput(REDSTONE_SIDE, true)
                updateDisplay(true, targetFloor)
                local ok, err = pcall(sleep, PULSE_TIME)
                redstone.setOutput(REDSTONE_SIDE, false)
                updateDisplay(false, targetFloor)
                if not ok then print("Relay-Impulsfehler: " .. tostring(err)) end
            end
        else
            if err then
                print("Decrypt-Fehler: " .. tostring(err))
            end
        end
    end
end
