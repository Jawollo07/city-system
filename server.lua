-- ====================================================
-- VOLLSTÄNDIGER KELLER-SERVER (server.lua)
-- ====================================================
local crypto = require("crypto")

-- ================= CONFIGURATION ====================
local PROTOCOL = "GEBAEUDE-1-SEC"
local DB_SERVER_ID = 19
local TIMEOUT = 3

-- ====================================================
crypto.ensureRednet()

local isLockdown = false

-- ----------------------------------------------------
-- Hilfsfunktion: Sichere DB-Kommunikation
-- ----------------------------------------------------
local function queryDB(payload)
    local packed, encErr = crypto.encrypt(payload)
    if not packed then
        return nil, "Krypto-Fehler vor DB-Senden: " .. tostring(encErr)
    end

    rednet.send(DB_SERVER_ID, packed, PROTOCOL)
    local senderID, replyMsg = rednet.receive(PROTOCOL, TIMEOUT)

    if senderID == DB_SERVER_ID and replyMsg then
        local data, decErr = crypto.decrypt(replyMsg)
        if data then
            return data
        end
        return nil, "Entschlüsselungsfehler von DB: " .. tostring(decErr)
    end
    return nil, "DB-Server (ID " .. DB_SERVER_ID .. ") reagiert nicht (Timeout)"
end

-- ----------------------------------------------------
local function logToDB(category, message)
    queryDB({
        cmd = "DB_ADD_LOG",
        category = category,
        msg = message
    })
end

-- ----------------------------------------------------
local function updateDisplay()
    term.clear()
    term.setCursorPos(1, 1)
    term.setTextColor(colors.yellow)
    print("==================================================")
    print(" KELLER-SERVER :: LOGIK-KNOTEN ZENTRALE ")
    print("==================================================")
    term.setTextColor(colors.white)
    print(" Server-ID: " .. os.getComputerID())
    print(" DB-Server-ID: " .. DB_SERVER_ID)
    print(" Crypto-HSM ID: " .. crypto.CRYPTO_SERVER_ID)

    if isLockdown then
        term.setTextColor(colors.red)
        print(" Status: [!] GLOBALER LOCKDOWN AKTIV [!]")
    else
        term.setTextColor(colors.green)
        print(" Status: [✓] System im Normalbetrieb")
    end
    term.setTextColor(colors.white)
    print("==================================================")
    print(" Warte auf Anfragen...\n")
end

-- ====================================================
-- SERVER STARTUP
-- ====================================================
updateDisplay()
logToDB("SYSTEM", "Keller-Server online (ID: " .. os.getComputerID() .. ")")

-- ====================================================
-- HAUPTSCHLEIFE
-- ====================================================
while true do
    local senderID, encryptedMessage, protocol = rednet.receive(PROTOCOL)

    if protocol == PROTOCOL and encryptedMessage then
        local payload, err = crypto.decrypt(encryptedMessage)

        if not payload then
            logToDB("ERROR", "Entschlüsselung fehlgeschlagen von ID " .. senderID .. ": " .. tostring(err))
            -- Optional: Antwort mit Fehler
            local errPacked = crypto.encrypt({ status = "ERROR", msg = "Entschlüsselung fehlgeschlagen" })
            if errPacked then rednet.send(senderID, errPacked, PROTOCOL) end
        else
            local cmd = payload.cmd or (payload.result and payload.result.cmd)

            -- ==================== COMMANDS ====================

            if cmd == "GET_FLOORS" then
                local dbReply, dbErr = queryDB({ cmd = "DB_GET_FLOORS" })
                local response = dbReply and dbReply.status == "OK"
                    and { status = "OK", etagen = dbReply.etagen }
                    or { status = "ERROR", msg = "DB-Fehler: " .. tostring(dbErr) }

                local packed = crypto.encrypt(response)
                if packed then rednet.send(senderID, packed, PROTOCOL) end

            elseif cmd == "REQUEST_ELEVATOR" then
                local targetFloor = payload.targetFloor
                local cardId = payload.cardId or ""

                if isLockdown then
                    logToDB("ACCESS_DENIED", string.format("Lockdown: Anfrage ID %d -> Etage %d", senderID, targetFloor or -1))
                    local packed = crypto.encrypt({ status = "DENIED", msg = "LOCKDOWN! Gebäude ist abgeriegelt." })
                    if packed then rednet.send(senderID, packed, PROTOCOL) end
                else
                    -- Keycard + Etagen-Infos holen
                    local cardReply = queryDB({ cmd = "DB_GET_KEYCARD", cardId = cardId })
                    local userLevel = (cardReply and cardReply.level) or payload.userLevel or 0
                    local cardOwner = (cardReply and cardReply.owner) or "Unbekannt"

                    local dbReply = queryDB({ cmd = "DB_GET_FLOORS" })
                    local target = dbReply and dbReply.etagen and dbReply.etagen[targetFloor]

                    local responsePayload

                    if not target then
                        responsePayload = { status = "DENIED", msg = "Ziel-Etage existiert nicht!" }
                    elseif target.locked then
                        logToDB("ACCESS_DENIED", string.format("Gesperrt: %s -> Etage %d", cardOwner, targetFloor))
                        responsePayload = { status = "DENIED", msg = "Etage ist derzeit gesperrt." }
                    elseif userLevel < (target.clearance or 0) then
                        logToDB("ACCESS_DENIED", string.format("Rechte fehlen: %s (Lvl %d) -> Etage %d", cardOwner, userLevel, targetFloor))
                        responsePayload = { status = "DENIED", msg = string.format("Keine Rechte! (Lvl %d nötig)", target.clearance or 0) }
                    else
                        logToDB("ACCESS_GRANTED", string.format("Freigabe: %s (Lvl %d) -> Etage %d", cardOwner, userLevel, targetFloor))
                        responsePayload = { status = "OK", msg = "Fahrt genehmigt!" }

                        if target.relayID then
                            local relayMsg = crypto.encrypt({ cmd = "TRIGGER_RELAY", floor = targetFloor })
                            if relayMsg then rednet.send(target.relayID, relayMsg, PROTOCOL) end
                        end
                    end

                    local packed = crypto.encrypt(responsePayload)
                    if packed then rednet.send(senderID, packed, PROTOCOL) end
                end

            -- Administrative Commands
            elseif cmd == "SET_LOCKDOWN" then
                isLockdown = (payload.state == true)
                updateDisplay()
                logToDB("SECURITY", "Lockdown-Status geändert auf: " .. tostring(isLockdown))
                local packed = crypto.encrypt({ status = "OK", isLockdown = isLockdown })
                if packed then rednet.send(senderID, packed, PROTOCOL) end

            elseif cmd == "GET_STATUS" then
                local dbReply = queryDB({ cmd = "DB_GET_FLOORS" })
                local packed = crypto.encrypt({
                    status = "OK",
                    isLockdown = isLockdown,
                    etagen = dbReply and dbReply.etagen or {}
                })
                if packed then rednet.send(senderID, packed, PROTOCOL) end

            elseif cmd == "TOGGLE_FLOOR" then
                queryDB({ cmd = "DB_SET_FLOOR_LOCK", floorId = payload.floorId, state = payload.state })
                local packed = crypto.encrypt({ status = "OK" })
                if packed then rednet.send(senderID, packed, PROTOCOL) end

            elseif cmd == "SET_CLEARANCE" then
                queryDB({ cmd = "DB_SET_FLOOR_CLEARANCE", floorId = payload.floorId, level = payload.level })
                local packed = crypto.encrypt({ status = "OK" })
                if packed then rednet.send(senderID, packed, PROTOCOL) end

            elseif cmd == "DB_SET_KEYCARD" then
                queryDB({
                    cmd = "DB_SET_KEYCARD",
                    cardId = payload.cardId,
                    owner = payload.owner,
                    level = payload.level
                })
                local packed = crypto.encrypt({ status = "OK" })
                if packed then rednet.send(senderID, packed, PROTOCOL) end
            end
        end
    end
end
