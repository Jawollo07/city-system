-- ====================================================
-- PROMISCUOUS REDNET / MODEM SNIFFER (MIT LOG-DATEI)
-- ====================================================

local LOG_FILE = "sniffer_log.txt"
local MAX_CHANNEL = 50
local BROADCAST_CHANNEL = 65535

-- Konfiguration der Protokoll-Farben
local PROTOCOL_COLORS = {
    ["GEBAEUDE-1-HSM"] = colors.green,
    ["GEBAEUDE-1-SEC"] = colors.cyan
}

-- Hilfsfunktion: Schreibt sowohl ins Terminal als auch in die Log-Datei
local function logPrint(text)
    -- 1. Normal im Terminal ausgeben
    print(text or "")

    -- 2. In Datei anfügen ("a" für Append)
    local file = fs.open(LOG_FILE, "a")
    if file then
        file.writeLine(text or "")
        file.close()
    end
end

-- UI Header
term.clear()
term.setCursorPos(1, 1)
term.setTextColor(colors.yellow)

logPrint("==================================================")
logPrint("       PROMISCUOUS REDNET SNIFFER (PROFI)         ")
logPrint("==================================================")
term.setTextColor(colors.white)

-- Modems suchen
local modems = { peripheral.find("modem") }
if #modems == 0 then
    error("FEHLER: Kein Modem (Kabel oder Funk) gefunden!", 0)
end

-- Kanäle öffnen
local openedCount = 0
for _, modem in ipairs(modems) do
    for ch = 1, MAX_CHANNEL do
        modem.open(ch)
        openedCount = openedCount + 1
    end
    modem.open(BROADCAST_CHANNEL)
end

logPrint(("Überwache Kanäle 1..%d + Broadcast auf %d Modem(s)."):format(MAX_CHANNEL, #modems))
logPrint("Drücke Strg+T zum Beenden.\n")
logPrint("--------------------------------------------------")

-- Hauptschleife
while true do
    local _, side, channel, replyChannel, rawData, distance = os.pullEvent("modem_message")
    local timeStr = os.date("%H:%M:%S")

    -- Prüfen, ob es sich um ein strukturiertes Rednet-Paket handelt
    if type(rawData) == "table" and rawData.nSender then
        local sender   = rawData.nSender
        local target   = rawData.nRecipient or channel
        local protocol = rawData.sProtocol or "KEIN PROTOKOLL"
        local payload  = rawData.message

        -- Farbzuweisung für Terminal
        local msgColor = PROTOCOL_COLORS[protocol] or colors.lightGray
        term.setTextColor(msgColor)

        logPrint(("[%s] ID %s ➔ ID %s (Kanal %d)"):format(timeStr, tostring(sender), tostring(target), channel))
        logPrint(" ├─ Protokoll: " .. tostring(protocol))

        -- Payload formatieren
        if type(payload) == "table" then
            local success, formatted = pcall(textutils.serialize, payload)
            if success then
                formatted = string.gsub(formatted, "\n", "\n │    ")
                logPrint(" └─ Daten:    " .. formatted)
            else
                logPrint(" └─ Daten:    [Tabelle konnte nicht serialisiert werden]")
            end
        else
            logPrint(" └─ Daten:    " .. tostring(payload))
        end

    else
        -- Rohdaten / Nicht-Rednet-Nachrichten abfangen
        term.setTextColor(colors.orange)
        logPrint(("[%s] RAW-SIGNAL auf Kanal %d (Antwort-Kanal: %d)"):format(timeStr, channel, replyChannel))
        if distance then
            logPrint((" ├─ Distanz:   %.1f Blöcke"):format(distance))
        end
        logPrint(" └─ Inhalt:    " .. tostring(rawData))
    end

    term.setTextColor(colors.gray)
    logPrint("--------------------------------------------------")
    term.setTextColor(colors.white)
end
