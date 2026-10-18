local crypto = require("crypto")

if not http then
    print("HTTP-API auf diesem Rechner deaktiviert.")
    return
end
if type(crypto.API_TOKEN) ~= "string"
    or crypto.API_TOKEN == ""
    or crypto.API_TOKEN == "REPLACE_WITH_SHARED_API_TOKEN" then
    print("API-Token nicht konfiguriert.")
    return
end

local url = crypto.API_URL .. crypto.NETWORK_NAME
local request = {
    url = url,
    method = "GET",
    headers = {
        ["Authorization"] = "Bearer " .. crypto.API_TOKEN,
        ["User-Agent"] = "CC-Tweaked-Node/" .. tostring(os.getComputerID()),
        ["Accept"] = "application/json"
    }
}

local ok, accepted, requestError = pcall(http.request, request)
if not ok or not accepted then
    print("HTTP-Anfrage konnte nicht gestartet werden: " .. tostring(requestError or accepted))
    return
end

print("Teste API: " .. url)
while true do
    local event, eventUrl, response, responseCode = os.pullEvent()
    if eventUrl == url and event == "http_success" then
        local body = response.readAll()
        response.close()
        print("HTTP " .. tostring(responseCode or "OK"))
        local data = textutils.unserializeJSON(body)
        if data and data.status == "success" and data.key then
            print("API-Schlüsselausgabe erfolgreich.")
            return
        end
        print("HTTP erfolgreich, aber unerwartete API-Antwort:")
        print(body)
        return
    elseif eventUrl == url and event == "http_failure" then
        print("API-Anfrage fehlgeschlagen: " .. tostring(response or "unbekannter Fehler"))
        if responseCode then print("HTTP " .. tostring(responseCode)) end
        return
    end
end
