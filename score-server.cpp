// license:GPLv3+

#include "plugins/MsgPlugin.h"
#include "plugins/LoggingPlugin.h"
#include "plugins/ControllerPlugin.h"
#include "plugins/VPXPlugin.h"
#include "plugins/ScriptablePlugin.h"

#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <cstdarg>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstring>

// For JSON parsing - using a simple JSON parser approach
#include <map>

// WebSocket support
#ifdef _WIN32
   #define WIN32_LEAN_AND_MEAN
   #undef TEXT
   #include <winsock2.h>
   #include <ws2tcpip.h>
   #pragma comment(lib, "ws2_32.lib")
   typedef int socklen_t;
   #include <windows.h>
#else
   #include <sys/types.h>
   #include <sys/socket.h>
   #include <netinet/in.h>
   #include <arpa/inet.h>
   #include <unistd.h>
   #include <netdb.h>
   #include <dlfcn.h>
   #include <linux/limits.h>
   typedef int SOCKET;
   #define INVALID_SOCKET -1
   #define SOCKET_ERROR -1
   #define closesocket close
#endif

namespace ScoreServer {

const MsgPluginAPI* msgApi = nullptr;
VPXPluginAPI* vpxApi = nullptr;
ScriptablePluginAPI* scriptApi = nullptr;

uint32_t endpointId;
unsigned int getVpxApiId, getScriptApiId, getControllerId, onGameEndId, onGameStartId, onPrepareFrameId;

std::string currentRomName;
std::string nvramMapsPath;
std::string currentMapPath;
std::vector<uint8_t> nvramData;

// TODO: To get NVRAM directly from the Controller, we need the PinMAME plugin to expose
// the Controller object pointer via a message or event. For now, this remains nullptr
// and we fall back to reading from disk files.
void* pinmameController = nullptr;  // Pointer to PinMAME Controller object (not currently available)

// Previous game state for change detection
std::vector<std::string> previousScores;
int previousPlayerCount = 0;
int previousCurrentPlayer = 0;
int previousCurrentBall = 0;

// WebSocket server
std::atomic<bool> wsServerRunning{false};
std::thread wsServerThread;
SOCKET wsServerSocket = INVALID_SOCKET;
std::vector<SOCKET> wsClients;
std::mutex wsClientsMutex;

PSC_USE_ERROR();
PSC_ERROR_IMPLEMENT(scriptApi);

LPI_IMPLEMENT // Implement shared log support

#define LOGD LPI_LOGD
#define LOGI LPI_LOGI
#define LOGW LPI_LOGW
#define LOGE LPI_LOGE

///////////////////////////////////////////////////////////////////////////////
// WebSocket implementation

// Base64 encoding for WebSocket handshake
static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const unsigned char* data, size_t len) {
    std::string ret;
    int i = 0;
    unsigned char array_3[3];
    unsigned char array_4[4];

    while (len--) {
        array_3[i++] = *(data++);
        if (i == 3) {
            array_4[0] = (array_3[0] & 0xfc) >> 2;
            array_4[1] = ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
            array_4[2] = ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);
            array_4[3] = array_3[2] & 0x3f;

            for(i = 0; i < 4; i++)
                ret += base64_chars[array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(int j = i; j < 3; j++)
            array_3[j] = '\0';

        array_4[0] = (array_3[0] & 0xfc) >> 2;
        array_4[1] = ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
        array_4[2] = ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);

        for (int j = 0; j < i + 1; j++)
            ret += base64_chars[array_4[j]];

        while(i++ < 3)
            ret += '=';
    }

    return ret;
}

// SHA-1 hash for WebSocket handshake
void sha1(const std::string& input, unsigned char output[20]) {
    // Simplified SHA-1 implementation
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    std::vector<uint8_t> msg(input.begin(), input.end());
    size_t ml = msg.size() * 8;
    msg.push_back(0x80);
    while ((msg.size() % 64) != 56) {
        msg.push_back(0);
    }
    for (int i = 7; i >= 0; i--) {
        msg.push_back((ml >> (i * 8)) & 0xFF);
    }

    for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++) {
            w[i] = (msg[chunk + i*4] << 24) | (msg[chunk + i*4 + 1] << 16) |
                   (msg[chunk + i*4 + 2] << 8) | msg[chunk + i*4 + 3];
        }
        for (int i = 16; i < 80; i++) {
            uint32_t temp = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
            w[i] = (temp << 1) | (temp >> 31);
        }

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
            e = d;
            d = c;
            c = (b << 30) | (b >> 2);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    for (int i = 0; i < 4; i++) {
        output[i] = (h0 >> (24 - i * 8)) & 0xFF;
        output[i + 4] = (h1 >> (24 - i * 8)) & 0xFF;
        output[i + 8] = (h2 >> (24 - i * 8)) & 0xFF;
        output[i + 12] = (h3 >> (24 - i * 8)) & 0xFF;
        output[i + 16] = (h4 >> (24 - i * 8)) & 0xFF;
    }
}

// Send WebSocket frame
void sendWebSocketFrame(SOCKET sock, const std::string& message) {
    std::vector<uint8_t> frame;
    frame.push_back(0x81); // FIN + text frame

    size_t len = message.size();
    if (len < 126) {
        frame.push_back(static_cast<uint8_t>(len));
    } else if (len < 65536) {
        frame.push_back(126);
        frame.push_back((len >> 8) & 0xFF);
        frame.push_back(len & 0xFF);
    } else {
        frame.push_back(127);
        for (int i = 7; i >= 0; i--) {
            frame.push_back((len >> (i * 8)) & 0xFF);
        }
    }

    frame.insert(frame.end(), message.begin(), message.end());
    send(sock, reinterpret_cast<const char*>(frame.data()), frame.size(), 0);
}

// Broadcast to all WebSocket clients
void broadcastWebSocket(const std::string& message) {
    std::lock_guard<std::mutex> lock(wsClientsMutex);
    auto it = wsClients.begin();
    while (it != wsClients.end()) {
        if (send(*it, nullptr, 0, 0) == SOCKET_ERROR) {
            // Client disconnected
            closesocket(*it);
            it = wsClients.erase(it);
        } else {
            sendWebSocketFrame(*it, message);
            ++it;
        }
    }
}

// Get the plugin installation directory
std::string GetPluginDirectory() {
#ifdef _WIN32
    HMODULE hm = nullptr;
    if (GetModuleHandleEx(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)"ScoreServerPluginLoad", &hm) == 0)
        return "";

    char path[MAX_PATH];
    if (GetModuleFileNameA(hm, path, MAX_PATH) == 0)
        return "";

    std::string pathStr(path);
    size_t pos = pathStr.find_last_of("\\/");
    if (pos != std::string::npos)
        return pathStr.substr(0, pos);
    return "";
#else
    Dl_info info{};
    if (dladdr((void*)&GetPluginDirectory, &info) == 0 || !info.dli_fname)
        return "";

    char realBuf[PATH_MAX];
    if (!realpath(info.dli_fname, realBuf))
        return "";

    std::string pathStr(realBuf);
    size_t pos = pathStr.find_last_of('/');
    if (pos != std::string::npos)
        return pathStr.substr(0, pos);
    return "";
#endif
}

// Simple JSON value class for parsing
struct JsonValue {
    enum Type { STRING, NUMBER, OBJECT, ARRAY, BOOLEAN, NULL_TYPE };
    Type type;
    std::string strValue;
    int64_t numValue;
    std::map<std::string, JsonValue*> objValue;
    std::vector<JsonValue*> arrayValue;
    bool boolValue;

    JsonValue() : type(NULL_TYPE), numValue(0), boolValue(false) {}

    ~JsonValue() {
        for (auto& p : objValue)
            delete p.second;
        for (auto& v : arrayValue)
            delete v;
    }

    const JsonValue* get(const char* key) const {
        auto it = objValue.find(key);
        return (it != objValue.end()) ? it->second : nullptr;
    }

    const JsonValue* at(size_t index) const {
        return (index < arrayValue.size()) ? arrayValue[index] : nullptr;
    }
};

// Simple JSON parser
class SimpleJsonParser {
private:
    const char* pos;
    const char* end;

    void skipWhitespace() {
        while (pos < end && (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r'))
            pos++;
    }

    std::string parseString() {
        if (*pos != '"') return "";
        pos++; // skip opening quote

        std::string result;
        while (pos < end && *pos != '"') {
            if (*pos == '\\' && pos + 1 < end) {
                pos++;
                switch (*pos) {
                    case 'n': result += '\n'; break;
                    case 't': result += '\t'; break;
                    case 'r': result += '\r'; break;
                    case '\\': result += '\\'; break;
                    case '"': result += '"'; break;
                    case 'u': // Unicode escape - simplified handling
                        pos += 4; // skip the 4 hex digits
                        result += '?'; // placeholder
                        break;
                    default: result += *pos; break;
                }
            } else {
                result += *pos;
            }
            pos++;
        }

        if (pos < end) pos++; // skip closing quote
        return result;
    }

    int64_t parseNumber() {
        int64_t result = 0;
        bool negative = false;

        if (*pos == '-') {
            negative = true;
            pos++;
        }

        while (pos < end && *pos >= '0' && *pos <= '9') {
            result = result * 10 + (*pos - '0');
            pos++;
        }

        // Skip decimal part if present (we only need integers for offsets)
        if (pos < end && *pos == '.') {
            pos++;
            while (pos < end && *pos >= '0' && *pos <= '9')
                pos++;
        }

        return negative ? -result : result;
    }

    JsonValue* parseValue();

    JsonValue* parseObject() {
        JsonValue* obj = new JsonValue();
        obj->type = JsonValue::OBJECT;

        pos++; // skip {
        skipWhitespace();

        while (pos < end && *pos != '}') {
            skipWhitespace();
            if (*pos == '}') break;

            if (*pos != '"') {
                delete obj;
                return nullptr;
            }

            std::string key = parseString();
            skipWhitespace();

            if (pos >= end || *pos != ':') {
                delete obj;
                return nullptr;
            }
            pos++; // skip :

            skipWhitespace();
            JsonValue* value = parseValue();
            if (!value) {
                delete obj;
                return nullptr;
            }

            obj->objValue[key] = value;

            skipWhitespace();
            if (pos < end && *pos == ',') {
                pos++;
                skipWhitespace();
            }
        }

        if (pos < end) pos++; // skip }
        return obj;
    }

    JsonValue* parseArray() {
        JsonValue* arr = new JsonValue();
        arr->type = JsonValue::ARRAY;

        pos++; // skip [
        skipWhitespace();

        while (pos < end && *pos != ']') {
            skipWhitespace();
            if (*pos == ']') break;

            JsonValue* value = parseValue();
            if (!value) {
                delete arr;
                return nullptr;
            }

            arr->arrayValue.push_back(value);

            skipWhitespace();
            if (pos < end && *pos == ',') {
                pos++;
                skipWhitespace();
            }
        }

        if (pos < end) pos++; // skip ]
        return arr;
    }

public:
    JsonValue* parse(const std::string& json) {
        pos = json.c_str();
        end = pos + json.length();
        skipWhitespace();
        return parseValue();
    }
};

JsonValue* SimpleJsonParser::parseValue() {
    skipWhitespace();
    if (pos >= end) return nullptr;

    if (*pos == '"') {
        JsonValue* v = new JsonValue();
        v->type = JsonValue::STRING;
        v->strValue = parseString();
        return v;
    }
    else if (*pos == '{') {
        return parseObject();
    }
    else if (*pos == '[') {
        return parseArray();
    }
    else if (*pos == 't' || *pos == 'f') {
        JsonValue* v = new JsonValue();
        v->type = JsonValue::BOOLEAN;
        if (*pos == 't') {
            v->boolValue = true;
            pos += 4; // skip "true"
        } else {
            v->boolValue = false;
            pos += 5; // skip "false"
        }
        return v;
    }
    else if (*pos == 'n') {
        JsonValue* v = new JsonValue();
        v->type = JsonValue::NULL_TYPE;
        pos += 4; // skip "null"
        return v;
    }
    else if (*pos == '-' || (*pos >= '0' && *pos <= '9')) {
        JsonValue* v = new JsonValue();
        v->type = JsonValue::NUMBER;
        v->numValue = parseNumber();
        return v;
    }

    return nullptr;
}

///////////////////////////////////////////////////////////////////////////////
// WebSocket Server

void webSocketServerThread() {
    LOGI("WebSocket server thread starting...");

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOGE("WSAStartup failed");
        return;
    }
#endif

    wsServerSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (wsServerSocket == INVALID_SOCKET) {
        LOGE("Failed to create WebSocket server socket");
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    int opt = 1;
    setsockopt(wsServerSocket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(3131);

    if (bind(wsServerSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        LOGE("Failed to bind WebSocket server to port 3131 (errno: %d)", errno);
        closesocket(wsServerSocket);
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    if (listen(wsServerSocket, 5) == SOCKET_ERROR) {
        LOGE("Failed to listen on WebSocket server socket (errno: %d)", errno);
        closesocket(wsServerSocket);
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    LOGI("WebSocket server listening on 0.0.0.0:3131 (all network interfaces)");

    while (wsServerRunning) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(wsServerSocket, &readfds);

        timeval timeout{};
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(wsServerSocket + 1, &readfds, nullptr, nullptr, &timeout);
        if (activity < 0) break;
        if (activity == 0) continue;

        if (FD_ISSET(wsServerSocket, &readfds)) {
            sockaddr_in clientAddr{};
            socklen_t clientLen = sizeof(clientAddr);
            SOCKET clientSocket = accept(wsServerSocket, reinterpret_cast<sockaddr*>(&clientAddr), &clientLen);

            if (clientSocket != INVALID_SOCKET) {
                LOGI("New WebSocket connection from %s", inet_ntoa(clientAddr.sin_addr));

                // Read HTTP upgrade request
                char buffer[4096];
                int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
                if (bytesRead > 0) {
                    buffer[bytesRead] = '\0';
                    std::string request(buffer);

                    // Extract Sec-WebSocket-Key
                    size_t keyPos = request.find("Sec-WebSocket-Key: ");
                    if (keyPos != std::string::npos) {
                        keyPos += 19;
                        size_t keyEnd = request.find("\r\n", keyPos);
                        std::string key = request.substr(keyPos, keyEnd - keyPos);

                        // Generate accept key
                        key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                        unsigned char hash[20];
                        sha1(key, hash);
                        std::string acceptKey = base64_encode(hash, 20);

                        // Send WebSocket handshake response
                        std::string response =
                            "HTTP/1.1 101 Switching Protocols\r\n"
                            "Upgrade: websocket\r\n"
                            "Connection: Upgrade\r\n"
                            "Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n";

                        send(clientSocket, response.c_str(), response.length(), 0);

                        // Add client to list
                        {
                            std::lock_guard<std::mutex> lock(wsClientsMutex);
                            wsClients.push_back(clientSocket);
                        }

                        LOGI("WebSocket handshake completed, %zu clients connected", wsClients.size());
                    } else {
                        closesocket(clientSocket);
                    }
                } else {
                    closesocket(clientSocket);
                }
            }
        }
    }

    // Cleanup
    {
        std::lock_guard<std::mutex> lock(wsClientsMutex);
        for (SOCKET client : wsClients) {
            closesocket(client);
        }
        wsClients.clear();
    }

    closesocket(wsServerSocket);
#ifdef _WIN32
    WSACleanup();
#endif

    LOGI("WebSocket server thread stopped");
}

// Decode BCD (Binary-Coded Decimal) from NVRAM bytes
std::string decodeBCD(const std::vector<uint8_t>& nvram, size_t start, size_t length) {
    if (start + length > nvram.size()) {
        return "ERROR";
    }

    std::stringstream result;
    for (size_t i = 0; i < length; i++) {
        uint8_t byte = nvram[start + i];
        uint8_t high = (byte >> 4) & 0x0F;
        uint8_t low = byte & 0x0F;

        // BCD digits should be 0-9
        if (high <= 9) result << (char)('0' + high);
        if (low <= 9) result << (char)('0' + low);
    }

    return result.str();
}

// Decode character string from NVRAM bytes
std::string decodeChar(const std::vector<uint8_t>& nvram, size_t start, size_t length) {
    if (start + length > nvram.size()) {
        return "ERROR";
    }

    std::string result;
    for (size_t i = 0; i < length; i++) {
        char c = (char)nvram[start + i];
        if (c >= 32 && c <= 126) { // printable ASCII
            result += c;
        } else {
            result += '?';
        }
    }

    return result;
}

// Get NVRAM data directly from PinMAME Controller via Scriptable API
bool getNVRAMFromController(std::vector<uint8_t>& nvram) {
    if (!scriptApi) {
        LOGW("ScriptAPI not available");
        return false;
    }

    if (!pinmameController) {
        LOGW("PinMAME Controller not available");
        return false;
    }

    // Get the Controller class definition
    ScriptClassDef* controllerClass = scriptApi->GetClassDef("Controller");
    if (!controllerClass) {
        LOGE("Failed to get Controller class definition");
        return false;
    }

    // Find the NVRAM property member
    int nvramMemberIndex = -1;
    for (unsigned int i = 0; i < controllerClass->nMembers; i++) {
        if (std::string(controllerClass->members[i].name.name) == "NVRAM") {
            nvramMemberIndex = i;
            break;
        }
    }

    if (nvramMemberIndex < 0) {
        LOGE("Failed to find NVRAM property in Controller class");
        return false;
    }

    // Call the NVRAM property getter
    ScriptVariant result;
    controllerClass->members[nvramMemberIndex].Call(pinmameController, nvramMemberIndex, nullptr, &result);

    // Extract byte array from result - ByteArray is a ScriptArray*
    ScriptArray* arr = result.vArray;
    if (!arr) {
        LOGE("NVRAM array is null");
        return false;
    }

    // ScriptArray has lengths[] array where lengths[0] is the size
    // Data follows immediately after the lengths array
    size_t arraySize = arr->lengths[0];

    // The data is stored right after the lengths array (1 dimension = 1 length value)
    uint8_t* dataPtr = reinterpret_cast<uint8_t*>(&arr->lengths[1]);

    // Copy bytes from array
    nvram.resize(arraySize);
    memcpy(nvram.data(), dataPtr, arraySize);

    // Release the array
    if (arr->Release) {
        arr->Release(arr);
    }

    return true;
}

// Extract current player scores from game_state
void extractAndLogCurrentScores() {
    if (!pinmameController || !scriptApi) {
        return; // Can't get live NVRAM without Controller
    }

    if (currentMapPath.empty()) {
        return; // No map loaded
    }

    // Get current NVRAM
    std::vector<uint8_t> liveNvram;
    if (!getNVRAMFromController(liveNvram)) {
        return;
    }

    // Read the JSON map file
    std::ifstream file(currentMapPath);
    if (!file.is_open()) {
        return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string jsonContent = buffer.str();
    file.close();

    // Parse JSON
    SimpleJsonParser parser;
    JsonValue* root = parser.parse(jsonContent);
    if (!root || root->type != JsonValue::OBJECT) {
        delete root;
        return;
    }

    // Get game_state section
    const JsonValue* gameState = root->get("game_state");
    if (!gameState || gameState->type != JsonValue::OBJECT) {
        delete root;
        return;
    }

    // Get player count
    const JsonValue* playerCountObj = gameState->get("player_count");
    int playerCount = 0;
    if (playerCountObj && playerCountObj->type == JsonValue::OBJECT) {
        const JsonValue* startVal = playerCountObj->get("start");
        if (startVal && startVal->numValue < (int64_t)liveNvram.size()) {
            playerCount = liveNvram[startVal->numValue];
        }
    }

    // Get current player
    const JsonValue* currentPlayerObj = gameState->get("current_player");
    int currentPlayer = 0;
    if (currentPlayerObj && currentPlayerObj->type == JsonValue::OBJECT) {
        const JsonValue* startVal = currentPlayerObj->get("start");
        if (startVal && startVal->numValue < (int64_t)liveNvram.size()) {
            currentPlayer = liveNvram[startVal->numValue];
        }
    }

    // Get current ball
    const JsonValue* currentBallObj = gameState->get("current_ball");
    int currentBall = 0;
    if (currentBallObj && currentBallObj->type == JsonValue::OBJECT) {
        const JsonValue* startVal = currentBallObj->get("start");
        if (startVal && startVal->numValue < (int64_t)liveNvram.size()) {
            currentBall = liveNvram[startVal->numValue];
        }
    }

    // Get scores array
    const JsonValue* scores = gameState->get("scores");
    if (!scores || scores->type != JsonValue::ARRAY) {
        delete root;
        return;
    }

    // Build output
    std::stringstream output;
    output << "=== Current Game Status for " << currentRomName << " ===\n";
    output << "Players: " << playerCount << " | Current Player: " << currentPlayer << " | Ball: " << currentBall << "\n";
    output << "----------------------------------------\n";

    // Extract each player's score
    for (size_t i = 0; i < scores->arrayValue.size() && i < (size_t)playerCount; i++) {
        const JsonValue* scoreEntry = scores->at(i);
        if (!scoreEntry || scoreEntry->type != JsonValue::OBJECT) continue;

        const JsonValue* labelVal = scoreEntry->get("label");
        const JsonValue* startVal = scoreEntry->get("start");
        const JsonValue* lengthVal = scoreEntry->get("length");
        const JsonValue* encodingVal = scoreEntry->get("encoding");

        if (!labelVal || !startVal || !lengthVal || !encodingVal) continue;

        std::string score;
        if (encodingVal->strValue == "bcd") {
            score = decodeBCD(liveNvram, startVal->numValue, lengthVal->numValue);
        } else if (encodingVal->strValue == "int") {
            uint64_t value = 0;
            size_t len = lengthVal->numValue;
            if (startVal->numValue + len <= liveNvram.size()) {
                for (size_t j = 0; j < len; j++) {
                    value = (value << 8) | liveNvram[startVal->numValue + j];
                }
                score = std::to_string(value);
            } else {
                score = "ERROR";
            }
        } else {
            score = "???";
        }

        std::string playerMarker = (i + 1 == (size_t)currentPlayer) ? " <-- PLAYING" : "";
        output << labelVal->strValue << ": " << std::right << std::setw(15) << score << playerMarker << "\n";
    }

    LOGI("Current Scores:\n%s", output.str().c_str());

    // Broadcast via WebSocket as JSON
    std::stringstream jsonOutput;
    jsonOutput << "{\"type\":\"current_scores\",\"rom\":\"" << currentRomName << "\","
               << "\"players\":" << playerCount << ","
               << "\"current_player\":" << currentPlayer << ","
               << "\"current_ball\":" << currentBall << ","
               << "\"scores\":[";

    for (size_t i = 0; i < scores->arrayValue.size() && i < (size_t)playerCount; i++) {
        const JsonValue* scoreEntry = scores->at(i);
        if (!scoreEntry || scoreEntry->type != JsonValue::OBJECT) continue;

        const JsonValue* labelVal = scoreEntry->get("label");
        const JsonValue* startVal = scoreEntry->get("start");
        const JsonValue* lengthVal = scoreEntry->get("length");
        const JsonValue* encodingVal = scoreEntry->get("encoding");

        if (!labelVal || !startVal || !lengthVal || !encodingVal) continue;

        std::string score;
        if (encodingVal->strValue == "bcd") {
            score = decodeBCD(liveNvram, startVal->numValue, lengthVal->numValue);
        } else if (encodingVal->strValue == "int") {
            uint64_t value = 0;
            size_t len = lengthVal->numValue;
            if (startVal->numValue + len <= liveNvram.size()) {
                for (size_t j = 0; j < len; j++) {
                    value = (value << 8) | liveNvram[startVal->numValue + j];
                }
                score = std::to_string(value);
            }
        }

        if (i > 0) jsonOutput << ",";
        jsonOutput << "{\"player\":\"" << labelVal->strValue << "\",\"score\":\"" << score << "\"}";
    }

    jsonOutput << "]}";
    broadcastWebSocket(jsonOutput.str());

    // Clean up JSON data after we're done using it
    delete root;
}

// Extract high scores using the JSON map
bool extractHighScores(const std::string& mapFilePath, const std::vector<uint8_t>& nvram, std::string& output) {
    // Read the JSON map file
    std::ifstream file(mapFilePath);
    if (!file.is_open()) {
        LOGE("Failed to open map file: %s", mapFilePath.c_str());
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string jsonContent = buffer.str();
    file.close();

    // Parse JSON
    SimpleJsonParser parser;
    JsonValue* root = parser.parse(jsonContent);
    if (!root || root->type != JsonValue::OBJECT) {
        LOGE("Failed to parse JSON map file");
        delete root;
        return false;
    }

    // Get high_scores array
    const JsonValue* highScores = root->get("high_scores");
    if (!highScores || highScores->type != JsonValue::ARRAY) {
        LOGE("No high_scores array found in map file");
        delete root;
        return false;
    }

    std::stringstream outStream;
    outStream << "High Scores for " << currentRomName << "\n";
    outStream << "================================================\n\n";

    // Process each high score entry
    for (size_t i = 0; i < highScores->arrayValue.size(); i++) {
        const JsonValue* entry = highScores->at(i);
        if (!entry || entry->type != JsonValue::OBJECT) continue;

        const JsonValue* labelVal = entry->get("label");
        const JsonValue* initialsVal = entry->get("initials");
        const JsonValue* scoreVal = entry->get("score");

        if (!labelVal || !initialsVal || !scoreVal) continue;

        std::string label = labelVal->strValue;

        // Extract initials
        const JsonValue* initStart = initialsVal->get("start");
        const JsonValue* initLength = initialsVal->get("length");
        const JsonValue* initEncoding = initialsVal->get("encoding");

        if (!initStart || !initLength || !initEncoding) continue;

        std::string initials;
        if (initEncoding->strValue == "ch") {
            initials = decodeChar(nvram, initStart->numValue, initLength->numValue);
        } else {
            initials = "???";
        }

        // Extract score
        const JsonValue* scoreStart = scoreVal->get("start");
        const JsonValue* scoreLength = scoreVal->get("length");
        const JsonValue* scoreEncoding = scoreVal->get("encoding");

        if (!scoreStart || !scoreLength || !scoreEncoding) continue;

        std::string score;
        if (scoreEncoding->strValue == "bcd") {
            score = decodeBCD(nvram, scoreStart->numValue, scoreLength->numValue);
        } else if (scoreEncoding->strValue == "int") {
            // Simple integer decoding (big-endian)
            uint64_t value = 0;
            size_t len = scoreLength->numValue;
            if (scoreStart->numValue + len <= nvram.size()) {
                for (size_t j = 0; j < len; j++) {
                    value = (value << 8) | nvram[scoreStart->numValue + j];
                }
                score = std::to_string(value);
            } else {
                score = "ERROR";
            }
        } else {
            score = "???";
        }

        // Format output
        outStream << std::left << std::setw(20) << label << " : "
                  << std::setw(5) << initials << " - "
                  << std::right << std::setw(15) << score << "\n";
    }

    delete root;

    output = outStream.str();
    return true;
}

// Shared function to extract and save high scores
void extractAndSaveHighScores(const char* eventName) {
    LOGI("%s - extracting high scores", eventName);

    if (currentRomName.empty()) {
        LOGW("No ROM name available, skipping high score extraction");
        return;
    }

    // Find the map file for this ROM
    std::string indexPath = nvramMapsPath + "/index.json";
    std::ifstream indexFile(indexPath);
    if (!indexFile.is_open()) {
        LOGE("Failed to open index.json at: %s", indexPath.c_str());
        return;
    }

    std::stringstream buffer;
    buffer << indexFile.rdbuf();
    std::string indexJson = buffer.str();
    indexFile.close();

    // Parse index to find map file
    SimpleJsonParser parser;
    JsonValue* index = parser.parse(indexJson);
    if (!index || index->type != JsonValue::OBJECT) {
        LOGE("Failed to parse index.json");
        delete index;
        return;
    }

    const JsonValue* mapPathVal = index->get(currentRomName.c_str());
    if (!mapPathVal || mapPathVal->type != JsonValue::STRING) {
        LOGW("No map found for ROM: %s", currentRomName.c_str());
        delete index;
        return;
    }

    std::string mapPath = nvramMapsPath + "/" + mapPathVal->strValue;
    delete index;

    LOGI("Using map file: %s", mapPath.c_str());

    // Store map path for current score extraction
    currentMapPath = mapPath;

    // Try to get NVRAM from Controller first
    bool gotNVRAM = false;
    if (scriptApi && pinmameController) {
        LOGI("Attempting to get NVRAM from PinMAME Controller");
        gotNVRAM = getNVRAMFromController(nvramData);
    }

    // Fall back to reading from disk if Controller method failed
    if (!gotNVRAM) {
        LOGI("Getting NVRAM from disk file");
        // Try to read NVRAM file from disk
    // PinMAME stores .nv files in the nvram subdirectory
    if (vpxApi) {
        VPXInfo vpxInfo;
        vpxApi->GetVpxInfo(&vpxInfo);

        // Try common PinMAME NVRAM locations
        // The triple slashes you saw (///) suggest prefPath already ends with a slash
        std::string prefPath = vpxInfo.prefPath;

        // Remove trailing slashes
        while (!prefPath.empty() && (prefPath.back() == '/' || prefPath.back() == '\\')) {
            prefPath.pop_back();
        }

        std::vector<std::string> nvramPaths = {
            prefPath + "/pinmame/nvram/" + currentRomName + ".nv",
            prefPath + "/nvram/" + currentRomName + ".nv",
            prefPath + "/.pinmame/nvram/" + currentRomName + ".nv",
            std::string(getenv("HOME") ? getenv("HOME") : "") + "/.pinmame/nvram/" + currentRomName + ".nv",
        };

        LOGI("Searching for NVRAM file in %zu locations...", nvramPaths.size());
        bool found = false;
        for (const auto& nvPath : nvramPaths) {
            LOGD("  Trying: %s", nvPath.c_str());
            std::ifstream nvFile(nvPath, std::ios::binary);
            if (nvFile.is_open()) {
                nvFile.seekg(0, std::ios::end);
                size_t size = nvFile.tellg();
                nvFile.seekg(0, std::ios::beg);

                nvramData.resize(size);
                nvFile.read(reinterpret_cast<char*>(nvramData.data()), size);
                nvFile.close();

                LOGI("Read NVRAM file: %s (%zu bytes)", nvPath.c_str(), size);
                found = true;
                break;
            }
        }

        if (!found) {
            LOGE("Failed to find NVRAM file for ROM: %s", currentRomName.c_str());
            LOGE("Checked locations:");
            for (const auto& nvPath : nvramPaths) {
                LOGE("  - %s", nvPath.c_str());
            }
            LOGE("Hint: Make sure PinMAME has saved the NVRAM file by playing the game first");
            return;
        }
    }
    } // End of disk fallback

    // Extract high scores - build JSON directly
    std::ifstream mapFile(mapPath);
    if (!mapFile.is_open()) {
        LOGE("Failed to open map file for high scores: %s", mapPath.c_str());
        return;
    }

    std::stringstream mapBuffer;
    mapBuffer << mapFile.rdbuf();
    std::string mapJsonContent = mapBuffer.str();
    mapFile.close();

    // Parse JSON map
    SimpleJsonParser mapParser;
    JsonValue* mapRoot = mapParser.parse(mapJsonContent);
    if (!mapRoot || mapRoot->type != JsonValue::OBJECT) {
        LOGE("Failed to parse JSON map file for high scores");
        delete mapRoot;
        return;
    }

    // Get high_scores array
    const JsonValue* highScores = mapRoot->get("high_scores");
    if (!highScores || highScores->type != JsonValue::ARRAY) {
        LOGE("No high_scores array found in map file");
        delete mapRoot;
        return;
    }

    // Build JSON output with structured high scores
    std::stringstream jsonOutput;
    jsonOutput << "{\"type\":\"high_scores\",\"rom\":\"" << currentRomName << "\",\"scores\":[";

    // Also build text output for logging
    std::stringstream textOutput;
    textOutput << "High Scores for " << currentRomName << "\n";
    textOutput << "================================================\n\n";

    bool firstEntry = true;
    for (size_t i = 0; i < highScores->arrayValue.size(); i++) {
        const JsonValue* entry = highScores->at(i);
        if (!entry || entry->type != JsonValue::OBJECT) continue;

        const JsonValue* labelVal = entry->get("label");
        const JsonValue* initialsVal = entry->get("initials");
        const JsonValue* scoreVal = entry->get("score");

        if (!labelVal || !initialsVal || !scoreVal) continue;

        std::string label = labelVal->strValue;

        // Extract initials
        const JsonValue* initStart = initialsVal->get("start");
        const JsonValue* initLength = initialsVal->get("length");
        const JsonValue* initEncoding = initialsVal->get("encoding");

        if (!initStart || !initLength || !initEncoding) continue;

        std::string initials;
        if (initEncoding->strValue == "ch") {
            initials = decodeChar(nvramData, initStart->numValue, initLength->numValue);
        } else {
            initials = "???";
        }

        // Extract score
        const JsonValue* scoreStart = scoreVal->get("start");
        const JsonValue* scoreLength = scoreVal->get("length");
        const JsonValue* scoreEncoding = scoreVal->get("encoding");

        if (!scoreStart || !scoreLength || !scoreEncoding) continue;

        std::string score;
        if (scoreEncoding->strValue == "bcd") {
            score = decodeBCD(nvramData, scoreStart->numValue, scoreLength->numValue);
        } else if (scoreEncoding->strValue == "int") {
            uint64_t value = 0;
            size_t len = scoreLength->numValue;
            if (scoreStart->numValue + len <= nvramData.size()) {
                for (size_t j = 0; j < len; j++) {
                    value = (value << 8) | nvramData[scoreStart->numValue + j];
                }
                score = std::to_string(value);
            } else {
                score = "ERROR";
            }
        } else {
            score = "???";
        }

        // Add to JSON array
        if (!firstEntry) jsonOutput << ",";
        jsonOutput << "{\"label\":\"" << label << "\",\"initials\":\"" << initials << "\",\"score\":\"" << score << "\"}";
        firstEntry = false;

        // Add to text output for logging
        textOutput << std::left << std::setw(20) << label << " : "
                   << std::setw(5) << initials << " - "
                   << std::right << std::setw(15) << score << "\n";
    }

    jsonOutput << "]}";

    delete mapRoot;

    // Log the extracted high scores
    LOGI("Extracted high scores:\n%s", textOutput.str().c_str());

    // Broadcast via WebSocket
    broadcastWebSocket(jsonOutput.str());
}

// Check if game state has changed and broadcast if so
void checkAndBroadcastCurrentScores() {
    if (!pinmameController || !scriptApi) {
        return; // Can't get live NVRAM without Controller
    }

    if (currentMapPath.empty()) {
        return; // No map loaded
    }

    // Get current NVRAM
    std::vector<uint8_t> liveNvram;
    if (!getNVRAMFromController(liveNvram)) {
        return;
    }

    // Read the JSON map file
    std::ifstream file(currentMapPath);
    if (!file.is_open()) {
        return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string jsonContent = buffer.str();
    file.close();

    // Parse JSON
    SimpleJsonParser parser;
    JsonValue* root = parser.parse(jsonContent);
    if (!root || root->type != JsonValue::OBJECT) {
        delete root;
        return;
    }

    // Get game_state section
    const JsonValue* gameState = root->get("game_state");
    if (!gameState || gameState->type != JsonValue::OBJECT) {
        delete root;
        return;
    }

    // Get current game state
    const JsonValue* playerCountObj = gameState->get("player_count");
    int playerCount = 0;
    if (playerCountObj && playerCountObj->type == JsonValue::OBJECT) {
        const JsonValue* startVal = playerCountObj->get("start");
        if (startVal && startVal->numValue < (int64_t)liveNvram.size()) {
            playerCount = liveNvram[startVal->numValue];
        }
    }

    const JsonValue* currentPlayerObj = gameState->get("current_player");
    int currentPlayer = 0;
    if (currentPlayerObj && currentPlayerObj->type == JsonValue::OBJECT) {
        const JsonValue* startVal = currentPlayerObj->get("start");
        if (startVal && startVal->numValue < (int64_t)liveNvram.size()) {
            currentPlayer = liveNvram[startVal->numValue];
        }
    }

    const JsonValue* currentBallObj = gameState->get("current_ball");
    int currentBall = 0;
    if (currentBallObj && currentBallObj->type == JsonValue::OBJECT) {
        const JsonValue* startVal = currentBallObj->get("start");
        if (startVal && startVal->numValue < (int64_t)liveNvram.size()) {
            currentBall = liveNvram[startVal->numValue];
        }
    }

    // Get scores array
    const JsonValue* scores = gameState->get("scores");
    if (!scores || scores->type != JsonValue::ARRAY) {
        delete root;
        return;
    }

    // Extract current scores
    std::vector<std::string> currentScores;
    for (size_t i = 0; i < scores->arrayValue.size() && i < (size_t)playerCount; i++) {
        const JsonValue* scoreEntry = scores->at(i);
        if (!scoreEntry || scoreEntry->type != JsonValue::OBJECT) continue;

        const JsonValue* startVal = scoreEntry->get("start");
        const JsonValue* lengthVal = scoreEntry->get("length");
        const JsonValue* encodingVal = scoreEntry->get("encoding");

        if (!startVal || !lengthVal || !encodingVal) continue;

        std::string score;
        if (encodingVal->strValue == "bcd") {
            score = decodeBCD(liveNvram, startVal->numValue, lengthVal->numValue);
        } else if (encodingVal->strValue == "int") {
            uint64_t value = 0;
            size_t len = lengthVal->numValue;
            if (startVal->numValue + len <= liveNvram.size()) {
                for (size_t j = 0; j < len; j++) {
                    value = (value << 8) | liveNvram[startVal->numValue + j];
                }
                score = std::to_string(value);
            }
        }
        currentScores.push_back(score);
    }

    // Check if anything changed
    bool changed = (playerCount != previousPlayerCount ||
                    currentPlayer != previousCurrentPlayer ||
                    currentBall != previousCurrentBall ||
                    currentScores != previousScores);

    if (changed) {
        // Update previous state
        previousPlayerCount = playerCount;
        previousCurrentPlayer = currentPlayer;
        previousCurrentBall = currentBall;
        previousScores = currentScores;

        // Log and broadcast the change
        extractAndLogCurrentScores();
    }

    delete root;
}

void onGameStart(const unsigned int eventId, void* userData, void* eventData) {
    // Game starting - get the ROM name
    CtlOnGameStartMsg* msg = static_cast<CtlOnGameStartMsg*>(eventData);
    if (msg && msg->gameId) {
        currentRomName = msg->gameId;
        LOGI("Game started: %s", currentRomName.c_str());

        // Clear previous NVRAM data
        nvramData.clear();

        // Get the Controller pointer from PinMAME plugin
        pinmameController = nullptr;
        msgApi->BroadcastMsg(endpointId, getControllerId, &pinmameController);
        if (pinmameController) {
            LOGI("Got Controller pointer from PinMAME plugin");
        } else {
            LOGW("Controller pointer not available from PinMAME plugin");
        }

        // Clear previous state for change detection
        previousScores.clear();
        previousPlayerCount = 0;
        previousCurrentPlayer = 0;
        previousCurrentBall = 0;

        // TEMPORARY: Also dump high scores on game start
        extractAndSaveHighScores("Game start");
    }
}

void onGameEnd(const unsigned int eventId, void* userData, void* eventData) {
    extractAndSaveHighScores("Game end");

    // Clear map path when game ends
    currentMapPath.clear();
}

void onPrepareFrame(const unsigned int eventId, void* userData, void* eventData) {
    // Check if game state changed and broadcast if so
    checkAndBroadcastCurrentScores();
}

} // namespace ScoreServer

using namespace ScoreServer;

MSGPI_EXPORT void MSGPIAPI ScoreServerPluginLoad(const uint32_t sessionId, const MsgPluginAPI* api)
{
    msgApi = api;
    endpointId = sessionId;

    // Setup logging
    LPISetup(endpointId, msgApi);

    // Get plugin directory and set NVRAM maps path to bundled files
    std::string pluginDir = GetPluginDirectory();
    if (pluginDir.empty()) {
        LOGE("Failed to determine plugin directory!");
        return;
    }

    nvramMapsPath = pluginDir + "/nvram-maps";

    // Verify the maps directory exists
    if (!std::filesystem::exists(nvramMapsPath)) {
        LOGE("NVRAM maps directory not found at: %s", nvramMapsPath.c_str());
        return;
    }

    LOGI("Score Server Plugin loaded");
    LOGI("NVRAM Maps Path: %s", nvramMapsPath.c_str());

    // Get VPX API
    msgApi->BroadcastMsg(endpointId, getVpxApiId = msgApi->GetMsgID(VPXPI_NAMESPACE, VPXPI_MSG_GET_API), &vpxApi);

    // Get Scriptable API
    msgApi->BroadcastMsg(endpointId, getScriptApiId = msgApi->GetMsgID(SCRIPTPI_NAMESPACE, SCRIPTPI_MSG_GET_API), &scriptApi);
    if (scriptApi) {
        LOGI("ScriptablePlugin API obtained successfully");
    } else {
        LOGW("ScriptablePlugin API not available - will fall back to disk-based NVRAM reading");
    }

    // Register message ID for getting Controller from PinMAME
    getControllerId = msgApi->GetMsgID("PinMAME", "GetController");

    // Subscribe to controller events
    msgApi->SubscribeMsg(endpointId, onGameStartId = msgApi->GetMsgID(CTLPI_NAMESPACE, CTLPI_EVT_ON_GAME_START), onGameStart, nullptr);
    msgApi->SubscribeMsg(endpointId, onGameEndId = msgApi->GetMsgID(CTLPI_NAMESPACE, CTLPI_EVT_ON_GAME_END), onGameEnd, nullptr);

    // Subscribe to frame prepare event for periodic current score logging
    msgApi->SubscribeMsg(endpointId, onPrepareFrameId = msgApi->GetMsgID(VPXPI_NAMESPACE, VPXPI_EVT_ON_PREPARE_FRAME), onPrepareFrame, nullptr);

#ifdef _WIN32
    // Initialize Winsock on Windows
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOGE("WSAStartup failed");
        return;
    }
#endif

    // Start WebSocket server
    wsServerRunning = true;
    wsServerThread = std::thread(webSocketServerThread);
    LOGI("WebSocket server thread started on port 3131");
}

MSGPI_EXPORT void MSGPIAPI ScoreServerPluginUnload()
{
    LOGI("Score Server Plugin unloading");

    // Stop WebSocket server
    wsServerRunning = false;

    // Close all client connections
    {
        std::lock_guard<std::mutex> lock(wsClientsMutex);
        for (SOCKET client : wsClients) {
            closesocket(client);
        }
        wsClients.clear();
    }

    // Close server socket to wake up accept()
    if (wsServerSocket != INVALID_SOCKET) {
        closesocket(wsServerSocket);
        wsServerSocket = INVALID_SOCKET;
    }

    // Wait for server thread to finish
    if (wsServerThread.joinable()) {
        wsServerThread.join();
    }
    LOGI("WebSocket server thread stopped");

#ifdef _WIN32
    WSACleanup();
#endif

    // Cleanup
    msgApi->UnsubscribeMsg(onGameStartId, onGameStart);
    msgApi->UnsubscribeMsg(onGameEndId, onGameEnd);
    msgApi->UnsubscribeMsg(onPrepareFrameId, onPrepareFrame);
    msgApi->ReleaseMsgID(getVpxApiId);
    msgApi->ReleaseMsgID(getScriptApiId);
    msgApi->ReleaseMsgID(getControllerId);
    msgApi->ReleaseMsgID(onGameStartId);
    msgApi->ReleaseMsgID(onGameEndId);
    msgApi->ReleaseMsgID(onPrepareFrameId);

    vpxApi = nullptr;
    scriptApi = nullptr;
    pinmameController = nullptr;
    msgApi = nullptr;
}
