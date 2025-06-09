#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <stdexcept>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

std::mutex clientsMutex;
std::vector<SOCKET> clients;

// == Crypto context
class CryptContext {
    HCRYPTPROV hProv{ 0 };
public:
    CryptContext() {
        if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            throw std::runtime_error("CryptAcquireContext failed");
        }
    }
    ~CryptContext() {
        if (hProv) CryptReleaseContext(hProv, 0);
    }
    HCRYPTPROV get() const { return hProv; }
};

class CryptHash {
    HCRYPTHASH hHash{ 0 };
public:
    CryptHash(HCRYPTPROV hProv, ALG_ID algId) {
        if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
            throw std::runtime_error("CryptCreateHash failed");
        }
    }
    ~CryptHash() {
        if (hHash) CryptDestroyHash(hHash);
    }
    HCRYPTHASH get() const { return hHash; }
};

std::string base64_encode(const BYTE* buffer, DWORD length) {
    DWORD base64Len = 0;
    CryptBinaryToStringA(buffer, length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &base64Len);
    std::string base64(base64Len, '\0');
    CryptBinaryToStringA(buffer, length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &base64[0], &base64Len);
    if (!base64.empty() && base64.back() == '\0') base64.pop_back();
    return base64;
}

std::string sha1_hash_base64(const std::string& input) {
    CryptContext context;
    CryptHash hash(context.get(), CALG_SHA1);
    CryptHashData(hash.get(), reinterpret_cast<const BYTE*>(input.data()), static_cast<DWORD>(input.size()), 0);
    BYTE hashValue[20];
    DWORD hashLen = sizeof(hashValue);
    CryptGetHashParam(hash.get(), HP_HASHVAL, hashValue, &hashLen, 0);
    return base64_encode(hashValue, hashLen);
}

std::string extract_sec_websocket_key(const std::string& request) {
    std::istringstream stream(request);
    std::string line;
    while (std::getline(stream, line)) {
        auto pos = line.find("Sec-WebSocket-Key:");
        if (pos != std::string::npos) {
            std::string key = line.substr(pos + 18);
            size_t start = key.find_first_not_of(" \t\r\n");
            size_t end = key.find_last_not_of(" \t\r\n");
            return key.substr(start, end - start + 1);
        }
    }
    return {};
}

std::string generate_handshake_response(const std::string& key) {
    constexpr char GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string acceptKey = sha1_hash_base64(key + GUID);
    std::ostringstream response;
    response << "HTTP/1.1 101 Switching Protocols\r\n"
        << "Upgrade: websocket\r\n"
        << "Connection: Upgrade\r\n"
        << "Sec-WebSocket-Accept: " << acceptKey << "\r\n\r\n";
    return response.str();
}

std::string create_websocket_frame(const std::string& message) {
    std::string frame;
    frame.push_back(0x81);
    size_t len = message.size();
    if (len <= 125) {
        frame.push_back(static_cast<char>(len));
    }
    else if (len <= 65535) {
        frame.push_back(126);
        frame.push_back((len >> 8) & 0xFF);
        frame.push_back(len & 0xFF);
    }
    else {
        frame.push_back(127);
        for (int i = 7; i >= 0; --i) {
            frame.push_back((len >> (8 * i)) & 0xFF);
        }
    }
    frame.append(message);
    return frame;
}

std::string parse_websocket_frame(const char* buffer, int length) {
    if (length < 2) return {};
    const unsigned char* ubuffer = reinterpret_cast<const unsigned char*>(buffer);
    bool masked = (ubuffer[1] & 0x80) != 0;
    size_t payloadLen = ubuffer[1] & 0x7F;
    int pos = 2;

    if (payloadLen == 126) {
        payloadLen = (ubuffer[2] << 8) | ubuffer[3];
        pos = 4;
    }
    else if (payloadLen == 127) {
        payloadLen = 0;
        for (int i = 0; i < 8; ++i) {
            payloadLen = (payloadLen << 8) | ubuffer[pos++];
        }
    }

    if (masked) {
        if (length < pos + 4) return {};
    }

    if (length < pos + (masked ? 4 : 0) + payloadLen) return {};

    std::string payload;
    if (masked) {
        const unsigned char* maskingKey = ubuffer + pos;
        pos += 4;
        for (size_t i = 0; i < payloadLen; ++i) {
            payload.push_back(ubuffer[pos + i] ^ maskingKey[i % 4]);
        }
    }
    else {
        payload.assign(buffer + pos, payloadLen);
    }
    return payload;
}

void broadcast_message(const std::string& message, SOCKET sender) {
    std::string frame = create_websocket_frame(message);
    std::lock_guard<std::mutex> lock(clientsMutex);
    for (SOCKET client : clients) {
        if (client != sender) {
            send(client, frame.c_str(), static_cast<int>(frame.size()), 0);
        }
    }
}

void handle_client(SOCKET clientSocket) {
    char buffer[4096];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived <= 0) {
        closesocket(clientSocket);
        return;
    }

    std::string request(buffer, bytesReceived);
    std::string key = extract_sec_websocket_key(request);
    if (key.empty()) {
        closesocket(clientSocket);
        return;
    }

    std::string handshake = generate_handshake_response(key);
    send(clientSocket, handshake.c_str(), static_cast<int>(handshake.size()), 0);

    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients.push_back(clientSocket);
    }

    std::cout << "[INFO] Client connected.\n";

    while (true) {
        bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) break;

        std::string msg = parse_websocket_frame(buffer, bytesReceived);
        std::cout << "[CHAT] " << msg << '\n';

        broadcast_message(msg, clientSocket);
    }

    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients.erase(std::remove(clients.begin(), clients.end(), clientSocket), clients.end());
    }

    std::cout << "[INFO] Client disconnected.\n";
    closesocket(clientSocket);
}

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    addrinfo hints{}, * result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    getaddrinfo(nullptr, "9002", &hints, &result);
    SOCKET server = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    bind(server, result->ai_addr, static_cast<int>(result->ai_addrlen));
    freeaddrinfo(result);
    listen(server, SOMAXCONN);

    std::cout << "[INFO] WebSocket Chat Server running on port 9002...\n";

    while (true) {
        SOCKET client = accept(server, nullptr, nullptr);
        std::thread(handle_client, client).detach();
    }

    closesocket(server);
    WSACleanup();
    return 0;
}
