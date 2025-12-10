#pragma once
// =============================================================================
// connection_manager.h - Manages listen/connect threads and NAT traversal
// =============================================================================

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <wininet.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <memory>
#include <functional>

#include "../core/types.h"
#include "../core/result.h"
#include "../core/logger.h"
#include "../network/socket_wrapper.h"
#include "session.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")

namespace p2p {

// -----------------------------------------------------------------------------
// NAT Traversal Helpers
// -----------------------------------------------------------------------------
namespace nat {

inline Result<std::string, std::string> discoverGateway() {
    ULONG size = 0;
    GetAdaptersInfo(nullptr, &size);
    if (size == 0) {
        return Result<std::string, std::string>::Err("No adapters found");
    }
    
    std::vector<char> buffer(size);
    IP_ADAPTER_INFO* info = reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data());
    
    if (GetAdaptersInfo(info, &size) != NO_ERROR) {
        return Result<std::string, std::string>::Err("GetAdaptersInfo failed");
    }
    
    for (auto p = info; p; p = p->Next) {
        if (strlen(p->GatewayList.IpAddress.String) > 0) {
            return Result<std::string, std::string>::Ok(p->GatewayList.IpAddress.String);
        }
    }
    
    return Result<std::string, std::string>::Err("No gateway found");
}

inline std::string getLocalIPv4() {
    ULONG bufLen = 15 * 1024;
    std::vector<char> buf(bufLen);
    IP_ADAPTER_ADDRESSES* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    
    if (GetAdaptersAddresses(AF_INET, 
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr, addrs, &bufLen) != NO_ERROR) {
        return "";
    }
    
    std::string fallback;
    
    for (auto p = addrs; p; p = p->Next) {
        if (p->OperStatus != IfOperStatusUp) continue;
        
        for (auto u = p->FirstUnicastAddress; u; u = u->Next) {
            sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(u->Address.lpSockaddr);
            if (!sin) continue;
            
            char ip[64];
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            std::string ipStr = ip;
            
            if (ipStr == "127.0.0.1") continue;
            
            // Prefer private addresses
            if (ipStr.rfind("10.", 0) == 0 ||
                ipStr.rfind("192.168.", 0) == 0 ||
                ipStr.rfind("172.", 0) == 0) {
                return ipStr;
            }
            
            if (fallback.empty()) {
                fallback = ipStr;
            }
        }
    }
    
    return fallback;
}

struct NatMapping {
    bool     active       = false;
    bool     isUpnp       = false;
    uint16_t internalPort = 0;
    uint16_t externalPort = 0;
    std::string controlUrl;
};

inline Result<NatMapping, std::string> addNatPmpMapping(uint16_t internalPort) {
    auto gwResult = discoverGateway();
    if (!gwResult) {
        return Result<NatMapping, std::string>::Err(gwResult.error());
    }
    
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) {
        return Result<NatMapping, std::string>::Err("Socket creation failed");
    }
    
    sockaddr_in gw{};
    gw.sin_family = AF_INET;
    gw.sin_port = htons(5351);
    
    if (InetPtonA(AF_INET, gwResult.value().c_str(), &gw.sin_addr) != 1) {
        closesocket(s);
        return Result<NatMapping, std::string>::Err("Invalid gateway address");
    }
    
    // NAT-PMP request
    uint8_t req[12] = {0};
    req[0] = 0;  // Version
    req[1] = 2;  // TCP
    req[4] = static_cast<uint8_t>((internalPort >> 8) & 0xFF);
    req[5] = static_cast<uint8_t>(internalPort & 0xFF);
    req[6] = static_cast<uint8_t>((internalPort >> 8) & 0xFF);
    req[7] = static_cast<uint8_t>(internalPort & 0xFF);
    
    uint32_t lifetime = 3600;
    req[8]  = static_cast<uint8_t>((lifetime >> 24) & 0xFF);
    req[9]  = static_cast<uint8_t>((lifetime >> 16) & 0xFF);
    req[10] = static_cast<uint8_t>((lifetime >> 8) & 0xFF);
    req[11] = static_cast<uint8_t>(lifetime & 0xFF);
    
    if (sendto(s, reinterpret_cast<char*>(req), 12, 0, 
               reinterpret_cast<sockaddr*>(&gw), sizeof(gw)) != 12) {
        closesocket(s);
        return Result<NatMapping, std::string>::Err("Send failed");
    }
    
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    timeval tv{2, 0};
    
    if (select(0, &fds, nullptr, nullptr, &tv) <= 0) {
        closesocket(s);
        return Result<NatMapping, std::string>::Err("NAT-PMP timeout");
    }
    
    uint8_t resp[32];
    int r = recv(s, reinterpret_cast<char*>(resp), sizeof(resp), 0);
    closesocket(s);
    
    if (r < 16) {
        return Result<NatMapping, std::string>::Err("Short response");
    }
    
    if (resp[0] != 0 || resp[1] != (2 | 0x80)) {
        return Result<NatMapping, std::string>::Err("Bad response opcode");
    }
    
    uint16_t resultCode = (resp[2] << 8) | resp[3];
    if (resultCode != 0) {
        return Result<NatMapping, std::string>::Err(
            "NAT-PMP error: " + std::to_string(resultCode));
    }
    
    NatMapping mapping;
    mapping.active = true;
    mapping.isUpnp = false;
    mapping.internalPort = internalPort;
    mapping.externalPort = static_cast<uint16_t>((resp[10] << 8) | resp[11]);
    
    return Result<NatMapping, std::string>::Ok(std::move(mapping));
}

inline void removeNatPmpMapping(uint16_t internalPort) {
    auto gwResult = discoverGateway();
    if (!gwResult) return;
    
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) return;
    
    sockaddr_in gw{};
    gw.sin_family = AF_INET;
    gw.sin_port = htons(5351);
    
    if (InetPtonA(AF_INET, gwResult.value().c_str(), &gw.sin_addr) != 1) {
        closesocket(s);
        return;
    }
    
    uint8_t req[12] = {0};
    req[0] = 0;
    req[1] = 2;
    req[4] = static_cast<uint8_t>((internalPort >> 8) & 0xFF);
    req[5] = static_cast<uint8_t>(internalPort & 0xFF);
    req[6] = static_cast<uint8_t>((internalPort >> 8) & 0xFF);
    req[7] = static_cast<uint8_t>(internalPort & 0xFF);
    // Lifetime 0 = delete
    
    sendto(s, reinterpret_cast<char*>(req), 12, 0, 
           reinterpret_cast<sockaddr*>(&gw), sizeof(gw));
    closesocket(s);
}

} // namespace nat

// -----------------------------------------------------------------------------
// STUN Client
// -----------------------------------------------------------------------------
namespace stun {

struct MappedAddress {
    std::string ip;
    uint16_t    port = 0;
};

inline Result<MappedAddress, std::string> getMappedAddress(
    const char* server, uint16_t port, int timeoutMs) {
    
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    addrinfo* res = nullptr;
    if (getaddrinfo(server, nullptr, &hints, &res) != 0 || !res) {
        return Result<MappedAddress, std::string>::Err("DNS resolution failed");
    }
    
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        return Result<MappedAddress, std::string>::Err("Socket creation failed");
    }
    
    // STUN Binding Request
    struct {
        uint16_t type;
        uint16_t length;
        uint32_t cookie;
        uint32_t transactionId[3];
    } request{};
    
    request.type = htons(0x0001);  // Binding Request
    request.length = htons(0);
    request.cookie = htonl(0x2112A442);
    
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(reinterpret_cast<uint8_t*>(request.transactionId), 
                      sizeof(request.transactionId));
    
    if (sendto(s, reinterpret_cast<char*>(&request), sizeof(request), 0,
               reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(s);
        return Result<MappedAddress, std::string>::Err("Send failed");
    }
    
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
    
    if (select(0, &fds, nullptr, nullptr, &tv) <= 0) {
        closesocket(s);
        return Result<MappedAddress, std::string>::Err("STUN timeout");
    }
    
    uint8_t buffer[512];
    sockaddr_in from{};
    int fromLen = sizeof(from);
    
    int received = recvfrom(s, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
                           reinterpret_cast<sockaddr*>(&from), &fromLen);
    closesocket(s);
    
    if (received < 20) {
        return Result<MappedAddress, std::string>::Err("Response too short");
    }
    
    // Parse attributes
    size_t idx = 20;  // Skip header
    
    while (idx + 4 <= static_cast<size_t>(received)) {
        uint16_t attrType = (buffer[idx] << 8) | buffer[idx + 1];
        uint16_t attrLen  = (buffer[idx + 2] << 8) | buffer[idx + 3];
        idx += 4;
        
        if (idx + attrLen > static_cast<size_t>(received)) break;
        
        // XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
        if ((attrType == 0x0020 || attrType == 0x0001) && attrLen >= 8) {
            uint8_t family = buffer[idx + 1];
            uint16_t mappedPort = (buffer[idx + 2] << 8) | buffer[idx + 3];
            uint32_t mappedIp = (buffer[idx + 4] << 24) | (buffer[idx + 5] << 16) |
                               (buffer[idx + 6] << 8) | buffer[idx + 7];
            
            if (attrType == 0x0020) {
                mappedPort ^= 0x2112;
                mappedIp ^= 0x2112A442;
            }
            
            if (family == 0x01) {  // IPv4
                in_addr addr;
                addr.S_un.S_addr = htonl(mappedIp);
                
                char ipStr[64];
                inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
                
                MappedAddress result;
                result.ip = ipStr;
                result.port = mappedPort;
                
                return Result<MappedAddress, std::string>::Ok(std::move(result));
            }
        }
        
        idx += attrLen;
        if (attrLen % 4) idx += (4 - (attrLen % 4));  // Padding
    }
    
    return Result<MappedAddress, std::string>::Err("No mapped address in response");
}

} // namespace stun

// -----------------------------------------------------------------------------
// Connection Manager
// -----------------------------------------------------------------------------
class ConnectionManager {
public:
    using SessionReadyCallback = std::function<void(std::shared_ptr<Session>)>;
    using ErrorCallback = std::function<void(const std::string&)>;
    
    ConnectionManager() = default;
    ~ConnectionManager() { stop(); }
    
    // No copy
    ConnectionManager(const ConnectionManager&) = delete;
    ConnectionManager& operator=(const ConnectionManager&) = delete;
    
    // -------------------------------------------------------------------------
    // Callbacks
    // -------------------------------------------------------------------------
    void onSessionReady(SessionReadyCallback cb) { m_onSessionReady = std::move(cb); }
    void onError(ErrorCallback cb) { m_onError = std::move(cb); }
    
    // -------------------------------------------------------------------------
    // Start Connection
    // -------------------------------------------------------------------------
    VoidResult start(const ConnectionConfig& config) {
        if (m_running.load()) {
            return VoidResult::Err("Already running");
        }
        
        if (!config.isValid()) {
            return VoidResult::Err("Invalid configuration");
        }
        
        m_config = config;
        m_running.store(true);
        m_sessionChosen.store(false);
        
        LOG_INFO("Starting connection manager: " +
                 std::string(config.listenOnly ? "listen-only" : 
                            (config.connectOnly ? "connect-only" : "simultaneous")));
        
        // Start NAT mapping if enabled
        if (m_config.autoMap && !m_config.connectOnly) {
            m_natThread = std::thread([this] { natMappingThread(); });
        }
        
        // Start listener
        if (!m_config.connectOnly) {
            m_listenThread = std::thread([this] { listenThread(); });
        }
        
        // Start connector
        if (!m_config.listenOnly) {
            m_connectThread = std::thread([this] { connectThread(); });
        }
        
        return VoidResult::Ok();
    }
    
    // -------------------------------------------------------------------------
    // Stop
    // -------------------------------------------------------------------------
    void stop() {
        if (!m_running.exchange(false)) return;
        
        m_sessionChosen.store(true);  // Stop threads from accepting new connections
        
        // Clean up NAT mapping
        if (m_natMapping.active) {
            if (m_natMapping.isUpnp) {
                // UPnP cleanup would go here
            } else {
                nat::removeNatPmpMapping(m_natMapping.internalPort);
            }
            m_natMapping.active = false;
            LOG_INFO("NAT mapping removed");
        }
        
        // Join threads
        if (m_natThread.joinable()) m_natThread.join();
        if (m_listenThread.joinable()) m_listenThread.join();
        if (m_connectThread.joinable()) m_connectThread.join();
        
        LOG_INFO("Connection manager stopped");
    }
    
    // -------------------------------------------------------------------------
    // STUN Query (synchronous)
    // -------------------------------------------------------------------------
    Result<stun::MappedAddress, std::string> queryStun(
        const char* server = "stun.l.google.com", uint16_t port = 19302) {
        return stun::getMappedAddress(server, port, 3000);
    }

private:
    // -------------------------------------------------------------------------
    // NAT Mapping Thread
    // -------------------------------------------------------------------------
    void natMappingThread() {
        LOG_INFO("Starting NAT mapping...");
        
        auto result = nat::addNatPmpMapping(m_config.listenPort);
        
        if (result) {
            m_natMapping = result.value();
            LOG_INFO("NAT-PMP mapped port " + std::to_string(m_natMapping.internalPort) +
                     " -> " + std::to_string(m_natMapping.externalPort));
        } else {
            LOG_WARNING("NAT-PMP failed: " + result.error() + " (UPnP fallback not implemented)");
        }
    }
    
    // -------------------------------------------------------------------------
    // Listen Thread
    // -------------------------------------------------------------------------
    void listenThread() {
        auto socketResult = Socket::createTcp();
        if (!socketResult) {
            notifyError("Listen socket: " + socketResult.error());
            return;
        }
        
        Socket listenSocket = std::move(socketResult.value());
        listenSocket.setReuseAddr();
        
        auto bindResult = listenSocket.bind(m_config.listenPort);
        if (!bindResult) {
            notifyError("Bind: " + bindResult.error());
            return;
        }
        
        auto listenResult = listenSocket.listen(1);
        if (!listenResult) {
            notifyError("Listen: " + listenResult.error());
            return;
        }
        
        LOG_INFO("Listening on port " + std::to_string(m_config.listenPort));
        
        while (m_running.load() && !m_sessionChosen.load()) {
            // Select with timeout for cancellation
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(listenSocket.handle(), &fds);
            timeval tv{1, 0};
            
            int sel = select(0, &fds, nullptr, nullptr, &tv);
            if (sel <= 0) continue;
            
            auto acceptResult = listenSocket.accept();
            if (!acceptResult) {
                LOG_WARNING("Accept failed: " + acceptResult.error());
                continue;
            }
            
            if (m_sessionChosen.exchange(true)) {
                // Another connection won
                LOG_DEBUG("Listen: session already chosen, rejecting");
                continue;
            }
            
            Socket clientSocket = std::move(acceptResult.value());
            LOG_INFO("Accepted connection: " + clientSocket.connectionTuple());
            
            createSession(std::move(clientSocket), HandshakeRole::Responder);
            break;
        }
        
        LOG_DEBUG("Listen thread exiting");
    }
    
    // -------------------------------------------------------------------------
    // Connect Thread
    // -------------------------------------------------------------------------
    void connectThread() {
        // Resolve host
        in_addr resolved{};
        
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        addrinfo* res = nullptr;
        if (getaddrinfo(m_config.remoteHost.c_str(), nullptr, &hints, &res) != 0 || !res) {
            notifyError("Cannot resolve host: " + m_config.remoteHost);
            return;
        }
        
        resolved = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
        freeaddrinfo(res);
        
        char ipStr[64];
        inet_ntop(AF_INET, &resolved, ipStr, sizeof(ipStr));
        LOG_INFO("Connecting to " + std::string(ipStr) + ":" + std::to_string(m_config.remotePort));
        
        // Create socket
        auto socketResult = Socket::createTcp();
        if (!socketResult) {
            notifyError("Connect socket: " + socketResult.error());
            return;
        }
        
        Socket connectSocket = std::move(socketResult.value());
        connectSocket.setReuseAddr();
        
        // Bind for simultaneous open
        if (!m_config.connectOnly) {
            auto bindResult = connectSocket.bind(m_config.listenPort);
            if (!bindResult) {
                LOG_WARNING("Connect bind failed (may be expected): " + bindResult.error());
            }
        }
        
        // Non-blocking connect with event
        WSAEVENT hEvent = WSACreateEvent();
        if (hEvent == WSA_INVALID_EVENT) {
            notifyError("WSACreateEvent failed");
            return;
        }
        
        WSAEventSelect(connectSocket.handle(), hEvent, FD_CONNECT);
        
        sockaddr_in remoteAddr{};
        remoteAddr.sin_family = AF_INET;
        remoteAddr.sin_addr = resolved;
        remoteAddr.sin_port = htons(m_config.remotePort);
        
        int cr = ::connect(connectSocket.handle(), 
                          reinterpret_cast<sockaddr*>(&remoteAddr), sizeof(remoteAddr));
        
        if (cr == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
            WSACloseEvent(hEvent);
            notifyError("Connect failed: " + std::to_string(WSAGetLastError()));
            return;
        }
        
        // Wait for connection
        auto startTime = std::chrono::steady_clock::now();
        
        while (m_running.load() && !m_sessionChosen.load()) {
            auto elapsed = std::chrono::steady_clock::now() - startTime;
            if (elapsed > std::chrono::seconds(CONNECT_TIMEOUT_SEC)) {
                LOG_WARNING("Connect timeout");
                break;
            }
            
            DWORD waitResult = WSAWaitForMultipleEvents(1, &hEvent, FALSE, 200, FALSE);
            
            if (waitResult == WSA_WAIT_EVENT_0) {
                WSANETWORKEVENTS netEvents{};
                WSAEnumNetworkEvents(connectSocket.handle(), hEvent, &netEvents);
                
                if (netEvents.lNetworkEvents & FD_CONNECT) {
                    int connectError = netEvents.iErrorCode[FD_CONNECT_BIT];
                    
                    if (connectError == 0) {
                        // Success - restore blocking mode
                        WSAEventSelect(connectSocket.handle(), hEvent, 0);
                        u_long blocking = 0;
                        ioctlsocket(connectSocket.handle(), FIONBIO, &blocking);
                        
                        WSACloseEvent(hEvent);
                        
                        if (m_sessionChosen.exchange(true)) {
                            LOG_DEBUG("Connect: session already chosen");
                            return;
                        }
                        
                        LOG_INFO("Connected: " + connectSocket.connectionTuple());
                        createSession(std::move(connectSocket), HandshakeRole::Initiator);
                        return;
                    } else {
                        LOG_WARNING("Connect error: " + std::to_string(connectError));
                        break;
                    }
                }
            }
        }
        
        WSACloseEvent(hEvent);
        LOG_DEBUG("Connect thread exiting");
    }
    
    // -------------------------------------------------------------------------
    // Create Session
    // -------------------------------------------------------------------------
    void createSession(Socket socket, HandshakeRole role) {
        auto session = std::make_shared<Session>();
        
        auto initResult = session->initialize(m_config.useHmac);
        if (!initResult) {
            notifyError("Session init: " + initResult.error());
            m_sessionChosen.store(false);
            return;
        }
        
        auto startResult = session->start(std::move(socket), role);
        if (!startResult) {
            notifyError("Session start: " + startResult.error());
            m_sessionChosen.store(false);
            return;
        }
        
        if (m_onSessionReady) {
            m_onSessionReady(session);
        }
    }
    
    void notifyError(const std::string& error) {
        LOG_ERROR(error);
        if (m_onError) {
            m_onError(error);
        }
    }
    
    // -------------------------------------------------------------------------
    // Members
    // -------------------------------------------------------------------------
    std::atomic<bool>        m_running{false};
    std::atomic<bool>        m_sessionChosen{false};
    ConnectionConfig         m_config;
    
    std::thread              m_natThread;
    std::thread              m_listenThread;
    std::thread              m_connectThread;
    
    nat::NatMapping          m_natMapping;
    
    SessionReadyCallback     m_onSessionReady;
    ErrorCallback            m_onError;
};

} // namespace p2p
