#pragma once
// =============================================================================
// socket_wrapper.h - RAII socket wrapper with thread-safe operations
// =============================================================================

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <mutex>
#include <string>
#include <sstream>
#include <atomic>
#include "../core/types.h"
#include "../core/result.h"
#include "../core/logger.h"

#pragma comment(lib, "ws2_32.lib")

namespace p2p {

// -----------------------------------------------------------------------------
// RAII Socket Wrapper
// -----------------------------------------------------------------------------
class Socket {
public:
    Socket() = default;
    
    explicit Socket(SOCKET s) : m_socket(s) {}
    
    // Move only
    Socket(Socket&& other) noexcept 
        : m_socket(other.m_socket.exchange(INVALID_SOCKET)) {}
    
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            close();
            m_socket.store(other.m_socket.exchange(INVALID_SOCKET));
        }
        return *this;
    }
    
    // No copy
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    
    ~Socket() { close(); }
    
    // Factory methods
    static Result<Socket, std::string> createTcp() {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            return Result<Socket, std::string>::Err(
                "socket() failed: " + std::to_string(WSAGetLastError()));
        }
        return Result<Socket, std::string>::Ok(Socket(s));
    }
    
    static Result<Socket, std::string> createUdp() {
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) {
            return Result<Socket, std::string>::Err(
                "socket() failed: " + std::to_string(WSAGetLastError()));
        }
        return Result<Socket, std::string>::Ok(Socket(s));
    }
    
    // State
    bool isValid() const { return m_socket.load() != INVALID_SOCKET; }
    SOCKET handle() const { return m_socket.load(); }
    SOCKET release() { return m_socket.exchange(INVALID_SOCKET); }
    
    // Close
    void close() {
        SOCKET s = m_socket.exchange(INVALID_SOCKET);
        if (s != INVALID_SOCKET) {
            shutdown(s, SD_BOTH);
            closesocket(s);
        }
    }
    
    // Options
    VoidResult setReuseAddr(bool enable = true) {
        BOOL val = enable ? TRUE : FALSE;
        if (setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, 
                       (const char*)&val, sizeof(val)) == SOCKET_ERROR) {
            return VoidResult::Err("setsockopt(SO_REUSEADDR) failed: " + 
                                   std::to_string(WSAGetLastError()));
        }
        return VoidResult::Ok();
    }
    
    VoidResult setNoDelay(bool enable = true) {
        int val = enable ? 1 : 0;
        if (setsockopt(m_socket, IPPROTO_TCP, TCP_NODELAY, 
                       (const char*)&val, sizeof(val)) == SOCKET_ERROR) {
            return VoidResult::Err("setsockopt(TCP_NODELAY) failed: " + 
                                   std::to_string(WSAGetLastError()));
        }
        return VoidResult::Ok();
    }
    
    VoidResult setKeepalive(DWORD idleMs, DWORD intervalMs) {
        BOOL on = TRUE;
        setsockopt(m_socket, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on));
        
        tcp_keepalive ka{};
        ka.onoff = 1;
        ka.keepalivetime = idleMs;
        ka.keepaliveinterval = intervalMs;
        
        DWORD bytesRet = 0;
        if (WSAIoctl(m_socket, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), 
                     nullptr, 0, &bytesRet, nullptr, nullptr) == SOCKET_ERROR) {
            return VoidResult::Err("WSAIoctl(SIO_KEEPALIVE_VALS) failed: " + 
                                   std::to_string(WSAGetLastError()));
        }
        return VoidResult::Ok();
    }
    
    VoidResult setNonBlocking(bool enable = true) {
        u_long mode = enable ? 1 : 0;
        if (ioctlsocket(m_socket, FIONBIO, &mode) == SOCKET_ERROR) {
            return VoidResult::Err("ioctlsocket(FIONBIO) failed: " + 
                                   std::to_string(WSAGetLastError()));
        }
        return VoidResult::Ok();
    }
    
    // Bind
    VoidResult bind(uint16_t port, const char* ip = nullptr) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        
        if (ip && ip[0]) {
            if (InetPtonA(AF_INET, ip, &addr.sin_addr) != 1) {
                return VoidResult::Err("Invalid bind address: " + std::string(ip));
            }
        } else {
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
        }
        
        if (::bind(m_socket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            return VoidResult::Err("bind() failed: " + std::to_string(WSAGetLastError()));
        }
        return VoidResult::Ok();
    }
    
    // Listen
    VoidResult listen(int backlog = SOMAXCONN) {
        if (::listen(m_socket, backlog) == SOCKET_ERROR) {
            return VoidResult::Err("listen() failed: " + std::to_string(WSAGetLastError()));
        }
        return VoidResult::Ok();
    }
    
    // Accept
    Result<Socket, std::string> accept() {
        SOCKET client = ::accept(m_socket, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            return Result<Socket, std::string>::Err(
                "accept() failed: " + std::to_string(WSAGetLastError()));
        }
        return Result<Socket, std::string>::Ok(Socket(client));
    }
    
    // Connect
    VoidResult connect(const char* host, uint16_t port) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        
        if (InetPtonA(AF_INET, host, &addr.sin_addr) != 1) {
            // Try DNS resolution
            addrinfo hints{};
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            
            addrinfo* result = nullptr;
            if (getaddrinfo(host, nullptr, &hints, &result) != 0 || !result) {
                return VoidResult::Err("Cannot resolve host: " + std::string(host));
            }
            
            addr.sin_addr = ((sockaddr_in*)result->ai_addr)->sin_addr;
            freeaddrinfo(result);
        }
        
        if (::connect(m_socket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {  // Non-blocking connect in progress is ok
                return VoidResult::Err("connect() failed: " + std::to_string(err));
            }
        }
        return VoidResult::Ok();
    }
    
    // Get local/remote address info
    std::string localAddress() const {
        sockaddr_in addr{};
        int len = sizeof(addr);
        if (getsockname(m_socket, (sockaddr*)&addr, &len) == 0) {
            char ip[64]{};
            inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
            return std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port));
        }
        return "?:?";
    }
    
    std::string remoteAddress() const {
        sockaddr_in addr{};
        int len = sizeof(addr);
        if (getpeername(m_socket, (sockaddr*)&addr, &len) == 0) {
            char ip[64]{};
            inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
            return std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port));
        }
        return "?:?";
    }
    
    std::string connectionTuple() const {
        return localAddress() + " -> " + remoteAddress();
    }

private:
    std::atomic<SOCKET> m_socket{INVALID_SOCKET};
};

// -----------------------------------------------------------------------------
// Winsock Initializer (RAII)
// -----------------------------------------------------------------------------
class WinsockInit {
public:
    static WinsockInit& instance() {
        static WinsockInit s_instance;
        return s_instance;
    }
    
    bool isInitialized() const { return m_initialized; }
    const std::string& error() const { return m_error; }

private:
    WinsockInit() {
        WSADATA wsd;
        int result = WSAStartup(MAKEWORD(2, 2), &wsd);
        if (result != 0) {
            m_error = "WSAStartup failed: " + std::to_string(result);
            m_initialized = false;
        } else {
            m_initialized = true;
        }
    }
    
    ~WinsockInit() {
        if (m_initialized) {
            WSACleanup();
        }
    }
    
    bool        m_initialized = false;
    std::string m_error;
};

} // namespace p2p
