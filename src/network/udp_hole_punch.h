#pragma once
// =============================================================================
// udp_hole_punch.h - UDP NAT hole punching implementation
// =============================================================================
//
// Implements simultaneous UDP hole punching:
// 1. Both peers discover their public endpoint via STUN
// 2. Both peers start sending probes to each other's public endpoint
// 3. When NAT sees outbound packet, it creates mapping
// 4. Inbound packet from peer matches the mapping and gets through
// 5. Once both sides receive packets, the "hole" is established
//
// After hole is established, we switch to TCP over the punched UDP "hole"
// using a simple reliable layer, or keep UDP with our own reliability.
//
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <random>
#include <functional>
#include <string>
#include <vector>
#include <mutex>

#include "../core/types.h"
#include "../core/result.h"
#include "../core/logger.h"
#include "socket_wrapper.h"

#pragma comment(lib, "ws2_32.lib")

namespace p2p {

// -----------------------------------------------------------------------------
// STUN Client (simplified for hole punching)
// -----------------------------------------------------------------------------
namespace stun {

struct Endpoint {
    std::string ip;
    uint16_t    port = 0;
    
    bool isValid() const { return !ip.empty() && port > 0; }
    std::string toString() const { return ip + ":" + std::to_string(port); }
};

// Minimal STUN binding request/response for discovering mapped address
inline Result<Endpoint, std::string> discoverPublicEndpoint(
    SOCKET udpSocket, 
    const char* stunServer = "stun.l.google.com",
    uint16_t stunPort = 19302,
    int timeoutMs = 3000
) {
    // Resolve STUN server
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    addrinfo* result = nullptr;
    if (getaddrinfo(stunServer, nullptr, &hints, &result) != 0 || !result) {
        return Result<Endpoint, std::string>::Err("Failed to resolve STUN server");
    }
    
    sockaddr_in stunAddr{};
    stunAddr.sin_family = AF_INET;
    stunAddr.sin_port = htons(stunPort);
    stunAddr.sin_addr = reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr;
    freeaddrinfo(result);
    
    // Build STUN binding request (RFC 5389)
    uint8_t request[20] = {};
    request[0] = 0x00;  // Message type: Binding Request (0x0001)
    request[1] = 0x01;
    request[2] = 0x00;  // Message length: 0 (no attributes)
    request[3] = 0x00;
    
    // Magic cookie
    request[4] = 0x21;
    request[5] = 0x12;
    request[6] = 0xA4;
    request[7] = 0x42;
    
    // Transaction ID (random 96 bits)
    std::random_device rd;
    std::mt19937 gen(rd());
    for (int i = 8; i < 20; ++i) {
        request[i] = static_cast<uint8_t>(gen() & 0xFF);
    }
    
    // Send request
    if (sendto(udpSocket, reinterpret_cast<char*>(request), 20, 0,
               reinterpret_cast<sockaddr*>(&stunAddr), sizeof(stunAddr)) != 20) {
        return Result<Endpoint, std::string>::Err("Failed to send STUN request");
    }
    
    // Wait for response
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(udpSocket, &fds);
    timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
    
    if (select(0, &fds, nullptr, nullptr, &tv) <= 0) {
        return Result<Endpoint, std::string>::Err("STUN request timed out");
    }
    
    // Receive response
    uint8_t response[256];
    sockaddr_in from{};
    int fromLen = sizeof(from);
    
    int recvLen = recvfrom(udpSocket, reinterpret_cast<char*>(response), sizeof(response), 0,
                           reinterpret_cast<sockaddr*>(&from), &fromLen);
    
    if (recvLen < 20) {
        return Result<Endpoint, std::string>::Err("Invalid STUN response");
    }
    
    // Verify it's a binding response
    if (response[0] != 0x01 || response[1] != 0x01) {
        return Result<Endpoint, std::string>::Err("Not a STUN binding response");
    }
    
    // Parse attributes looking for XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
    uint16_t msgLen = (static_cast<uint16_t>(response[2]) << 8) | response[3];
    size_t offset = 20;
    
    while (offset + 4 <= static_cast<size_t>(recvLen) && offset < 20 + msgLen) {
        uint16_t attrType = (static_cast<uint16_t>(response[offset]) << 8) | response[offset + 1];
        uint16_t attrLen = (static_cast<uint16_t>(response[offset + 2]) << 8) | response[offset + 3];
        offset += 4;
        
        if (offset + attrLen > static_cast<size_t>(recvLen)) break;
        
        if (attrType == 0x0020 && attrLen >= 8) {  // XOR-MAPPED-ADDRESS
            // Skip family byte
            uint16_t xorPort = (static_cast<uint16_t>(response[offset + 2]) << 8) | response[offset + 3];
            uint32_t xorIp = (static_cast<uint32_t>(response[offset + 4]) << 24) |
                             (static_cast<uint32_t>(response[offset + 5]) << 16) |
                             (static_cast<uint32_t>(response[offset + 6]) << 8) |
                             response[offset + 7];
            
            // XOR with magic cookie
            uint16_t port = xorPort ^ 0x2112;
            uint32_t ip = xorIp ^ 0x2112A442;
            
            Endpoint ep;
            ep.port = port;
            
            in_addr addr;
            addr.s_addr = htonl(ip);
            char ipStr[64];
            inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
            ep.ip = ipStr;
            
            return Result<Endpoint, std::string>::Ok(std::move(ep));
        }
        else if (attrType == 0x0001 && attrLen >= 8) {  // MAPPED-ADDRESS (fallback)
            uint16_t port = (static_cast<uint16_t>(response[offset + 2]) << 8) | response[offset + 3];
            uint32_t ip = (static_cast<uint32_t>(response[offset + 4]) << 24) |
                          (static_cast<uint32_t>(response[offset + 5]) << 16) |
                          (static_cast<uint32_t>(response[offset + 6]) << 8) |
                          response[offset + 7];
            
            Endpoint ep;
            ep.port = port;
            
            in_addr addr;
            addr.s_addr = htonl(ip);
            char ipStr[64];
            inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
            ep.ip = ipStr;
            
            return Result<Endpoint, std::string>::Ok(std::move(ep));
        }
        
        // Align to 4-byte boundary
        offset += attrLen;
        if (attrLen % 4 != 0) {
            offset += 4 - (attrLen % 4);
        }
    }
    
    return Result<Endpoint, std::string>::Err("No mapped address in STUN response");
}

} // namespace stun

// -----------------------------------------------------------------------------
// UDP Hole Punch Probes
// -----------------------------------------------------------------------------
namespace holePunch {

// Probe packet format: [magic:4][seq:4][timestamp:8]
constexpr uint32_t PROBE_MAGIC = 0x50554E43;  // "PUNC"
constexpr size_t   PROBE_SIZE  = 16;

struct ProbePacket {
    uint32_t magic     = PROBE_MAGIC;
    uint32_t sequence  = 0;
    uint64_t timestamp = 0;
    
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(PROBE_SIZE);
        buf[0] = static_cast<uint8_t>((magic >> 24) & 0xFF);
        buf[1] = static_cast<uint8_t>((magic >> 16) & 0xFF);
        buf[2] = static_cast<uint8_t>((magic >> 8) & 0xFF);
        buf[3] = static_cast<uint8_t>(magic & 0xFF);
        buf[4] = static_cast<uint8_t>((sequence >> 24) & 0xFF);
        buf[5] = static_cast<uint8_t>((sequence >> 16) & 0xFF);
        buf[6] = static_cast<uint8_t>((sequence >> 8) & 0xFF);
        buf[7] = static_cast<uint8_t>(sequence & 0xFF);
        for (int i = 0; i < 8; ++i) {
            buf[8 + i] = static_cast<uint8_t>((timestamp >> (56 - i * 8)) & 0xFF);
        }
        return buf;
    }
    
    static bool deserialize(const uint8_t* data, size_t len, ProbePacket& out) {
        if (len < PROBE_SIZE) return false;
        
        out.magic = (static_cast<uint32_t>(data[0]) << 24) |
                    (static_cast<uint32_t>(data[1]) << 16) |
                    (static_cast<uint32_t>(data[2]) << 8) |
                    data[3];
        
        if (out.magic != PROBE_MAGIC) return false;
        
        out.sequence = (static_cast<uint32_t>(data[4]) << 24) |
                       (static_cast<uint32_t>(data[5]) << 16) |
                       (static_cast<uint32_t>(data[6]) << 8) |
                       data[7];
        
        out.timestamp = 0;
        for (int i = 0; i < 8; ++i) {
            out.timestamp = (out.timestamp << 8) | data[8 + i];
        }
        
        return true;
    }
};

// Acknowledgment packet: [magic:4][ack_seq:4]
constexpr uint32_t ACK_MAGIC = 0x41434B21;  // "ACK!"
constexpr size_t   ACK_SIZE  = 8;

struct AckPacket {
    uint32_t magic   = ACK_MAGIC;
    uint32_t ackSeq  = 0;
    
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(ACK_SIZE);
        buf[0] = static_cast<uint8_t>((magic >> 24) & 0xFF);
        buf[1] = static_cast<uint8_t>((magic >> 16) & 0xFF);
        buf[2] = static_cast<uint8_t>((magic >> 8) & 0xFF);
        buf[3] = static_cast<uint8_t>(magic & 0xFF);
        buf[4] = static_cast<uint8_t>((ackSeq >> 24) & 0xFF);
        buf[5] = static_cast<uint8_t>((ackSeq >> 16) & 0xFF);
        buf[6] = static_cast<uint8_t>((ackSeq >> 8) & 0xFF);
        buf[7] = static_cast<uint8_t>(ackSeq & 0xFF);
        return buf;
    }
    
    static bool deserialize(const uint8_t* data, size_t len, AckPacket& out) {
        if (len < ACK_SIZE) return false;
        
        out.magic = (static_cast<uint32_t>(data[0]) << 24) |
                    (static_cast<uint32_t>(data[1]) << 16) |
                    (static_cast<uint32_t>(data[2]) << 8) |
                    data[3];
        
        if (out.magic != ACK_MAGIC) return false;
        
        out.ackSeq = (static_cast<uint32_t>(data[4]) << 24) |
                     (static_cast<uint32_t>(data[5]) << 16) |
                     (static_cast<uint32_t>(data[6]) << 8) |
                     data[7];
        
        return true;
    }
};

} // namespace holePunch

// -----------------------------------------------------------------------------
// UDP Hole Puncher
// -----------------------------------------------------------------------------
class UdpHolePuncher {
public:
    using SuccessCallback = std::function<void(SOCKET sock, const stun::Endpoint& peerEndpoint)>;
    using FailureCallback = std::function<void(const std::string& error)>;
    
    UdpHolePuncher() = default;
    ~UdpHolePuncher() { stop(); }
    
    // No copy
    UdpHolePuncher(const UdpHolePuncher&) = delete;
    UdpHolePuncher& operator=(const UdpHolePuncher&) = delete;
    
    void onSuccess(SuccessCallback cb) { m_onSuccess = std::move(cb); }
    void onFailure(FailureCallback cb) { m_onFailure = std::move(cb); }
    
    // Get our local endpoint (for display/signaling before discovery)
    stun::Endpoint localEndpoint() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_localEndpoint;
    }
    
    // Get our public endpoint (discovered via STUN)
    stun::Endpoint publicEndpoint() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_publicEndpoint;
    }
    
    // -------------------------------------------------------------------------
    // Start hole punching process
    // -------------------------------------------------------------------------
    // Call this with the peer's public endpoint (exchanged via out-of-band signaling)
    VoidResult start(uint16_t localPort, const stun::Endpoint& peerPublicEndpoint, int timeoutMs = 10000) {
        if (m_running.load()) {
            return VoidResult::Err("Already running");
        }
        
        // Create UDP socket
        auto sockResult = Socket::createUdp();
        if (!sockResult) {
            return VoidResult::Err(sockResult.error());
        }
        
        m_socket = std::move(sockResult.value());
        m_socket.setReuseAddr();
        
        auto bindResult = m_socket.bind(localPort);
        if (!bindResult) {
            return VoidResult::Err(bindResult.error());
        }
        
        // Get local endpoint
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_localEndpoint.ip = nat::getLocalIPv4();
            m_localEndpoint.port = localPort;
        }
        
        // Discover public endpoint via STUN
        LOG_INFO("Discovering public endpoint via STUN...");
        auto stunResult = stun::discoverPublicEndpoint(m_socket.handle());
        if (!stunResult) {
            return VoidResult::Err("STUN failed: " + stunResult.error());
        }
        
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_publicEndpoint = stunResult.value();
        }
        
        LOG_INFO("Public endpoint: " + m_publicEndpoint.toString());
        
        // Set peer endpoint
        m_peerEndpoint = peerPublicEndpoint;
        m_timeoutMs = timeoutMs;
        m_running.store(true);
        
        // Start hole punch thread
        m_punchThread = std::thread([this] { punchLoop(); });
        
        return VoidResult::Ok();
    }
    
    // -------------------------------------------------------------------------
    // Discover public endpoint only (for signaling exchange)
    // -------------------------------------------------------------------------
    Result<stun::Endpoint, std::string> discoverOnly(uint16_t localPort) {
        auto sockResult = Socket::createUdp();
        if (!sockResult) {
            return Result<stun::Endpoint, std::string>::Err(sockResult.error());
        }
        
        Socket tempSock = std::move(sockResult.value());
        tempSock.setReuseAddr();
        
        auto bindResult = tempSock.bind(localPort);
        if (!bindResult) {
            return Result<stun::Endpoint, std::string>::Err(bindResult.error());
        }
        
        return stun::discoverPublicEndpoint(tempSock.handle());
    }
    
    // -------------------------------------------------------------------------
    // Stop
    // -------------------------------------------------------------------------
    void stop() {
        m_running.store(false);
        m_socket.close();
        
        if (m_punchThread.joinable()) {
            m_punchThread.join();
        }
    }
    
    bool isRunning() const { return m_running.load(); }
    bool succeeded() const { return m_succeeded.load(); }
    
private:
    void punchLoop() {
        LOG_INFO("Starting UDP hole punch to " + m_peerEndpoint.toString());
        
        // Resolve peer address
        sockaddr_in peerAddr{};
        peerAddr.sin_family = AF_INET;
        peerAddr.sin_port = htons(m_peerEndpoint.port);
        
        if (InetPtonA(AF_INET, m_peerEndpoint.ip.c_str(), &peerAddr.sin_addr) != 1) {
            notifyFailure("Invalid peer IP address");
            return;
        }
        
        auto startTime = std::chrono::steady_clock::now();
        uint32_t seq = 0;
        bool receivedProbe = false;
        bool sentAck = false;
        bool receivedAck = false;
        
        // Set non-blocking for recv
        m_socket.setNonBlocking(true);
        
        while (m_running.load()) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();
            
            if (elapsed > m_timeoutMs) {
                notifyFailure("Hole punch timed out after " + std::to_string(m_timeoutMs) + "ms");
                return;
            }
            
            // Send probe every 100ms
            holePunch::ProbePacket probe;
            probe.sequence = seq++;
            probe.timestamp = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            
            auto probeData = probe.serialize();
            sendto(m_socket.handle(), reinterpret_cast<char*>(probeData.data()), 
                   static_cast<int>(probeData.size()), 0,
                   reinterpret_cast<sockaddr*>(&peerAddr), sizeof(peerAddr));
            
            // Try to receive
            uint8_t recvBuf[256];
            sockaddr_in fromAddr{};
            int fromLen = sizeof(fromAddr);
            
            int recvLen = recvfrom(m_socket.handle(), reinterpret_cast<char*>(recvBuf), 
                                   sizeof(recvBuf), 0,
                                   reinterpret_cast<sockaddr*>(&fromAddr), &fromLen);
            
            if (recvLen > 0) {
                holePunch::ProbePacket recvProbe;
                holePunch::AckPacket recvAck;
                
                if (holePunch::ProbePacket::deserialize(recvBuf, recvLen, recvProbe)) {
                    // Received a probe from peer
                    if (!receivedProbe) {
                        LOG_INFO("Received probe from peer (seq=" + std::to_string(recvProbe.sequence) + ")");
                        receivedProbe = true;
                    }
                    
                    // Send ACK
                    holePunch::AckPacket ack;
                    ack.ackSeq = recvProbe.sequence;
                    auto ackData = ack.serialize();
                    sendto(m_socket.handle(), reinterpret_cast<char*>(ackData.data()),
                           static_cast<int>(ackData.size()), 0,
                           reinterpret_cast<sockaddr*>(&peerAddr), sizeof(peerAddr));
                    sentAck = true;
                }
                else if (holePunch::AckPacket::deserialize(recvBuf, recvLen, recvAck)) {
                    // Received ACK from peer
                    if (!receivedAck) {
                        LOG_INFO("Received ACK from peer (ack_seq=" + std::to_string(recvAck.ackSeq) + ")");
                        receivedAck = true;
                    }
                }
            }
            
            // Success condition: we've both sent and received
            if (receivedProbe && receivedAck) {
                LOG_INFO("UDP hole punch successful!");
                m_succeeded.store(true);
                
                // Switch back to blocking for the handoff
                m_socket.setNonBlocking(false);
                
                if (m_onSuccess) {
                    // Release socket ownership to caller
                    m_onSuccess(m_socket.release(), m_peerEndpoint);
                }
                return;
            }
            
            // Small delay between probes
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    void notifyFailure(const std::string& error) {
        LOG_ERROR("UDP hole punch failed: " + error);
        if (m_onFailure) {
            m_onFailure(error);
        }
    }
    
    mutable std::mutex       m_mutex;
    std::atomic<bool>        m_running{false};
    std::atomic<bool>        m_succeeded{false};
    Socket                   m_socket;
    std::thread              m_punchThread;
    
    stun::Endpoint           m_localEndpoint;
    stun::Endpoint           m_publicEndpoint;
    stun::Endpoint           m_peerEndpoint;
    int                      m_timeoutMs = 10000;
    
    SuccessCallback          m_onSuccess;
    FailureCallback          m_onFailure;
};

} // namespace p2p
