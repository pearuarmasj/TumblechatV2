#pragma once
// =============================================================================
// udp_transport.h - DTLS-style reliable UDP transport
// =============================================================================
//
// Implements ITransport over UDP with DTLS-inspired reliability features:
// - Sequence numbers for ordering and deduplication
// - Cumulative ACKs with selective ACK (SACK) bitmap
// - Retransmission queue with exponential backoff
// - Congestion control (simple AIMD like TCP)
// - RTT estimation using Jacobson/Karels algorithm
// - Keepalive/heartbeat for dead peer detection
// - Handshake for connection establishment
//
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdint>
#include <string>
#include <vector>
#include <queue>
#include <map>
#include <deque>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <condition_variable>
#include <functional>

#include "../core/types.h"
#include "../core/result.h"
#include "../core/logger.h"
#include "transport.h"
#include "socket_wrapper.h"

#pragma comment(lib, "ws2_32.lib")

namespace p2p {

// =============================================================================
// Constants
// =============================================================================

// Packet size limits
constexpr size_t   UDP_MAX_PACKET_SIZE      = 1400;   // MTU-safe (leaves room for IP/UDP headers)
constexpr size_t   UDP_HEADER_SIZE          = 12;     // Our protocol header size
constexpr size_t   UDP_MAX_PAYLOAD_SIZE     = UDP_MAX_PACKET_SIZE - UDP_HEADER_SIZE;

// Timing constants (milliseconds)
constexpr int      UDP_INITIAL_RTO_MS       = 1000;   // Initial retransmit timeout
constexpr int      UDP_MIN_RTO_MS           = 200;    // Minimum RTO
constexpr int      UDP_MAX_RTO_MS           = 60000;  // Maximum RTO (1 minute)
constexpr int      UDP_MAX_RETRANSMITS      = 10;     // Max retransmit attempts before failure
constexpr int      UDP_HEARTBEAT_INTERVAL_MS = 5000;  // Send heartbeat every 5 seconds
constexpr int      UDP_HEARTBEAT_TIMEOUT_MS  = 15000; // Consider peer dead after 15 seconds

// Congestion control
constexpr uint32_t UDP_INITIAL_CWND         = 4;      // Initial congestion window (packets)
constexpr uint32_t UDP_MIN_CWND             = 1;      // Minimum congestion window
constexpr uint32_t UDP_MAX_CWND             = 64;     // Maximum congestion window
constexpr uint32_t UDP_SSTHRESH_INITIAL     = 16;     // Initial slow start threshold

// SACK bitmap size (covers 32 packets beyond cumulative ACK)
constexpr size_t   UDP_SACK_BITMAP_SIZE     = 4;      // 32 bits = 32 packets

// Handshake timeout - generous to allow both peers time to click Connect
constexpr int      UDP_HANDSHAKE_TIMEOUT_MS = 60000;  // 60 second overall timeout
constexpr int      UDP_HANDSHAKE_RETRIES    = 30;     // Max handshake retries (2 sec each)

// =============================================================================
// Internal Packet Types
// =============================================================================

enum class UdpPacketType : uint8_t {
    DATA            = 0x01,   // Application data with sequence number
    ACK             = 0x02,   // Cumulative ACK + SACK bitmap
    HANDSHAKE_INIT  = 0x10,   // Connection initiation (like DTLS ClientHello)
    HANDSHAKE_RESP  = 0x11,   // Connection response (like DTLS ServerHello)
    HANDSHAKE_ACK   = 0x12,   // Handshake completion acknowledgment
    HEARTBEAT       = 0x20,   // Keepalive probe
    HEARTBEAT_ACK   = 0x21,   // Keepalive response
    CLOSE           = 0x30    // Graceful connection close
};

inline const char* UdpPacketTypeName(UdpPacketType type) {
    switch (type) {
        case UdpPacketType::DATA:           return "DATA";
        case UdpPacketType::ACK:            return "ACK";
        case UdpPacketType::HANDSHAKE_INIT: return "HANDSHAKE_INIT";
        case UdpPacketType::HANDSHAKE_RESP: return "HANDSHAKE_RESP";
        case UdpPacketType::HANDSHAKE_ACK:  return "HANDSHAKE_ACK";
        case UdpPacketType::HEARTBEAT:      return "HEARTBEAT";
        case UdpPacketType::HEARTBEAT_ACK:  return "HEARTBEAT_ACK";
        case UdpPacketType::CLOSE:          return "CLOSE";
        default:                            return "UNKNOWN";
    }
}

// =============================================================================
// Packet Header Structure
// =============================================================================
// Wire format (12 bytes):
//   [0]      - packet type (UdpPacketType)
//   [1]      - flags (reserved for future use)
//   [2..3]   - payload length (big-endian uint16)
//   [4..7]   - sequence number (big-endian uint32)
//   [8..11]  - acknowledgment number (big-endian uint32)
//
// For ACK packets, additional SACK bitmap follows the header.
// For DATA packets, the application payload follows the header.

struct UdpPacketHeader {
    UdpPacketType type       = UdpPacketType::DATA;
    uint8_t       flags      = 0;
    uint16_t      payloadLen = 0;
    uint32_t      seqNum     = 0;
    uint32_t      ackNum     = 0;

    static constexpr size_t SIZE = 12;

    void serialize(uint8_t* buf) const;
    static bool deserialize(const uint8_t* buf, size_t len, UdpPacketHeader& out);
};

// =============================================================================
// ACK Packet Structure
// =============================================================================
// Cumulative ACK: all packets up to ackNum have been received.
// SACK bitmap: additional out-of-order packets received beyond ackNum.
// Bit N in bitmap means packet (ackNum + 1 + N) has been received.

struct UdpAckPacket {
    uint32_t cumAck  = 0;                               // Cumulative acknowledgment
    uint8_t  sackMap[UDP_SACK_BITMAP_SIZE] = {0};      // Selective ACK bitmap

    static constexpr size_t SIZE = 4 + UDP_SACK_BITMAP_SIZE;

    void serialize(uint8_t* buf) const;
    static bool deserialize(const uint8_t* buf, size_t len, UdpAckPacket& out);

    // Set bit for out-of-order packet at offset from cumAck
    void setSackBit(uint32_t offset);
    bool getSackBit(uint32_t offset) const;
};

// =============================================================================
// Handshake Packet Structure
// =============================================================================
// Contains connection ID and initial sequence number for the connection.

struct UdpHandshakePacket {
    uint32_t connectionId    = 0;   // Unique connection identifier
    uint32_t initialSeq      = 0;   // Initial sequence number
    uint32_t timestamp       = 0;   // Timestamp for RTT measurement
    uint8_t  version         = 1;   // Protocol version
    uint8_t  reserved[3]     = {0}; // Padding for alignment

    static constexpr size_t SIZE = 16;

    void serialize(uint8_t* buf) const;
    static bool deserialize(const uint8_t* buf, size_t len, UdpHandshakePacket& out);
};

// =============================================================================
// Retransmission Queue Entry
// =============================================================================

struct RetransmitEntry {
    uint32_t                                seqNum;       // Sequence number
    std::vector<uint8_t>                    packet;       // Complete packet (header + payload)
    std::chrono::steady_clock::time_point   firstSent;    // Time of first transmission
    std::chrono::steady_clock::time_point   lastSent;     // Time of last transmission
    int                                     retryCount;   // Number of retransmissions
    int                                     rtoMs;        // Current RTO for this packet
};

// =============================================================================
// Received Message (for reordering buffer)
// =============================================================================

struct ReceivedMessage {
    uint32_t             seqNum;
    MsgType              msgType;
    std::vector<uint8_t> payload;
};

// =============================================================================
// Connection State
// =============================================================================

enum class UdpConnectionState {
    CLOSED,
    HANDSHAKE_SENT,
    HANDSHAKE_RECEIVED,
    ESTABLISHED,
    CLOSING
};

inline const char* UdpConnectionStateName(UdpConnectionState state) {
    switch (state) {
        case UdpConnectionState::CLOSED:             return "CLOSED";
        case UdpConnectionState::HANDSHAKE_SENT:     return "HANDSHAKE_SENT";
        case UdpConnectionState::HANDSHAKE_RECEIVED: return "HANDSHAKE_RECEIVED";
        case UdpConnectionState::ESTABLISHED:        return "ESTABLISHED";
        case UdpConnectionState::CLOSING:            return "CLOSING";
        default:                                     return "UNKNOWN";
    }
}

// =============================================================================
// RTT Estimator (Jacobson/Karels Algorithm)
// =============================================================================
// SRTT = (1 - alpha) * SRTT + alpha * RTT
// RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - RTT|
// RTO = SRTT + max(G, 4 * RTTVAR)
//
// Where: alpha = 1/8, beta = 1/4, G = clock granularity (1ms)

class RttEstimator {
public:
    RttEstimator();

    // Update with a new RTT sample (in milliseconds)
    void addSample(int rttMs);

    // Get current RTO estimate (clamped to [min, max])
    int getRto() const;

    // Get smoothed RTT
    int getSrtt() const { return m_srtt; }

    // Get RTT variance
    int getRttVar() const { return m_rttvar; }

    // Reset to initial state
    void reset();

private:
    int  m_srtt;          // Smoothed RTT (scaled by 8)
    int  m_rttvar;        // RTT variance (scaled by 4)
    bool m_hasFirstSample;
};

// =============================================================================
// Congestion Controller (AIMD - Additive Increase Multiplicative Decrease)
// =============================================================================

class CongestionController {
public:
    CongestionController();

    // Get current congestion window (in packets)
    uint32_t getCwnd() const { return m_cwnd; }

    // Can we send more packets?
    bool canSend(uint32_t inFlightPackets) const;

    // Called when an ACK is received (additive increase)
    void onAck();

    // Called when packet loss is detected (multiplicative decrease)
    void onLoss();

    // Called on timeout (severe congestion)
    void onTimeout();

    // Reset to initial state
    void reset();

    // Get slow start threshold
    uint32_t getSsthresh() const { return m_ssthresh; }

private:
    uint32_t m_cwnd;      // Congestion window (packets)
    uint32_t m_ssthresh;  // Slow start threshold
    uint32_t m_ackCount;  // ACKs received in current window (for congestion avoidance)
};

// =============================================================================
// UdpTransport Class
// =============================================================================

class UdpTransport : public ITransport {
public:
    // -------------------------------------------------------------------------
    // Factory Methods
    // -------------------------------------------------------------------------

    /**
     * Create a new UDP transport by connecting to a remote peer.
     * Performs handshake to establish connection.
     *
     * @param host Remote hostname or IP address
     * @param port Remote port number
     * @param localPort Local port to bind to (0 for auto-assign)
     * @return UdpTransport on success, error string on failure
     */
    static Result<std::unique_ptr<UdpTransport>, std::string> connect(
        const std::string& host,
        uint16_t port,
        uint16_t localPort = 0);

    /**
     * Create a UDP transport from an already-established hole punch.
     * The socket is already bound and the peer endpoint is known.
     * Still performs reliability handshake over the established path.
     *
     * @param sock The hole-punched UDP socket (takes ownership)
     * @param peerIp Peer's IP address (from hole punch)
     * @param peerPort Peer's port (from hole punch)
     * @return UdpTransport on success, error string on failure
     */
    static Result<std::unique_ptr<UdpTransport>, std::string> fromHolePunch(
        SOCKET sock,
        const std::string& peerIp,
        uint16_t peerPort);

    /**
     * Create a listening UDP transport that waits for incoming connection.
     *
     * @param localPort Local port to listen on
     * @param timeoutMs Timeout for waiting for connection (0 = infinite)
     * @return UdpTransport on success, error string on failure
     */
    static Result<std::unique_ptr<UdpTransport>, std::string> listen(
        uint16_t localPort,
        int timeoutMs = 0);

    // -------------------------------------------------------------------------
    // Destructor
    // -------------------------------------------------------------------------
    ~UdpTransport() override;

    // Move only (no copy)
    UdpTransport(UdpTransport&& other) noexcept;
    UdpTransport& operator=(UdpTransport&& other) noexcept;
    UdpTransport(const UdpTransport&) = delete;
    UdpTransport& operator=(const UdpTransport&) = delete;

    // -------------------------------------------------------------------------
    // ITransport Interface
    // -------------------------------------------------------------------------

    /**
     * Send a message with reliable delivery.
     * Message is queued for transmission and will be retransmitted until ACKed.
     *
     * @param type Application-level message type
     * @param payload Message payload bytes
     * @return Success or error
     */
    VoidResult send(MsgType type, const std::vector<uint8_t>& payload) override;

    /**
     * Receive the next message in order.
     * Blocks until a message is available or an error occurs.
     * Messages are delivered in sequence number order (no gaps).
     *
     * @return Message type and payload, or error string
     */
    Result<std::pair<MsgType, std::vector<uint8_t>>, std::string> receive() override;

    /**
     * Close the connection gracefully.
     * Sends CLOSE packet and waits for acknowledgment.
     */
    void close() override;

    /**
     * Check if connection is established and healthy.
     */
    bool isConnected() const override;

    /**
     * Get remote endpoint as "ip:port" string.
     */
    std::string remoteEndpoint() const override;

    // -------------------------------------------------------------------------
    // Additional Public Methods
    // -------------------------------------------------------------------------

    /**
     * Get connection statistics.
     */
    struct Stats {
        uint64_t packetsSent        = 0;
        uint64_t packetsReceived    = 0;
        uint64_t packetsRetransmit  = 0;
        uint64_t packetsDropped     = 0;
        uint64_t bytesSent          = 0;
        uint64_t bytesReceived      = 0;
        int      currentRttMs       = 0;
        int      currentRtoMs       = 0;
        uint32_t currentCwnd        = 0;
        uint32_t packetsInFlight    = 0;
    };

    Stats getStats() const;

    /**
     * Get current connection state.
     */
    UdpConnectionState getState() const;

    /**
     * Set receive timeout (0 = blocking).
     */
    void setReceiveTimeout(int timeoutMs);

    /**
     * Get local endpoint as "ip:port" string.
     */
    std::string localEndpoint() const;

private:
    // -------------------------------------------------------------------------
    // Private Constructor (use factory methods)
    // -------------------------------------------------------------------------
    UdpTransport();

    // -------------------------------------------------------------------------
    // Internal Packet Sending
    // -------------------------------------------------------------------------

    // Send raw packet to peer (does not add to retransmit queue)
    VoidResult sendPacket(const UdpPacketHeader& header, const uint8_t* payload, size_t payloadLen);

    // Send data packet with reliability (adds to retransmit queue)
    VoidResult sendDataPacket(MsgType msgType, const std::vector<uint8_t>& payload);

    // Send ACK packet
    VoidResult sendAck();

    // Send heartbeat
    VoidResult sendHeartbeat();

    // Send close packet
    VoidResult sendClose();

    // -------------------------------------------------------------------------
    // Handshake
    // -------------------------------------------------------------------------

    // Initiate handshake as client
    VoidResult initiateHandshake();

    // Handle incoming handshake (as server)
    VoidResult handleHandshakeInit(const UdpHandshakePacket& packet, const sockaddr_in& from);

    // Complete handshake (both sides)
    VoidResult completeHandshake(const UdpHandshakePacket& packet);

    // -------------------------------------------------------------------------
    // Packet Processing
    // -------------------------------------------------------------------------

    // Receive and process one packet (internal)
    VoidResult processIncomingPacket();

    // Handle received data packet
    void handleDataPacket(const UdpPacketHeader& header, const uint8_t* payload, size_t len);

    // Handle received ACK packet
    void handleAckPacket(const UdpPacketHeader& header, const uint8_t* payload, size_t len);

    // Handle received heartbeat
    void handleHeartbeat(const UdpPacketHeader& header);

    // Handle received close
    void handleClose();

    // -------------------------------------------------------------------------
    // Retransmission
    // -------------------------------------------------------------------------

    // Check for packets that need retransmission
    void checkRetransmissions();

    // Retransmit a specific packet
    VoidResult retransmitPacket(RetransmitEntry& entry);

    // Remove acknowledged packets from retransmit queue
    void acknowledgePackets(uint32_t cumAck, const UdpAckPacket& sack);

    // -------------------------------------------------------------------------
    // Receive Reordering
    // -------------------------------------------------------------------------

    // Insert received message into reorder buffer
    void insertIntoReorderBuffer(uint32_t seqNum, MsgType msgType, const std::vector<uint8_t>& payload);

    // Try to deliver messages from reorder buffer to application
    bool deliverFromReorderBuffer();

    // -------------------------------------------------------------------------
    // Background Thread
    // -------------------------------------------------------------------------

    // Main loop for background processing (heartbeats, retransmissions)
    void backgroundLoop();

    // -------------------------------------------------------------------------
    // Member Variables
    // -------------------------------------------------------------------------

    // Socket and endpoint
    p2p::Socket                 m_socket;
    sockaddr_in                 m_peerAddr;
    std::string                 m_peerIp;
    uint16_t                    m_peerPort = 0;

    // Connection state
    std::atomic<UdpConnectionState> m_state{UdpConnectionState::CLOSED};
    uint32_t                    m_connectionId = 0;
    uint32_t                    m_peerConnectionId = 0;

    // Sequence numbers
    std::atomic<uint32_t>       m_nextSeqNum{0};       // Next seq to send
    uint32_t                    m_nextExpectedSeq = 0; // Next seq to receive
    uint32_t                    m_lastAckSent = 0;     // Last cumulative ACK sent

    // Retransmission queue (keyed by sequence number)
    std::map<uint32_t, RetransmitEntry> m_retransmitQueue;
    mutable std::mutex          m_retransmitMutex;

    // Receive reorder buffer (keyed by sequence number)
    std::map<uint32_t, ReceivedMessage> m_reorderBuffer;
    mutable std::mutex          m_reorderMutex;

    // Received message queue (for application)
    std::queue<ReceivedMessage> m_receiveQueue;
    mutable std::mutex          m_receiveMutex;
    std::condition_variable     m_receiveCondition;

    // RTT estimation and congestion control
    RttEstimator                m_rttEstimator;
    CongestionController        m_congestion;
    mutable std::mutex          m_congestionMutex;

    // Timing
    std::chrono::steady_clock::time_point m_lastPacketReceived;
    std::chrono::steady_clock::time_point m_lastHeartbeatSent;
    int                         m_receiveTimeoutMs = 0;

    // Statistics
    mutable std::mutex          m_statsMutex;
    Stats                       m_stats;

    // Background thread
    std::thread                 m_backgroundThread;
    std::atomic<bool>           m_running{false};
    std::condition_variable     m_backgroundCondition;
    std::mutex                  m_backgroundMutex;

    // SACK state for generating ACKs
    std::deque<uint32_t>        m_outOfOrderReceived;  // Out-of-order seq numbers received
    mutable std::mutex          m_sackMutex;
};

} // namespace p2p
