// =============================================================================
// udp_transport.cpp - DTLS-style reliable UDP transport implementation
// =============================================================================

#include "udp_transport.h"

#include <algorithm>
#include <random>
#include <sstream>
#include <cstring>

namespace p2p {

// =============================================================================
// Helper Functions
// =============================================================================

namespace {

// Generate a random 32-bit value
uint32_t generateRandomU32() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);
    return dist(gen);
}

// Get current timestamp in milliseconds since epoch
uint32_t getCurrentTimestampMs() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    return static_cast<uint32_t>(ms & 0xFFFFFFFF);
}

// Write uint16_t in big-endian
void writeU16BE(uint8_t* buf, uint16_t val) {
    buf[0] = static_cast<uint8_t>((val >> 8) & 0xFF);
    buf[1] = static_cast<uint8_t>(val & 0xFF);
}

// Write uint32_t in big-endian
void writeU32BE(uint8_t* buf, uint32_t val) {
    buf[0] = static_cast<uint8_t>((val >> 24) & 0xFF);
    buf[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
    buf[2] = static_cast<uint8_t>((val >> 8) & 0xFF);
    buf[3] = static_cast<uint8_t>(val & 0xFF);
}

// Read uint16_t from big-endian
uint16_t readU16BE(const uint8_t* buf) {
    return (static_cast<uint16_t>(buf[0]) << 8) |
           static_cast<uint16_t>(buf[1]);
}

// Read uint32_t from big-endian
uint32_t readU32BE(const uint8_t* buf) {
    return (static_cast<uint32_t>(buf[0]) << 24) |
           (static_cast<uint32_t>(buf[1]) << 16) |
           (static_cast<uint32_t>(buf[2]) << 8) |
           static_cast<uint32_t>(buf[3]);
}

} // anonymous namespace

// =============================================================================
// UdpPacketHeader Implementation
// =============================================================================

void UdpPacketHeader::serialize(uint8_t* buf) const {
    // Wire format (12 bytes):
    //   [0]      - packet type
    //   [1]      - flags
    //   [2..3]   - payload length (big-endian)
    //   [4..7]   - sequence number (big-endian)
    //   [8..11]  - acknowledgment number (big-endian)
    buf[0] = static_cast<uint8_t>(type);
    buf[1] = flags;
    writeU16BE(buf + 2, payloadLen);
    writeU32BE(buf + 4, seqNum);
    writeU32BE(buf + 8, ackNum);
}

bool UdpPacketHeader::deserialize(const uint8_t* buf, size_t len, UdpPacketHeader& out) {
    if (len < SIZE) {
        return false;
    }

    out.type = static_cast<UdpPacketType>(buf[0]);
    out.flags = buf[1];
    out.payloadLen = readU16BE(buf + 2);
    out.seqNum = readU32BE(buf + 4);
    out.ackNum = readU32BE(buf + 8);

    return true;
}

// =============================================================================
// UdpAckPacket Implementation
// =============================================================================

void UdpAckPacket::serialize(uint8_t* buf) const {
    // Wire format (8 bytes):
    //   [0..3]   - cumulative ack (big-endian)
    //   [4..7]   - SACK bitmap
    writeU32BE(buf, cumAck);
    std::memcpy(buf + 4, sackMap, UDP_SACK_BITMAP_SIZE);
}

bool UdpAckPacket::deserialize(const uint8_t* buf, size_t len, UdpAckPacket& out) {
    if (len < SIZE) {
        return false;
    }

    out.cumAck = readU32BE(buf);
    std::memcpy(out.sackMap, buf + 4, UDP_SACK_BITMAP_SIZE);

    return true;
}

void UdpAckPacket::setSackBit(uint32_t offset) {
    if (offset > 0 && offset <= 32) {
        uint32_t bitIndex = offset - 1;
        uint32_t byteIndex = bitIndex / 8;
        uint32_t bitPos = bitIndex % 8;
        if (byteIndex < UDP_SACK_BITMAP_SIZE) {
            sackMap[byteIndex] |= (1 << bitPos);
        }
    }
}

bool UdpAckPacket::getSackBit(uint32_t offset) const {
    if (offset > 0 && offset <= 32) {
        uint32_t bitIndex = offset - 1;
        uint32_t byteIndex = bitIndex / 8;
        uint32_t bitPos = bitIndex % 8;
        if (byteIndex < UDP_SACK_BITMAP_SIZE) {
            return (sackMap[byteIndex] & (1 << bitPos)) != 0;
        }
    }
    return false;
}

// =============================================================================
// UdpHandshakePacket Implementation
// =============================================================================

void UdpHandshakePacket::serialize(uint8_t* buf) const {
    // Wire format (16 bytes):
    //   [0..3]   - connectionId (big-endian)
    //   [4..7]   - initialSeq (big-endian)
    //   [8..11]  - timestamp (big-endian)
    //   [12]     - version
    //   [13..15] - reserved
    writeU32BE(buf, connectionId);
    writeU32BE(buf + 4, initialSeq);
    writeU32BE(buf + 8, timestamp);
    buf[12] = version;
    buf[13] = reserved[0];
    buf[14] = reserved[1];
    buf[15] = reserved[2];
}

bool UdpHandshakePacket::deserialize(const uint8_t* buf, size_t len, UdpHandshakePacket& out) {
    if (len < SIZE) {
        return false;
    }

    out.connectionId = readU32BE(buf);
    out.initialSeq = readU32BE(buf + 4);
    out.timestamp = readU32BE(buf + 8);
    out.version = buf[12];
    out.reserved[0] = buf[13];
    out.reserved[1] = buf[14];
    out.reserved[2] = buf[15];

    return true;
}

// =============================================================================
// RttEstimator Implementation (Jacobson/Karels Algorithm)
// =============================================================================

RttEstimator::RttEstimator()
    : m_srtt(UDP_INITIAL_RTO_MS << 3)  // Scale by 8
    , m_rttvar(UDP_INITIAL_RTO_MS << 1) // Initial variance = RTO/2, scaled by 4
    , m_hasFirstSample(false)
{
}

void RttEstimator::addSample(int rttMs) {
    if (!m_hasFirstSample) {
        // First sample: initialize SRTT and RTTVAR
        m_srtt = rttMs << 3;   // Scale by 8
        m_rttvar = rttMs << 1;  // Scale by 4, initial = RTT/2
        m_hasFirstSample = true;
        LOG_DEBUG("RttEstimator: First sample rtt=" + std::to_string(rttMs) +
                  "ms, srtt=" + std::to_string(m_srtt >> 3) +
                  "ms, rttvar=" + std::to_string(m_rttvar >> 2) + "ms");
    } else {
        // Jacobson/Karels algorithm:
        // SRTT = (1 - alpha) * SRTT + alpha * RTT, where alpha = 1/8
        // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - RTT|, where beta = 1/4
        int delta = rttMs - (m_srtt >> 3);
        m_srtt += delta;  // alpha = 1/8: adds delta/8 to srtt

        if (delta < 0) delta = -delta;
        m_rttvar += (delta - (m_rttvar >> 2));  // beta = 1/4

        LOG_DEBUG("RttEstimator: Sample rtt=" + std::to_string(rttMs) +
                  "ms, srtt=" + std::to_string(m_srtt >> 3) +
                  "ms, rto=" + std::to_string(getRto()) + "ms");
    }
}

int RttEstimator::getRto() const {
    // RTO = SRTT + max(G, 4 * RTTVAR), where G = 1ms (clock granularity)
    int rto = (m_srtt >> 3) + std::max(1, m_rttvar);
    return std::clamp(rto, UDP_MIN_RTO_MS, UDP_MAX_RTO_MS);
}

void RttEstimator::reset() {
    m_srtt = UDP_INITIAL_RTO_MS << 3;
    m_rttvar = UDP_INITIAL_RTO_MS << 1;
    m_hasFirstSample = false;
}

// =============================================================================
// CongestionController Implementation (AIMD)
// =============================================================================

CongestionController::CongestionController()
    : m_cwnd(UDP_INITIAL_CWND)
    , m_ssthresh(UDP_SSTHRESH_INITIAL)
    , m_ackCount(0)
{
}

bool CongestionController::canSend(uint32_t inFlightPackets) const {
    return inFlightPackets < m_cwnd;
}

void CongestionController::onAck() {
    if (m_cwnd < m_ssthresh) {
        // Slow start: exponential growth
        m_cwnd++;
        LOG_DEBUG("CongestionController: Slow start, cwnd=" + std::to_string(m_cwnd));
    } else {
        // Congestion avoidance: linear growth (1/cwnd per ACK)
        m_ackCount++;
        if (m_ackCount >= m_cwnd) {
            m_cwnd++;
            m_ackCount = 0;
            LOG_DEBUG("CongestionController: Congestion avoidance, cwnd=" + std::to_string(m_cwnd));
        }
    }

    // Cap at maximum
    if (m_cwnd > UDP_MAX_CWND) {
        m_cwnd = UDP_MAX_CWND;
    }
}

void CongestionController::onLoss() {
    // Fast recovery: multiplicative decrease
    m_ssthresh = std::max(m_cwnd / 2, UDP_MIN_CWND);
    m_cwnd = m_ssthresh;
    m_ackCount = 0;
    LOG_DEBUG("CongestionController: Loss detected, ssthresh=" + std::to_string(m_ssthresh) +
              ", cwnd=" + std::to_string(m_cwnd));
}

void CongestionController::onTimeout() {
    // Timeout: severe congestion, back to slow start
    m_ssthresh = std::max(m_cwnd / 2, UDP_MIN_CWND);
    m_cwnd = UDP_MIN_CWND;
    m_ackCount = 0;
    LOG_DEBUG("CongestionController: Timeout, ssthresh=" + std::to_string(m_ssthresh) +
              ", cwnd=" + std::to_string(m_cwnd));
}

void CongestionController::reset() {
    m_cwnd = UDP_INITIAL_CWND;
    m_ssthresh = UDP_SSTHRESH_INITIAL;
    m_ackCount = 0;
}

// =============================================================================
// UdpTransport Implementation
// =============================================================================

UdpTransport::UdpTransport()
    : m_peerAddr{}
{
    // Initialize Winsock
    WinsockInit::instance();
}

UdpTransport::~UdpTransport() {
    close();
}

UdpTransport::UdpTransport(UdpTransport&& other) noexcept
    : m_socket(std::move(other.m_socket))
    , m_peerAddr(other.m_peerAddr)
    , m_peerIp(std::move(other.m_peerIp))
    , m_peerPort(other.m_peerPort)
    , m_state(other.m_state.load())
    , m_connectionId(other.m_connectionId)
    , m_peerConnectionId(other.m_peerConnectionId)
    , m_nextSeqNum(other.m_nextSeqNum.load())
    , m_nextExpectedSeq(other.m_nextExpectedSeq)
    , m_lastAckSent(other.m_lastAckSent)
    , m_rttEstimator(other.m_rttEstimator)
    , m_congestion(other.m_congestion)
    , m_lastPacketReceived(other.m_lastPacketReceived)
    , m_lastHeartbeatSent(other.m_lastHeartbeatSent)
    , m_receiveTimeoutMs(other.m_receiveTimeoutMs)
    , m_stats(other.m_stats)
    , m_running(other.m_running.load())
{
    other.m_running = false;
    other.m_state = UdpConnectionState::CLOSED;
}

UdpTransport& UdpTransport::operator=(UdpTransport&& other) noexcept {
    if (this != &other) {
        close();

        m_socket = std::move(other.m_socket);
        m_peerAddr = other.m_peerAddr;
        m_peerIp = std::move(other.m_peerIp);
        m_peerPort = other.m_peerPort;
        m_state = other.m_state.load();
        m_connectionId = other.m_connectionId;
        m_peerConnectionId = other.m_peerConnectionId;
        m_nextSeqNum = other.m_nextSeqNum.load();
        m_nextExpectedSeq = other.m_nextExpectedSeq;
        m_lastAckSent = other.m_lastAckSent;
        m_rttEstimator = other.m_rttEstimator;
        m_congestion = other.m_congestion;
        m_lastPacketReceived = other.m_lastPacketReceived;
        m_lastHeartbeatSent = other.m_lastHeartbeatSent;
        m_receiveTimeoutMs = other.m_receiveTimeoutMs;
        m_stats = other.m_stats;
        m_running = other.m_running.load();

        other.m_running = false;
        other.m_state = UdpConnectionState::CLOSED;
    }
    return *this;
}

// =============================================================================
// Factory Methods
// =============================================================================

Result<std::unique_ptr<UdpTransport>, std::string> UdpTransport::connect(
    const std::string& host,
    uint16_t port,
    uint16_t localPort)
{
    LOG_INFO("UdpTransport::connect: Connecting to " + host + ":" + std::to_string(port));

    // Create UDP socket
    auto sockResult = Socket::createUdp();
    if (!sockResult) {
        LOG_ERROR("UdpTransport::connect: Failed to create socket: " + sockResult.error());
        return Result<std::unique_ptr<UdpTransport>, std::string>::Err(sockResult.error());
    }

    auto transport = std::unique_ptr<UdpTransport>(new UdpTransport());
    transport->m_socket = std::move(sockResult.value());

    // Set socket options
    transport->m_socket.setReuseAddr(true);

    // Bind to local port
    auto bindResult = transport->m_socket.bind(localPort);
    if (!bindResult) {
        LOG_ERROR("UdpTransport::connect: Failed to bind: " + bindResult.error());
        return Result<std::unique_ptr<UdpTransport>, std::string>::Err(bindResult.error());
    }

    LOG_DEBUG("UdpTransport::connect: Bound to " + transport->m_socket.localAddress());

    // Resolve peer address
    transport->m_peerAddr.sin_family = AF_INET;
    transport->m_peerAddr.sin_port = htons(port);

    if (InetPtonA(AF_INET, host.c_str(), &transport->m_peerAddr.sin_addr) != 1) {
        // Try DNS resolution
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;

        addrinfo* result = nullptr;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || !result) {
            LOG_ERROR("UdpTransport::connect: Cannot resolve host: " + host);
            return Result<std::unique_ptr<UdpTransport>, std::string>::Err(
                "Cannot resolve host: " + host);
        }

        transport->m_peerAddr.sin_addr = ((sockaddr_in*)result->ai_addr)->sin_addr;
        freeaddrinfo(result);
    }

    transport->m_peerIp = host;
    transport->m_peerPort = port;

    // Initiate handshake
    auto hsResult = transport->initiateHandshake();
    if (!hsResult) {
        LOG_ERROR("UdpTransport::connect: Handshake failed: " + hsResult.error());
        return Result<std::unique_ptr<UdpTransport>, std::string>::Err(hsResult.error());
    }

    // Start background thread
    transport->m_running = true;
    transport->m_backgroundThread = std::thread(&UdpTransport::backgroundLoop, transport.get());

    LOG_INFO("UdpTransport::connect: Connected to " + transport->remoteEndpoint());

    return Result<std::unique_ptr<UdpTransport>, std::string>::Ok(std::move(transport));
}

Result<std::unique_ptr<UdpTransport>, std::string> UdpTransport::fromHolePunch(
    SOCKET sock,
    const std::string& peerIp,
    uint16_t peerPort)
{
    LOG_INFO("UdpTransport::fromHolePunch: Wrapping socket for " + peerIp + ":" + std::to_string(peerPort));

    auto transport = std::unique_ptr<UdpTransport>(new UdpTransport());
    transport->m_socket = Socket(sock);

    // Set up peer address
    transport->m_peerAddr.sin_family = AF_INET;
    transport->m_peerAddr.sin_port = htons(peerPort);
    if (InetPtonA(AF_INET, peerIp.c_str(), &transport->m_peerAddr.sin_addr) != 1) {
        LOG_ERROR("UdpTransport::fromHolePunch: Invalid peer IP: " + peerIp);
        return Result<std::unique_ptr<UdpTransport>, std::string>::Err(
            "Invalid peer IP: " + peerIp);
    }

    transport->m_peerIp = peerIp;
    transport->m_peerPort = peerPort;

    // Initiate handshake
    auto hsResult = transport->initiateHandshake();
    if (!hsResult) {
        LOG_ERROR("UdpTransport::fromHolePunch: Handshake failed: " + hsResult.error());
        return Result<std::unique_ptr<UdpTransport>, std::string>::Err(hsResult.error());
    }

    // Start background thread
    transport->m_running = true;
    transport->m_backgroundThread = std::thread(&UdpTransport::backgroundLoop, transport.get());

    LOG_INFO("UdpTransport::fromHolePunch: Connected to " + transport->remoteEndpoint());

    return Result<std::unique_ptr<UdpTransport>, std::string>::Ok(std::move(transport));
}

Result<std::unique_ptr<UdpTransport>, std::string> UdpTransport::listen(
    uint16_t localPort,
    int timeoutMs)
{
    LOG_INFO("UdpTransport::listen: Listening on port " + std::to_string(localPort));

    // Create UDP socket
    auto sockResult = Socket::createUdp();
    if (!sockResult) {
        LOG_ERROR("UdpTransport::listen: Failed to create socket: " + sockResult.error());
        return Result<std::unique_ptr<UdpTransport>, std::string>::Err(sockResult.error());
    }

    auto transport = std::unique_ptr<UdpTransport>(new UdpTransport());
    transport->m_socket = std::move(sockResult.value());

    // Set socket options
    transport->m_socket.setReuseAddr(true);

    // Bind to local port
    auto bindResult = transport->m_socket.bind(localPort);
    if (!bindResult) {
        LOG_ERROR("UdpTransport::listen: Failed to bind: " + bindResult.error());
        return Result<std::unique_ptr<UdpTransport>, std::string>::Err(bindResult.error());
    }

    LOG_DEBUG("UdpTransport::listen: Bound to " + transport->m_socket.localAddress());

    // Wait for HANDSHAKE_INIT
    transport->m_state = UdpConnectionState::CLOSED;

    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeoutMs > 0 ? timeoutMs : UDP_HANDSHAKE_TIMEOUT_MS);

    uint8_t recvBuf[UDP_MAX_PACKET_SIZE];
    sockaddr_in fromAddr{};
    int fromLen = sizeof(fromAddr);

    while (std::chrono::steady_clock::now() < deadline) {
        // Set up select for receive with timeout
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(transport->m_socket.handle(), &readSet);

        timeval tv;
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) break;

        tv.tv_sec = static_cast<long>(remaining / 1000);
        tv.tv_usec = static_cast<long>((remaining % 1000) * 1000);

        int selectResult = select(0, &readSet, nullptr, nullptr, &tv);
        if (selectResult <= 0) {
            continue;  // Timeout or error, try again
        }

        // Receive packet
        int recvLen = recvfrom(transport->m_socket.handle(),
                               reinterpret_cast<char*>(recvBuf),
                               sizeof(recvBuf),
                               0,
                               reinterpret_cast<sockaddr*>(&fromAddr),
                               &fromLen);

        if (recvLen <= 0) {
            continue;
        }

        // Parse header
        UdpPacketHeader header;
        if (!UdpPacketHeader::deserialize(recvBuf, recvLen, header)) {
            LOG_DEBUG("UdpTransport::listen: Invalid packet header");
            continue;
        }

        // Check for HANDSHAKE_INIT
        if (header.type == UdpPacketType::HANDSHAKE_INIT) {
            LOG_DEBUG("UdpTransport::listen: Received HANDSHAKE_INIT");

            // Parse handshake packet
            if (static_cast<size_t>(recvLen) < UDP_HEADER_SIZE + UdpHandshakePacket::SIZE) {
                LOG_DEBUG("UdpTransport::listen: HANDSHAKE_INIT too short");
                continue;
            }

            UdpHandshakePacket hsPacket;
            if (!UdpHandshakePacket::deserialize(recvBuf + UDP_HEADER_SIZE,
                                                  header.payloadLen,
                                                  hsPacket)) {
                LOG_DEBUG("UdpTransport::listen: Invalid handshake packet");
                continue;
            }

            // Store peer info
            transport->m_peerAddr = fromAddr;
            char peerIpBuf[64];
            inet_ntop(AF_INET, &fromAddr.sin_addr, peerIpBuf, sizeof(peerIpBuf));
            transport->m_peerIp = peerIpBuf;
            transport->m_peerPort = ntohs(fromAddr.sin_port);

            // Handle the handshake init
            auto result = transport->handleHandshakeInit(hsPacket, fromAddr);
            if (result) {
                // Start background thread
                transport->m_running = true;
                transport->m_backgroundThread = std::thread(&UdpTransport::backgroundLoop, transport.get());

                LOG_INFO("UdpTransport::listen: Accepted connection from " + transport->remoteEndpoint());

                return Result<std::unique_ptr<UdpTransport>, std::string>::Ok(std::move(transport));
            }
        }
    }

    LOG_ERROR("UdpTransport::listen: Timeout waiting for connection");
    return Result<std::unique_ptr<UdpTransport>, std::string>::Err("Timeout waiting for connection");
}

// =============================================================================
// ITransport Interface Implementation
// =============================================================================

VoidResult UdpTransport::send(MsgType type, const std::vector<uint8_t>& payload) {
    if (m_state != UdpConnectionState::ESTABLISHED) {
        return VoidResult::Err("Connection not established");
    }

    return sendDataPacket(type, payload);
}

Result<std::pair<MsgType, std::vector<uint8_t>>, std::string> UdpTransport::receive() {
    std::unique_lock<std::mutex> lock(m_receiveMutex);

    // Wait for a message or error condition
    auto predicate = [this]() {
        return !m_receiveQueue.empty() ||
               m_state == UdpConnectionState::CLOSED ||
               m_state == UdpConnectionState::CLOSING;
    };

    if (m_receiveTimeoutMs > 0) {
        if (!m_receiveCondition.wait_for(lock,
                                         std::chrono::milliseconds(m_receiveTimeoutMs),
                                         predicate)) {
            return Result<std::pair<MsgType, std::vector<uint8_t>>, std::string>::Err("Receive timeout");
        }
    } else {
        m_receiveCondition.wait(lock, predicate);
    }

    // Check for closed connection
    if (m_receiveQueue.empty()) {
        if (m_state == UdpConnectionState::CLOSED || m_state == UdpConnectionState::CLOSING) {
            return Result<std::pair<MsgType, std::vector<uint8_t>>, std::string>::Err("Connection closed");
        }
        return Result<std::pair<MsgType, std::vector<uint8_t>>, std::string>::Err("No message available");
    }

    // Get next message
    auto msg = std::move(m_receiveQueue.front());
    m_receiveQueue.pop();

    LOG_DEBUG("UdpTransport::receive: Delivered message type=" +
              std::string(MsgTypeName(msg.msgType)) +
              ", len=" + std::to_string(msg.payload.size()));

    return Result<std::pair<MsgType, std::vector<uint8_t>>, std::string>::Ok(
        std::make_pair(msg.msgType, std::move(msg.payload)));
}

void UdpTransport::close() {
    if (m_state == UdpConnectionState::CLOSED) {
        return;
    }

    LOG_INFO("UdpTransport::close: Closing connection");

    // Set state to CLOSING
    m_state = UdpConnectionState::CLOSING;

    // Send CLOSE packet (best effort)
    sendClose();

    // Stop background thread
    m_running = false;

    {
        std::lock_guard<std::mutex> lock(m_backgroundMutex);
        m_backgroundCondition.notify_all();
    }

    if (m_backgroundThread.joinable()) {
        m_backgroundThread.join();
    }

    // Notify waiting receivers
    {
        std::lock_guard<std::mutex> lock(m_receiveMutex);
        m_receiveCondition.notify_all();
    }

    // Close socket
    m_socket.close();

    m_state = UdpConnectionState::CLOSED;

    LOG_INFO("UdpTransport::close: Connection closed");
}

bool UdpTransport::isConnected() const {
    return m_state == UdpConnectionState::ESTABLISHED;
}

std::string UdpTransport::remoteEndpoint() const {
    return m_peerIp + ":" + std::to_string(m_peerPort);
}

// =============================================================================
// Additional Public Methods
// =============================================================================

UdpTransport::Stats UdpTransport::getStats() const {
    std::lock_guard<std::mutex> lock(m_statsMutex);
    Stats stats = m_stats;

    std::lock_guard<std::mutex> congLock(m_congestionMutex);
    stats.currentRttMs = m_rttEstimator.getSrtt() >> 3;
    stats.currentRtoMs = m_rttEstimator.getRto();
    stats.currentCwnd = m_congestion.getCwnd();

    std::lock_guard<std::mutex> rtxLock(m_retransmitMutex);
    stats.packetsInFlight = static_cast<uint32_t>(m_retransmitQueue.size());

    return stats;
}

UdpConnectionState UdpTransport::getState() const {
    return m_state.load();
}

void UdpTransport::setReceiveTimeout(int timeoutMs) {
    m_receiveTimeoutMs = timeoutMs;
}

std::string UdpTransport::localEndpoint() const {
    return m_socket.localAddress();
}

// =============================================================================
// Internal Packet Sending
// =============================================================================

VoidResult UdpTransport::sendPacket(const UdpPacketHeader& header,
                                     const uint8_t* payload,
                                     size_t payloadLen) {
    if (!m_socket.isValid()) {
        return VoidResult::Err("Socket not valid");
    }

    // Build packet
    std::vector<uint8_t> packet(UDP_HEADER_SIZE + payloadLen);
    header.serialize(packet.data());
    if (payloadLen > 0 && payload) {
        std::memcpy(packet.data() + UDP_HEADER_SIZE, payload, payloadLen);
    }

    // Send
    int sent = sendto(m_socket.handle(),
                      reinterpret_cast<const char*>(packet.data()),
                      static_cast<int>(packet.size()),
                      0,
                      reinterpret_cast<const sockaddr*>(&m_peerAddr),
                      sizeof(m_peerAddr));

    if (sent == SOCKET_ERROR) {
        int err = WSAGetLastError();
        LOG_ERROR("UdpTransport::sendPacket: sendto failed: " + std::to_string(err));
        return VoidResult::Err("sendto failed: " + std::to_string(err));
    }

    // Update stats
    {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        m_stats.packetsSent++;
        m_stats.bytesSent += sent;
    }

    LOG_DEBUG("UdpTransport::sendPacket: Sent " + std::string(UdpPacketTypeName(header.type)) +
              " seq=" + std::to_string(header.seqNum) +
              " ack=" + std::to_string(header.ackNum) +
              " len=" + std::to_string(payloadLen));

    return VoidResult::Ok();
}

VoidResult UdpTransport::sendDataPacket(MsgType msgType, const std::vector<uint8_t>& payload) {
    // Check congestion window
    {
        std::lock_guard<std::mutex> rtxLock(m_retransmitMutex);
        std::lock_guard<std::mutex> congLock(m_congestionMutex);

        if (!m_congestion.canSend(static_cast<uint32_t>(m_retransmitQueue.size()))) {
            LOG_DEBUG("UdpTransport::sendDataPacket: Congestion window full");
            return VoidResult::Err("Congestion window full");
        }
    }

    // Build DATA payload: [msgType:1][payload:N]
    std::vector<uint8_t> dataPayload(1 + payload.size());
    dataPayload[0] = static_cast<uint8_t>(msgType);
    if (!payload.empty()) {
        std::memcpy(dataPayload.data() + 1, payload.data(), payload.size());
    }

    // Get sequence number
    uint32_t seqNum = m_nextSeqNum.fetch_add(1);

    // Build header
    UdpPacketHeader header;
    header.type = UdpPacketType::DATA;
    header.flags = 0;
    header.payloadLen = static_cast<uint16_t>(dataPayload.size());
    header.seqNum = seqNum;
    header.ackNum = m_nextExpectedSeq > 0 ? m_nextExpectedSeq - 1 : 0;

    // Build complete packet for retransmission queue
    std::vector<uint8_t> packet(UDP_HEADER_SIZE + dataPayload.size());
    header.serialize(packet.data());
    std::memcpy(packet.data() + UDP_HEADER_SIZE, dataPayload.data(), dataPayload.size());

    // Add to retransmit queue
    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(m_retransmitMutex);
        std::lock_guard<std::mutex> congLock(m_congestionMutex);

        RetransmitEntry entry;
        entry.seqNum = seqNum;
        entry.packet = packet;
        entry.firstSent = now;
        entry.lastSent = now;
        entry.retryCount = 0;
        entry.rtoMs = m_rttEstimator.getRto();

        m_retransmitQueue[seqNum] = std::move(entry);
    }

    // Send packet
    auto result = sendPacket(header, dataPayload.data(), dataPayload.size());
    if (!result) {
        // Remove from retransmit queue on send failure
        std::lock_guard<std::mutex> lock(m_retransmitMutex);
        m_retransmitQueue.erase(seqNum);
        return result;
    }

    LOG_DEBUG("UdpTransport::sendDataPacket: Sent DATA msgType=" +
              std::string(MsgTypeName(msgType)) +
              " seq=" + std::to_string(seqNum) +
              " len=" + std::to_string(payload.size()));

    return VoidResult::Ok();
}

VoidResult UdpTransport::sendAck() {
    // Build ACK packet payload
    UdpAckPacket ackPayload;
    ackPayload.cumAck = m_nextExpectedSeq > 0 ? m_nextExpectedSeq - 1 : 0;

    // Fill SACK bitmap from out-of-order received packets
    {
        std::lock_guard<std::mutex> lock(m_sackMutex);
        for (uint32_t seqNum : m_outOfOrderReceived) {
            if (seqNum > ackPayload.cumAck && seqNum <= ackPayload.cumAck + 32) {
                ackPayload.setSackBit(seqNum - ackPayload.cumAck);
            }
        }
    }

    std::vector<uint8_t> payload(UdpAckPacket::SIZE);
    ackPayload.serialize(payload.data());

    UdpPacketHeader header;
    header.type = UdpPacketType::ACK;
    header.flags = 0;
    header.payloadLen = static_cast<uint16_t>(payload.size());
    header.seqNum = 0;
    header.ackNum = ackPayload.cumAck;

    m_lastAckSent = ackPayload.cumAck;

    return sendPacket(header, payload.data(), payload.size());
}

VoidResult UdpTransport::sendHeartbeat() {
    UdpPacketHeader header;
    header.type = UdpPacketType::HEARTBEAT;
    header.flags = 0;
    header.payloadLen = 0;
    header.seqNum = 0;
    header.ackNum = m_nextExpectedSeq > 0 ? m_nextExpectedSeq - 1 : 0;

    m_lastHeartbeatSent = std::chrono::steady_clock::now();

    LOG_DEBUG("UdpTransport::sendHeartbeat: Sending heartbeat");

    return sendPacket(header, nullptr, 0);
}

VoidResult UdpTransport::sendClose() {
    UdpPacketHeader header;
    header.type = UdpPacketType::CLOSE;
    header.flags = 0;
    header.payloadLen = 0;
    header.seqNum = m_nextSeqNum;
    header.ackNum = m_nextExpectedSeq > 0 ? m_nextExpectedSeq - 1 : 0;

    LOG_DEBUG("UdpTransport::sendClose: Sending CLOSE");

    return sendPacket(header, nullptr, 0);
}

// =============================================================================
// Handshake Implementation
// =============================================================================

VoidResult UdpTransport::initiateHandshake() {
    LOG_INFO("UdpTransport::initiateHandshake: Starting handshake");

    // Generate our connection parameters
    m_connectionId = generateRandomU32();
    m_nextSeqNum = generateRandomU32() & 0x00FFFFFF;  // Start with random, leaving room
    m_nextExpectedSeq = 0;

    // Build handshake packet
    UdpHandshakePacket hsPacket;
    hsPacket.connectionId = m_connectionId;
    hsPacket.initialSeq = m_nextSeqNum;
    hsPacket.timestamp = getCurrentTimestampMs();
    hsPacket.version = 1;

    std::vector<uint8_t> payload(UdpHandshakePacket::SIZE);
    hsPacket.serialize(payload.data());

    UdpPacketHeader header;
    header.type = UdpPacketType::HANDSHAKE_INIT;
    header.flags = 0;
    header.payloadLen = static_cast<uint16_t>(payload.size());
    header.seqNum = 0;
    header.ackNum = 0;

    m_state = UdpConnectionState::HANDSHAKE_SENT;

    // Retry loop with fixed interval (not exponential - we want consistent retries)
    int retryDelayMs = 2000;  // 2 seconds between retries
    for (int retry = 0; retry < UDP_HANDSHAKE_RETRIES; ++retry) {
        // Only send INIT if we haven't already become responder (simultaneous open)
        if (m_state == UdpConnectionState::HANDSHAKE_SENT) {
            LOG_DEBUG("UdpTransport::initiateHandshake: Sending HANDSHAKE_INIT (attempt " +
                      std::to_string(retry + 1) + ")");

            auto result = sendPacket(header, payload.data(), payload.size());
            if (!result) {
                LOG_ERROR("UdpTransport::initiateHandshake: Send failed: " + result.error());
                return result;
            }
        } else {
            LOG_DEBUG("UdpTransport::initiateHandshake: Waiting for HANDSHAKE_ACK (attempt " +
                      std::to_string(retry + 1) + ")");
        }

        // Wait for response with timeout
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(m_socket.handle(), &readSet);

        timeval tv;
        tv.tv_sec = retryDelayMs / 1000;
        tv.tv_usec = (retryDelayMs % 1000) * 1000;

        int selectResult = select(0, &readSet, nullptr, nullptr, &tv);
        if (selectResult > 0) {
            // Receive packet
            uint8_t recvBuf[UDP_MAX_PACKET_SIZE];
            sockaddr_in fromAddr{};
            int fromLen = sizeof(fromAddr);

            int recvLen = recvfrom(m_socket.handle(),
                                   reinterpret_cast<char*>(recvBuf),
                                   sizeof(recvBuf),
                                   0,
                                   reinterpret_cast<sockaddr*>(&fromAddr),
                                   &fromLen);

            if (recvLen > 0) {
                UdpPacketHeader respHeader;
                if (UdpPacketHeader::deserialize(recvBuf, recvLen, respHeader)) {
                    LOG_INFO("UdpTransport::initiateHandshake: Received packet type=" +
                             std::string(UdpPacketTypeName(respHeader.type)) + " len=" + std::to_string(recvLen));

                    if (respHeader.type == UdpPacketType::HANDSHAKE_RESP) {
                        LOG_DEBUG("UdpTransport::initiateHandshake: Received HANDSHAKE_RESP");

                        if (static_cast<size_t>(recvLen) >= UDP_HEADER_SIZE + UdpHandshakePacket::SIZE) {
                            UdpHandshakePacket respPacket;
                            if (UdpHandshakePacket::deserialize(recvBuf + UDP_HEADER_SIZE,
                                                                 respHeader.payloadLen,
                                                                 respPacket)) {
                                // Complete handshake
                                auto compResult = completeHandshake(respPacket);
                                if (compResult) {
                                    return VoidResult::Ok();
                                }
                            }
                        }
                    }
                    else if (respHeader.type == UdpPacketType::HANDSHAKE_INIT) {
                        // Simultaneous open: both sides sent INIT at the same time
                        LOG_DEBUG("UdpTransport::initiateHandshake: Simultaneous open detected - received HANDSHAKE_INIT");

                        if (static_cast<size_t>(recvLen) >= UDP_HEADER_SIZE + UdpHandshakePacket::SIZE) {
                            UdpHandshakePacket peerPacket;
                            if (UdpHandshakePacket::deserialize(recvBuf + UDP_HEADER_SIZE,
                                                                 respHeader.payloadLen,
                                                                 peerPacket)) {
                                // Tie-breaker: higher connection ID becomes "responder" (sends RESP)
                                if (m_connectionId > peerPacket.connectionId) {
                                    LOG_DEBUG("UdpTransport::initiateHandshake: We have higher ID (" +
                                              std::to_string(m_connectionId) + " > " +
                                              std::to_string(peerPacket.connectionId) +
                                              "), becoming responder");

                                    // Store peer's connection info
                                    m_peerConnectionId = peerPacket.connectionId;
                                    m_nextExpectedSeq = peerPacket.initialSeq;

                                    // Build and send HANDSHAKE_RESP
                                    UdpHandshakePacket respPacket;
                                    respPacket.connectionId = m_connectionId;
                                    respPacket.initialSeq = m_nextSeqNum;
                                    respPacket.timestamp = getCurrentTimestampMs();
                                    respPacket.version = 1;

                                    std::vector<uint8_t> respPayload(UdpHandshakePacket::SIZE);
                                    respPacket.serialize(respPayload.data());

                                    UdpPacketHeader respHdr;
                                    respHdr.type = UdpPacketType::HANDSHAKE_RESP;
                                    respHdr.flags = 0;
                                    respHdr.payloadLen = static_cast<uint16_t>(respPayload.size());
                                    respHdr.seqNum = 0;
                                    respHdr.ackNum = 0;

                                    auto sendResult = sendPacket(respHdr, respPayload.data(), respPayload.size());
                                    if (!sendResult) {
                                        LOG_ERROR("UdpTransport::initiateHandshake: Failed to send RESP: " + sendResult.error());
                                        continue;
                                    }

                                    // Now wait for HANDSHAKE_ACK from peer
                                    m_state = UdpConnectionState::HANDSHAKE_RECEIVED;

                                    // Continue waiting - peer will send ACK after receiving our RESP
                                    // (or they may resend INIT if they didn't get our RESP yet)
                                }
                                else if (m_connectionId < peerPacket.connectionId) {
                                    LOG_DEBUG("UdpTransport::initiateHandshake: Peer has higher ID (" +
                                              std::to_string(peerPacket.connectionId) + " > " +
                                              std::to_string(m_connectionId) +
                                              "), waiting for their RESP");

                                    // Peer will become responder and send us RESP
                                    // Just continue waiting for HANDSHAKE_RESP
                                }
                                else {
                                    // Extremely unlikely: same connection ID
                                    LOG_WARNING("UdpTransport::initiateHandshake: Same connection ID! Regenerating...");
                                    m_connectionId = generateRandomU32();
                                    hsPacket.connectionId = m_connectionId;
                                    hsPacket.serialize(payload.data());
                                }
                            }
                        }
                    }
                    else if (respHeader.type == UdpPacketType::HANDSHAKE_ACK) {
                        // We sent RESP (as responder in simultaneous open), peer is confirming
                        LOG_DEBUG("UdpTransport::initiateHandshake: Received HANDSHAKE_ACK - connection established");
                        m_state = UdpConnectionState::ESTABLISHED;
                        m_lastPacketReceived = std::chrono::steady_clock::now();
                        m_lastHeartbeatSent = std::chrono::steady_clock::now();
                        return VoidResult::Ok();
                    }
                }
            }
        }

        // Fixed interval retries
        LOG_INFO("UdpTransport::initiateHandshake: No response, retry " + std::to_string(retry + 1) +
                 "/" + std::to_string(UDP_HANDSHAKE_RETRIES));
    }

    m_state = UdpConnectionState::CLOSED;
    LOG_ERROR("UdpTransport::initiateHandshake: Handshake timeout after " + std::to_string(UDP_HANDSHAKE_RETRIES) + " retries");
    return VoidResult::Err("Handshake timeout - no response from peer (NAT binding may have expired)");
}

VoidResult UdpTransport::handleHandshakeInit(const UdpHandshakePacket& packet,
                                              const sockaddr_in& from) {
    LOG_DEBUG("UdpTransport::handleHandshakeInit: Processing HANDSHAKE_INIT from peer");

    // Store peer's connection info
    m_peerConnectionId = packet.connectionId;
    m_nextExpectedSeq = packet.initialSeq;

    // Generate our connection parameters
    m_connectionId = generateRandomU32();
    m_nextSeqNum = generateRandomU32() & 0x00FFFFFF;

    // Calculate RTT from timestamp
    uint32_t now = getCurrentTimestampMs();
    int rttMs = static_cast<int>(now - packet.timestamp);
    if (rttMs > 0 && rttMs < 10000) {
        std::lock_guard<std::mutex> lock(m_congestionMutex);
        m_rttEstimator.addSample(rttMs);
    }

    // Build response
    UdpHandshakePacket respPacket;
    respPacket.connectionId = m_connectionId;
    respPacket.initialSeq = m_nextSeqNum;
    respPacket.timestamp = now;
    respPacket.version = 1;

    std::vector<uint8_t> payload(UdpHandshakePacket::SIZE);
    respPacket.serialize(payload.data());

    UdpPacketHeader header;
    header.type = UdpPacketType::HANDSHAKE_RESP;
    header.flags = 0;
    header.payloadLen = static_cast<uint16_t>(payload.size());
    header.seqNum = 0;
    header.ackNum = 0;

    m_state = UdpConnectionState::HANDSHAKE_RECEIVED;

    // Send response
    auto result = sendPacket(header, payload.data(), payload.size());
    if (!result) {
        return result;
    }

    // Wait for HANDSHAKE_ACK
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(UDP_HANDSHAKE_TIMEOUT_MS);

    while (std::chrono::steady_clock::now() < deadline) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(m_socket.handle(), &readSet);

        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) break;

        timeval tv;
        tv.tv_sec = static_cast<long>(remaining / 1000);
        tv.tv_usec = static_cast<long>((remaining % 1000) * 1000);

        int selectResult = select(0, &readSet, nullptr, nullptr, &tv);
        if (selectResult <= 0) continue;

        uint8_t recvBuf[UDP_MAX_PACKET_SIZE];
        sockaddr_in fromAddr{};
        int fromLen = sizeof(fromAddr);

        int recvLen = recvfrom(m_socket.handle(),
                               reinterpret_cast<char*>(recvBuf),
                               sizeof(recvBuf),
                               0,
                               reinterpret_cast<sockaddr*>(&fromAddr),
                               &fromLen);

        if (recvLen <= 0) continue;

        UdpPacketHeader respHeader;
        if (!UdpPacketHeader::deserialize(recvBuf, recvLen, respHeader)) {
            continue;
        }

        if (respHeader.type == UdpPacketType::HANDSHAKE_ACK) {
            LOG_DEBUG("UdpTransport::handleHandshakeInit: Received HANDSHAKE_ACK");

            m_state = UdpConnectionState::ESTABLISHED;
            m_lastPacketReceived = std::chrono::steady_clock::now();
            m_lastHeartbeatSent = std::chrono::steady_clock::now();

            LOG_INFO("UdpTransport::handleHandshakeInit: Connection established");
            return VoidResult::Ok();
        } else if (respHeader.type == UdpPacketType::HANDSHAKE_INIT) {
            // Peer resent INIT, resend our response
            LOG_DEBUG("UdpTransport::handleHandshakeInit: Resending HANDSHAKE_RESP");
            sendPacket(header, payload.data(), payload.size());
        }
    }

    m_state = UdpConnectionState::CLOSED;
    LOG_ERROR("UdpTransport::handleHandshakeInit: Timeout waiting for HANDSHAKE_ACK");
    return VoidResult::Err("Timeout waiting for HANDSHAKE_ACK");
}

VoidResult UdpTransport::completeHandshake(const UdpHandshakePacket& packet) {
    LOG_DEBUG("UdpTransport::completeHandshake: Processing HANDSHAKE_RESP");

    // Store peer's connection info
    m_peerConnectionId = packet.connectionId;
    m_nextExpectedSeq = packet.initialSeq;

    // Calculate RTT
    uint32_t now = getCurrentTimestampMs();
    int rttMs = static_cast<int>(now - packet.timestamp);
    if (rttMs > 0 && rttMs < 10000) {
        std::lock_guard<std::mutex> lock(m_congestionMutex);
        m_rttEstimator.addSample(rttMs);
    }

    // Send HANDSHAKE_ACK
    UdpPacketHeader header;
    header.type = UdpPacketType::HANDSHAKE_ACK;
    header.flags = 0;
    header.payloadLen = 0;
    header.seqNum = 0;
    header.ackNum = 0;

    auto result = sendPacket(header, nullptr, 0);
    if (!result) {
        return result;
    }

    m_state = UdpConnectionState::ESTABLISHED;
    m_lastPacketReceived = std::chrono::steady_clock::now();
    m_lastHeartbeatSent = std::chrono::steady_clock::now();

    LOG_INFO("UdpTransport::completeHandshake: Connection established");
    return VoidResult::Ok();
}

// =============================================================================
// Packet Processing
// =============================================================================

VoidResult UdpTransport::processIncomingPacket() {
    if (!m_socket.isValid()) {
        return VoidResult::Err("Socket not valid");
    }

    // Set up select for receive with timeout
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(m_socket.handle(), &readSet);

    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;  // 100ms timeout for background processing

    int selectResult = select(0, &readSet, nullptr, nullptr, &tv);
    if (selectResult <= 0) {
        return VoidResult::Ok();  // No data, not an error
    }

    // Receive packet
    uint8_t recvBuf[UDP_MAX_PACKET_SIZE];
    sockaddr_in fromAddr{};
    int fromLen = sizeof(fromAddr);

    int recvLen = recvfrom(m_socket.handle(),
                           reinterpret_cast<char*>(recvBuf),
                           sizeof(recvBuf),
                           0,
                           reinterpret_cast<sockaddr*>(&fromAddr),
                           &fromLen);

    if (recvLen <= 0) {
        if (recvLen == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK && err != WSAETIMEDOUT) {
                LOG_ERROR("UdpTransport::processIncomingPacket: recvfrom failed: " + std::to_string(err));
                return VoidResult::Err("recvfrom failed: " + std::to_string(err));
            }
        }
        return VoidResult::Ok();
    }

    // Update stats
    {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        m_stats.packetsReceived++;
        m_stats.bytesReceived += recvLen;
    }

    // Update last received timestamp
    m_lastPacketReceived = std::chrono::steady_clock::now();

    // Parse header
    UdpPacketHeader header;
    if (!UdpPacketHeader::deserialize(recvBuf, recvLen, header)) {
        LOG_DEBUG("UdpTransport::processIncomingPacket: Invalid packet header");
        return VoidResult::Ok();
    }

    LOG_DEBUG("UdpTransport::processIncomingPacket: Received " +
              std::string(UdpPacketTypeName(header.type)) +
              " seq=" + std::to_string(header.seqNum) +
              " ack=" + std::to_string(header.ackNum) +
              " len=" + std::to_string(header.payloadLen));

    // Dispatch based on type
    switch (header.type) {
        case UdpPacketType::DATA:
            handleDataPacket(header, recvBuf + UDP_HEADER_SIZE, header.payloadLen);
            break;

        case UdpPacketType::ACK:
            handleAckPacket(header, recvBuf + UDP_HEADER_SIZE, header.payloadLen);
            break;

        case UdpPacketType::HEARTBEAT:
            handleHeartbeat(header);
            break;

        case UdpPacketType::HEARTBEAT_ACK:
            // Just update last received timestamp (already done above)
            LOG_DEBUG("UdpTransport::processIncomingPacket: Received HEARTBEAT_ACK");
            break;

        case UdpPacketType::CLOSE:
            handleClose();
            break;

        default:
            LOG_DEBUG("UdpTransport::processIncomingPacket: Unknown packet type: " +
                      std::to_string(static_cast<int>(header.type)));
            break;
    }

    return VoidResult::Ok();
}

void UdpTransport::handleDataPacket(const UdpPacketHeader& header,
                                     const uint8_t* payload,
                                     size_t len) {
    if (len < 1) {
        LOG_DEBUG("UdpTransport::handleDataPacket: Empty payload");
        return;
    }

    uint32_t seqNum = header.seqNum;
    MsgType msgType = static_cast<MsgType>(payload[0]);
    std::vector<uint8_t> data(payload + 1, payload + len);

    LOG_DEBUG("UdpTransport::handleDataPacket: seq=" + std::to_string(seqNum) +
              " expected=" + std::to_string(m_nextExpectedSeq) +
              " msgType=" + std::string(MsgTypeName(msgType)));

    if (seqNum == m_nextExpectedSeq) {
        // In-order delivery
        LOG_DEBUG("UdpTransport::handleDataPacket: In-order, delivering to app");

        // Deliver to application
        {
            std::lock_guard<std::mutex> lock(m_receiveMutex);
            ReceivedMessage msg;
            msg.seqNum = seqNum;
            msg.msgType = msgType;
            msg.payload = std::move(data);
            m_receiveQueue.push(std::move(msg));
            m_receiveCondition.notify_one();
        }

        // Advance expected sequence
        m_nextExpectedSeq++;

        // Try to deliver from reorder buffer
        while (deliverFromReorderBuffer()) {}

    } else if (seqNum > m_nextExpectedSeq) {
        // Out of order - add to reorder buffer
        LOG_DEBUG("UdpTransport::handleDataPacket: Out of order, buffering");
        insertIntoReorderBuffer(seqNum, msgType, data);

    } else {
        // Duplicate - ignore but still send ACK
        LOG_DEBUG("UdpTransport::handleDataPacket: Duplicate, ignoring");
    }

    // Always send ACK after receiving data
    sendAck();
}

void UdpTransport::handleAckPacket(const UdpPacketHeader& header,
                                    const uint8_t* payload,
                                    size_t len) {
    UdpAckPacket ackPacket;
    if (!UdpAckPacket::deserialize(payload, len, ackPacket)) {
        LOG_DEBUG("UdpTransport::handleAckPacket: Invalid ACK packet");
        return;
    }

    LOG_DEBUG("UdpTransport::handleAckPacket: cumAck=" + std::to_string(ackPacket.cumAck));

    acknowledgePackets(ackPacket.cumAck, ackPacket);
}

void UdpTransport::handleHeartbeat(const UdpPacketHeader& header) {
    LOG_DEBUG("UdpTransport::handleHeartbeat: Received, sending ACK");

    // Send HEARTBEAT_ACK
    UdpPacketHeader respHeader;
    respHeader.type = UdpPacketType::HEARTBEAT_ACK;
    respHeader.flags = 0;
    respHeader.payloadLen = 0;
    respHeader.seqNum = 0;
    respHeader.ackNum = m_nextExpectedSeq > 0 ? m_nextExpectedSeq - 1 : 0;

    sendPacket(respHeader, nullptr, 0);
}

void UdpTransport::handleClose() {
    LOG_INFO("UdpTransport::handleClose: Received CLOSE from peer");

    m_state = UdpConnectionState::CLOSING;

    // Notify waiting receivers
    {
        std::lock_guard<std::mutex> lock(m_receiveMutex);
        m_receiveCondition.notify_all();
    }
}

// =============================================================================
// Retransmission
// =============================================================================

void UdpTransport::checkRetransmissions() {
    auto now = std::chrono::steady_clock::now();
    std::vector<uint32_t> toRetransmit;

    {
        std::lock_guard<std::mutex> lock(m_retransmitMutex);

        for (auto& [seqNum, entry] : m_retransmitQueue) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - entry.lastSent).count();

            if (elapsed >= entry.rtoMs) {
                if (entry.retryCount >= UDP_MAX_RETRANSMITS) {
                    LOG_ERROR("UdpTransport::checkRetransmissions: Max retransmits exceeded for seq=" +
                              std::to_string(seqNum));
                    // Connection failed - will be cleaned up
                    m_state = UdpConnectionState::CLOSING;
                    return;
                }

                toRetransmit.push_back(seqNum);
            }
        }
    }

    // Retransmit outside the lock
    for (uint32_t seqNum : toRetransmit) {
        std::lock_guard<std::mutex> lock(m_retransmitMutex);
        auto it = m_retransmitQueue.find(seqNum);
        if (it != m_retransmitQueue.end()) {
            retransmitPacket(it->second);
        }
    }
}

VoidResult UdpTransport::retransmitPacket(RetransmitEntry& entry) {
    LOG_DEBUG("UdpTransport::retransmitPacket: Retransmitting seq=" + std::to_string(entry.seqNum) +
              " retry=" + std::to_string(entry.retryCount + 1));

    // Send the packet
    int sent = sendto(m_socket.handle(),
                      reinterpret_cast<const char*>(entry.packet.data()),
                      static_cast<int>(entry.packet.size()),
                      0,
                      reinterpret_cast<const sockaddr*>(&m_peerAddr),
                      sizeof(m_peerAddr));

    if (sent == SOCKET_ERROR) {
        int err = WSAGetLastError();
        LOG_ERROR("UdpTransport::retransmitPacket: sendto failed: " + std::to_string(err));
        return VoidResult::Err("sendto failed: " + std::to_string(err));
    }

    // Update entry
    entry.lastSent = std::chrono::steady_clock::now();
    entry.retryCount++;

    // Exponential backoff for RTO
    entry.rtoMs = std::min(entry.rtoMs * 2, UDP_MAX_RTO_MS);

    // Update stats
    {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        m_stats.packetsRetransmit++;
        m_stats.packetsSent++;
        m_stats.bytesSent += sent;
    }

    // Notify congestion controller of timeout
    {
        std::lock_guard<std::mutex> lock(m_congestionMutex);
        m_congestion.onTimeout();
    }

    return VoidResult::Ok();
}

void UdpTransport::acknowledgePackets(uint32_t cumAck, const UdpAckPacket& sack) {
    auto now = std::chrono::steady_clock::now();
    std::vector<uint32_t> acked;
    int rttSample = -1;

    {
        std::lock_guard<std::mutex> lock(m_retransmitMutex);

        // Remove all packets <= cumAck
        for (auto it = m_retransmitQueue.begin(); it != m_retransmitQueue.end(); ) {
            if (it->first <= cumAck) {
                // Calculate RTT sample from first transmission (not retransmissions)
                if (it->second.retryCount == 0 && rttSample < 0) {
                    rttSample = static_cast<int>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            now - it->second.firstSent).count());
                }

                acked.push_back(it->first);
                it = m_retransmitQueue.erase(it);
            } else {
                ++it;
            }
        }

        // Process SACK bitmap for selective acknowledgments
        for (uint32_t offset = 1; offset <= 32; ++offset) {
            if (sack.getSackBit(offset)) {
                uint32_t seqNum = cumAck + offset;
                auto it = m_retransmitQueue.find(seqNum);
                if (it != m_retransmitQueue.end()) {
                    // Calculate RTT if this is first ACK for this packet
                    if (it->second.retryCount == 0 && rttSample < 0) {
                        rttSample = static_cast<int>(
                            std::chrono::duration_cast<std::chrono::milliseconds>(
                                now - it->second.firstSent).count());
                    }

                    acked.push_back(seqNum);
                    m_retransmitQueue.erase(it);
                }
            }
        }
    }

    // Update RTT estimator and congestion controller
    if (!acked.empty()) {
        std::lock_guard<std::mutex> lock(m_congestionMutex);

        if (rttSample > 0) {
            m_rttEstimator.addSample(rttSample);
        }

        for (size_t i = 0; i < acked.size(); ++i) {
            m_congestion.onAck();
        }
    }

    LOG_DEBUG("UdpTransport::acknowledgePackets: ACKed " + std::to_string(acked.size()) +
              " packets, cumAck=" + std::to_string(cumAck));
}

// =============================================================================
// Receive Reordering
// =============================================================================

void UdpTransport::insertIntoReorderBuffer(uint32_t seqNum,
                                            MsgType msgType,
                                            const std::vector<uint8_t>& payload) {
    std::lock_guard<std::mutex> reorderLock(m_reorderMutex);
    std::lock_guard<std::mutex> sackLock(m_sackMutex);

    // Add to reorder buffer
    ReceivedMessage msg;
    msg.seqNum = seqNum;
    msg.msgType = msgType;
    msg.payload = payload;
    m_reorderBuffer[seqNum] = std::move(msg);

    // Track for SACK
    m_outOfOrderReceived.push_back(seqNum);

    // Limit reorder buffer size
    if (m_reorderBuffer.size() > 64) {
        // Remove oldest entry
        auto oldest = m_reorderBuffer.begin();
        m_reorderBuffer.erase(oldest);
        LOG_DEBUG("UdpTransport::insertIntoReorderBuffer: Buffer overflow, dropped oldest");
    }

    LOG_DEBUG("UdpTransport::insertIntoReorderBuffer: Buffered seq=" + std::to_string(seqNum) +
              ", buffer size=" + std::to_string(m_reorderBuffer.size()));
}

bool UdpTransport::deliverFromReorderBuffer() {
    std::lock_guard<std::mutex> reorderLock(m_reorderMutex);

    auto it = m_reorderBuffer.find(m_nextExpectedSeq);
    if (it == m_reorderBuffer.end()) {
        return false;
    }

    LOG_DEBUG("UdpTransport::deliverFromReorderBuffer: Delivering seq=" +
              std::to_string(m_nextExpectedSeq));

    // Deliver to application
    {
        std::lock_guard<std::mutex> lock(m_receiveMutex);
        m_receiveQueue.push(std::move(it->second));
        m_receiveCondition.notify_one();
    }

    // Remove from reorder buffer and SACK tracking
    m_reorderBuffer.erase(it);

    {
        std::lock_guard<std::mutex> sackLock(m_sackMutex);
        m_outOfOrderReceived.erase(
            std::remove(m_outOfOrderReceived.begin(), m_outOfOrderReceived.end(), m_nextExpectedSeq),
            m_outOfOrderReceived.end());
    }

    // Advance expected sequence
    m_nextExpectedSeq++;

    return true;
}

// =============================================================================
// Background Thread
// =============================================================================

void UdpTransport::backgroundLoop() {
    LOG_DEBUG("UdpTransport::backgroundLoop: Starting");

    while (m_running) {
        // Process incoming packets
        if (m_state == UdpConnectionState::ESTABLISHED) {
            auto result = processIncomingPacket();
            if (!result && m_running) {
                LOG_DEBUG("UdpTransport::backgroundLoop: processIncomingPacket error: " + result.error());
            }
        }

        // Check retransmissions
        if (m_state == UdpConnectionState::ESTABLISHED) {
            checkRetransmissions();
        }

        // Send heartbeat if needed
        auto now = std::chrono::steady_clock::now();
        auto heartbeatElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - m_lastHeartbeatSent).count();

        if (m_state == UdpConnectionState::ESTABLISHED &&
            heartbeatElapsed >= UDP_HEARTBEAT_INTERVAL_MS) {
            sendHeartbeat();
        }

        // Check heartbeat timeout
        auto receivedElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - m_lastPacketReceived).count();

        if (m_state == UdpConnectionState::ESTABLISHED &&
            receivedElapsed >= UDP_HEARTBEAT_TIMEOUT_MS) {
            LOG_ERROR("UdpTransport::backgroundLoop: Heartbeat timeout, closing connection");
            m_state = UdpConnectionState::CLOSING;

            // Notify waiting receivers
            {
                std::lock_guard<std::mutex> lock(m_receiveMutex);
                m_receiveCondition.notify_all();
            }
        }

        // Check if closing
        if (m_state == UdpConnectionState::CLOSING) {
            LOG_INFO("UdpTransport::backgroundLoop: Connection closing");
            m_running = false;
            break;
        }

        // Sleep briefly
        {
            std::unique_lock<std::mutex> lock(m_backgroundMutex);
            m_backgroundCondition.wait_for(lock, std::chrono::milliseconds(100));
        }
    }

    LOG_DEBUG("UdpTransport::backgroundLoop: Exiting");
}

} // namespace p2p
