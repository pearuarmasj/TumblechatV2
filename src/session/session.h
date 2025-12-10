#pragma once
// =============================================================================
// session.h - Network session with unified handshake
// =============================================================================

#include <winsock2.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <memory>
#include <utility>

#include "../core/types.h"
#include "../core/result.h"
#include "../core/logger.h"
#include "../network/socket_wrapper.h"
#include "../network/frame_io.h"
#include "../crypto/crypto_engine.h"

namespace p2p {

class Session {
public:
    using MessageHandler = std::function<void(const std::string& msg, uint64_t timestamp)>;
    using StateHandler   = std::function<void(ConnectionState state)>;
    using ErrorHandler   = std::function<void(SessionError err, const std::string& detail)>;
    
    Session() = default;
    ~Session() { stop(); }
    
    // No copy
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    
    // -------------------------------------------------------------------------
    // Callbacks
    // -------------------------------------------------------------------------
    void onMessage(MessageHandler handler) { m_onMessage = std::move(handler); }
    void onStateChange(StateHandler handler) { m_onState = std::move(handler); }
    void onError(ErrorHandler handler) { m_onError = std::move(handler); }
    
    // -------------------------------------------------------------------------
    // State Access
    // -------------------------------------------------------------------------
    ConnectionState state() const { return m_state.load(); }
    bool isReady() const { return m_state.load() == ConnectionState::Ready; }
    bool isConnected() const { 
        auto s = m_state.load();
        return s == ConnectionState::Handshaking || s == ConnectionState::Ready; 
    }
    
    const PeerIdentity& localIdentity() const { return m_localIdentity; }
    const PeerIdentity& remoteIdentity() const { return m_remoteIdentity; }
    std::string peerFingerprint() const { 
        return (m_peerKeys.x25519Valid && m_peerKeys.mlkemValid) ? m_peerKeys.fingerprint() : ""; 
    }
    
    // -------------------------------------------------------------------------
    // Initialize Session (call once before start)
    // -------------------------------------------------------------------------
    VoidResult initialize(bool useHmac = true) {
        m_sessionKeys.useHmac = useHmac;
        
        auto result = m_crypto.loadOrCreatePeerId(m_localIdentity);
        if (!result) return result;
        
        result = m_crypto.generateKeyPair(m_myKeys);
        if (!result) return result;
        
        return VoidResult::Ok();
    }
    
    // -------------------------------------------------------------------------
    // Start Session with Existing Socket
    // -------------------------------------------------------------------------
    VoidResult start(Socket socket, HandshakeRole role) {
        if (m_running.load()) {
            return VoidResult::Err("Session already running");
        }
        
        m_socket = std::move(socket);
        m_role = role;
        m_running.store(true);
        
        setState(ConnectionState::Handshaking);
        
        // Configure socket
        m_socket.setNoDelay();
        m_socket.setKeepalive(KEEPALIVE_IDLE_MS, KEEPALIVE_INTERVAL);
        
        LOG_INFO(std::string("Session starting as ") + 
                 (role == HandshakeRole::Initiator ? "initiator" : "responder") +
                 " - " + m_socket.connectionTuple());
        
        // Perform handshake synchronously before starting recv thread
        auto handshakeResult = performHandshake();
        if (!handshakeResult) {
            setState(ConnectionState::Disconnected);
            m_running.store(false);
            return VoidResult::Err(handshakeResult.error());
        }
        
        // Start receive thread
        m_recvThread = std::thread([this] { recvLoop(); });
        
        // Start rekey timer thread
        m_rekeyTimerThread = std::thread([this] { rekeyTimerLoop(); });
        
        return VoidResult::Ok();
    }
    
    // -------------------------------------------------------------------------
    // Stop Session
    // -------------------------------------------------------------------------
    void stop() {
        if (!m_running.exchange(false)) return;
        
        setState(ConnectionState::Disconnecting);
        
        // Try graceful goodbye
        if (m_frameIo) {
            m_frameIo->writeFrame(MsgType::Goodbye);
        }
        
        m_socket.close();
        
        // Wait for recv thread (avoid self-join)
        if (m_recvThread.joinable() && 
            m_recvThread.get_id() != std::this_thread::get_id()) {
            m_recvThread.join();
        }
        
        // Wait for rekey timer thread
        if (m_rekeyTimerThread.joinable() && 
            m_rekeyTimerThread.get_id() != std::this_thread::get_id()) {
            m_rekeyTimerThread.join();
        }
        
        setState(ConnectionState::Disconnected);
        LOG_INFO("Session stopped");
    }
    
    // -------------------------------------------------------------------------
    // Send Message
    // -------------------------------------------------------------------------
    VoidResult send(const std::string& message) {
        if (!isReady()) {
            return VoidResult::Err("Session not ready");
        }
        
        // Note: Rekey is handled by background timer thread (rekeyTimerLoop)
        // The timer triggers every 60 seconds automatically
        
        auto encrypted = m_crypto.encryptMessage(m_sessionKeys, message);
        if (!encrypted) {
            return VoidResult::Err(encrypted.error());
        }
        
        return m_frameIo->writeFrame(MsgType::Data, encrypted.value());
    }

private:
    // -------------------------------------------------------------------------
    // State Management
    // -------------------------------------------------------------------------
    void setState(ConnectionState newState) {
        auto oldState = m_state.exchange(newState);
        if (oldState != newState && m_onState) {
            m_onState(newState);
        }
    }
    
    void notifyError(SessionError err, const std::string& detail) {
        LOG_ERROR(std::string(SessionErrorName(err)) + ": " + detail);
        if (m_onError) {
            m_onError(err, detail);
        }
    }
    
    // -------------------------------------------------------------------------
    // Automatic Rekeying
    // -------------------------------------------------------------------------
    // Rekey Timer Loop - ONLY Initiator triggers rekey, Responder just responds
    // -------------------------------------------------------------------------
    void rekeyTimerLoop() {
        LOG_DEBUG("Rekey timer started (interval: " + std::to_string(REKEY_INTERVAL_SEC) + "s)");
        
        while (m_running.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            if (!m_running.load() || !isReady()) continue;
            
            // Only Initiator triggers rekey - Responder waits for RekeyRequest
            if (m_role != HandshakeRole::Initiator) continue;
            
            if (m_sessionKeys.shouldRekey() && m_sessionKeys.rekeyState == RekeyState::None) {
                LOG_INFO("Initiator triggering rekey (60 second interval)");
                auto rekeyResult = initiateRekey();
                if (!rekeyResult) {
                    LOG_ERROR("Auto-rekey failed: " + rekeyResult.error());
                }
            }
        }
        
        LOG_DEBUG("Rekey timer stopped");
    }
    
    // -------------------------------------------------------------------------
    VoidResult initiateRekey() {
        std::lock_guard<std::mutex> lock(m_rekeyMutex);
        
        if (m_sessionKeys.rekeyState != RekeyState::None) {
            return VoidResult::Ok();  // Already in progress
        }
        
        m_sessionKeys.rekeyState = RekeyState::Requested;
        LOG_INFO("Generating new key pair for rekey...");
        
        // Generate fresh key material
        auto genResult = m_crypto.generateKeyPair(m_rekeyKeys);
        if (!genResult) {
            m_sessionKeys.rekeyState = RekeyState::None;
            return VoidResult::Err("Failed to generate rekey keys: " + genResult.error());
        }
        
        // Send RekeyRequest with our new public keys
        std::vector<uint8_t> payload;
        auto x25519Pub = m_rekeyKeys.serializeX25519Public();
        auto mlkemPub = m_rekeyKeys.serializeMlkemPublic();
        payload.reserve(x25519Pub.size() + mlkemPub.size());
        payload.insert(payload.end(), x25519Pub.begin(), x25519Pub.end());
        payload.insert(payload.end(), mlkemPub.begin(), mlkemPub.end());
        
        auto sendResult = m_frameIo->writeFrame(MsgType::RekeyRequest, payload);
        if (!sendResult) {
            m_sessionKeys.rekeyState = RekeyState::None;
            return VoidResult::Err("Failed to send RekeyRequest: " + sendResult.error());
        }
        
        LOG_DEBUG("Sent RekeyRequest, awaiting peer's new keys...");
        return VoidResult::Ok();
    }
    
    VoidResult handleRekeyRequest(const std::vector<uint8_t>& payload) {
        std::lock_guard<std::mutex> lock(m_rekeyMutex);
        
        // Only Responder should receive RekeyRequest (Initiator sends it)
        if (m_role == HandshakeRole::Initiator) {
            LOG_WARNING("Initiator received RekeyRequest - ignoring (we send, they respond)");
            return VoidResult::Ok();
        }
        
        // Validate payload size
        if (payload.size() != X25519_PUBLIC_KEY_SIZE + MLKEM768_PUBLIC_KEY_SIZE) {
            return VoidResult::Err("Invalid RekeyRequest payload size");
        }
        
        LOG_INFO("Responder received RekeyRequest - generating new keys");
        
        // Load peer's (Initiator's) new public keys
        PeerKeyMaterial peerRekeyKeys;
        auto loadResult = m_crypto.loadX25519PublicKey(payload.data(), X25519_PUBLIC_KEY_SIZE, peerRekeyKeys);
        if (!loadResult) return loadResult;
        
        loadResult = m_crypto.loadMlkemPublicKey(payload.data() + X25519_PUBLIC_KEY_SIZE, 
                                                  MLKEM768_PUBLIC_KEY_SIZE, peerRekeyKeys);
        if (!loadResult) return loadResult;
        
        // Generate our new key material
        auto genResult = m_crypto.generateKeyPair(m_rekeyKeys);
        if (!genResult) {
            return VoidResult::Err("Failed to generate rekey keys: " + genResult.error());
        }
        
        m_sessionKeys.rekeyState = RekeyState::InProgress;
        
        // Responder sends keys back, waits for ciphertext from Initiator
        std::vector<uint8_t> response;
        auto x25519Pub = m_rekeyKeys.serializeX25519Public();
        auto mlkemPub = m_rekeyKeys.serializeMlkemPublic();
        response.reserve(x25519Pub.size() + mlkemPub.size());
        response.insert(response.end(), x25519Pub.begin(), x25519Pub.end());
        response.insert(response.end(), mlkemPub.begin(), mlkemPub.end());
        
        auto sendResult = m_frameIo->writeFrame(MsgType::RekeyComplete, response);
        if (!sendResult) {
            m_sessionKeys.rekeyState = RekeyState::None;
            return VoidResult::Err("Failed to send RekeyComplete: " + sendResult.error());
        }
        
        // Store peer's keys for when we receive ciphertext
        m_peerRekeyKeys = std::move(peerRekeyKeys);
        LOG_DEBUG("Responder sent RekeyComplete, waiting for ciphertext from Initiator...");
        
        return VoidResult::Ok();
    }
    
    // Initiator receives RekeyComplete from Responder, then sends ciphertext
    VoidResult handleRekeyComplete(const std::vector<uint8_t>& payload) {
        std::lock_guard<std::mutex> lock(m_rekeyMutex);
        
        // Only Initiator should receive RekeyComplete
        if (m_role != HandshakeRole::Initiator) {
            LOG_WARNING("Responder received RekeyComplete - ignoring");
            return VoidResult::Ok();
        }
        
        if (m_sessionKeys.rekeyState != RekeyState::Requested) {
            LOG_WARNING("Received RekeyComplete but not in Requested state - ignoring");
            return VoidResult::Ok();
        }
        
        // Payload is Responder's new keys
        if (payload.size() != X25519_PUBLIC_KEY_SIZE + MLKEM768_PUBLIC_KEY_SIZE) {
            return VoidResult::Err("Invalid RekeyComplete payload size");
        }
        
        LOG_INFO("Initiator received Responder's new keys - encapsulating");
        
        PeerKeyMaterial peerRekeyKeys;
        auto loadResult = m_crypto.loadX25519PublicKey(payload.data(), X25519_PUBLIC_KEY_SIZE, peerRekeyKeys);
        if (!loadResult) return loadResult;
        
        loadResult = m_crypto.loadMlkemPublicKey(payload.data() + X25519_PUBLIC_KEY_SIZE, 
                                                  MLKEM768_PUBLIC_KEY_SIZE, peerRekeyKeys);
        if (!loadResult) return loadResult;
        
        // Encapsulate to Responder's new keys
        auto encapResult = m_crypto.encapsulateSessionKey(m_rekeyKeys, peerRekeyKeys);
        if (!encapResult) {
            return VoidResult::Err("Rekey encapsulation failed: " + encapResult.error());
        }
        
        // Send ciphertext to Responder
        auto sendResult = m_frameIo->writeFrame(MsgType::MlkemCiphertext, encapResult.value().mlkemCiphertext);
        if (!sendResult) {
            return VoidResult::Err("Failed to send rekey ciphertext: " + sendResult.error());
        }
        
        // Update keys - Initiator is done
        m_myKeys = std::move(m_rekeyKeys);
        m_peerKeys = std::move(peerRekeyKeys);
        m_sessionKeys.key = std::move(encapResult.value().sessionKey);
        m_sessionKeys.sendCounter.store(0);
        m_sessionKeys.recvCounterMax = 0;
        m_sessionKeys.replayWindow = 0;
        m_sessionKeys.rekeyState = RekeyState::None;
        m_sessionKeys.resetRekeyTimer();
        
        LOG_INFO("Rekey complete (Initiator)");
        return VoidResult::Ok();
    }
    
    // -------------------------------------------------------------------------
    // Unified Handshake (X25519 + ML-KEM-768 Hybrid)
    // -------------------------------------------------------------------------
    VoidResult performHandshake() {
        m_frameIo = std::make_unique<FrameIO>(m_socket.handle());
        
        LOG_INFO("Starting handshake (X25519 + ML-KEM-768 hybrid)...");
        
        // Step 1: Exchange X25519 public keys
        auto x25519PubSer = m_myKeys.serializeX25519Public();
        LOG_DEBUG("Sending X25519 public key (" + std::to_string(x25519PubSer.size()) + " bytes)");
        
        auto sendResult = m_frameIo->writeFrame(MsgType::X25519PublicKey, x25519PubSer);
        if (!sendResult) {
            return VoidResult::Err("Failed to send X25519 key: " + sendResult.error());
        }
        
        auto recvResult = m_frameIo->readFrame();
        if (!recvResult) {
            return VoidResult::Err("Failed to receive X25519 key: " + recvResult.error());
        }
        
        auto& [type, payload] = recvResult.value();
        if (type != MsgType::X25519PublicKey) {
            return VoidResult::Err("Expected X25519PublicKey, got " + std::string(MsgTypeName(type)));
        }
        
        auto loadResult = m_crypto.loadX25519PublicKey(payload.data(), payload.size(), m_peerKeys);
        if (!loadResult) {
            return VoidResult::Err(loadResult.error());
        }
        
        // Step 2: Exchange ML-KEM-768 public keys
        auto mlkemPubSer = m_myKeys.serializeMlkemPublic();
        LOG_DEBUG("Sending ML-KEM-768 public key (" + std::to_string(mlkemPubSer.size()) + " bytes)");
        
        sendResult = m_frameIo->writeFrame(MsgType::MlkemPublicKey, mlkemPubSer);
        if (!sendResult) {
            return VoidResult::Err("Failed to send ML-KEM key: " + sendResult.error());
        }
        
        recvResult = m_frameIo->readFrame();
        if (!recvResult) {
            return VoidResult::Err("Failed to receive ML-KEM key: " + recvResult.error());
        }
        
        std::tie(type, payload) = recvResult.value();
        if (type != MsgType::MlkemPublicKey) {
            return VoidResult::Err("Expected MlkemPublicKey, got " + std::string(MsgTypeName(type)));
        }
        
        loadResult = m_crypto.loadMlkemPublicKey(payload.data(), payload.size(), m_peerKeys);
        if (!loadResult) {
            return VoidResult::Err(loadResult.error());
        }
        
        LOG_INFO("Peer fingerprint: " + m_peerKeys.fingerprint().substr(0, 16) + "...");
        
        // Step 3: Exchange peer IDs
        std::vector<uint8_t> helloPayload;
        helloPayload.reserve(PEER_ID_SIZE + 1);
        helloPayload.insert(helloPayload.end(), m_localIdentity.id.begin(), m_localIdentity.id.end());
        helloPayload.push_back(static_cast<uint8_t>(m_role));
        
        sendResult = m_frameIo->writeFrame(MsgType::PeerHello, helloPayload);
        if (!sendResult) {
            return VoidResult::Err("Failed to send PeerHello: " + sendResult.error());
        }
        
        recvResult = m_frameIo->readFrame();
        if (!recvResult) {
            return VoidResult::Err("Failed to receive PeerHello: " + recvResult.error());
        }
        
        std::tie(type, payload) = recvResult.value();
        if (type != MsgType::PeerHello) {
            return VoidResult::Err("Expected PeerHello, got " + std::string(MsgTypeName(type)));
        }
        
        if (payload.size() != PEER_ID_SIZE + 1) {
            return VoidResult::Err("Invalid PeerHello payload size");
        }
        
        m_remoteIdentity.id.assign(payload.begin(), payload.begin() + PEER_ID_SIZE);
        m_remoteIdentity.fingerprint = toHex(m_remoteIdentity.id.data(), 
                                              m_remoteIdentity.id.size(), 
                                              m_remoteIdentity.id.size());
        
        LOG_INFO("Connected to peer: " + m_remoteIdentity.shortFingerprint());
        
        // Role negotiation: If both sides claim Initiator (simultaneous open),
        // use peer ID comparison as tie-breaker. Lower peer ID becomes Responder.
        auto peerRole = static_cast<HandshakeRole>(payload[PEER_ID_SIZE]);
        LOG_INFO("Role check - Our role: " + std::string(m_role == HandshakeRole::Initiator ? "Initiator" : "Responder") +
                  ", Peer role: " + std::string(peerRole == HandshakeRole::Initiator ? "Initiator" : "Responder"));
        
        if (m_role == HandshakeRole::Initiator && peerRole == HandshakeRole::Initiator) {
            // Both think they're initiator - need tie-breaker
            bool weAreLower = m_localIdentity.id < m_remoteIdentity.id;
            LOG_INFO("Role conflict detected. Our ID: " + m_localIdentity.shortFingerprint() + 
                     ", Peer ID: " + m_remoteIdentity.shortFingerprint() + 
                     ", We are " + (weAreLower ? "lower" : "higher"));
            if (weAreLower) {
                LOG_INFO("Role conflict: we have lower peer ID, becoming Responder");
                m_role = HandshakeRole::Responder;
            } else {
                LOG_INFO("Role conflict: we have higher peer ID, staying Initiator");
            }
        }
        
        // Step 4: Key encapsulation (role-dependent)
        if (m_role == HandshakeRole::Initiator) {
            // Initiator: encapsulate to peer's public keys
            auto encapResult = m_crypto.encapsulateSessionKey(m_myKeys, m_peerKeys);
            if (!encapResult) {
                return VoidResult::Err(encapResult.error());
            }
            
            auto& encapData = encapResult.value();
            m_sessionKeys.key = std::move(encapData.sessionKey);
            
            // Send ML-KEM ciphertext
            sendResult = m_frameIo->writeFrame(MsgType::MlkemCiphertext, encapData.mlkemCiphertext);
            if (!sendResult) {
                return VoidResult::Err("Failed to send MlkemCiphertext: " + sendResult.error());
            }
            
            LOG_DEBUG("Sent ML-KEM ciphertext, waiting for SessionOk...");
            
            // Wait for SessionOk
            recvResult = m_frameIo->readFrame();
            if (!recvResult) {
                return VoidResult::Err("Failed to receive SessionOk: " + recvResult.error());
            }
            
            std::tie(type, payload) = recvResult.value();
            if (type != MsgType::SessionOk) {
                return VoidResult::Err("Expected SessionOk, got " + std::string(MsgTypeName(type)));
            }
        }
        else {
            // Responder: receive ciphertext and decapsulate
            recvResult = m_frameIo->readFrame();
            if (!recvResult) {
                return VoidResult::Err("Failed to receive MlkemCiphertext: " + recvResult.error());
            }
            
            std::tie(type, payload) = recvResult.value();
            if (type != MsgType::MlkemCiphertext) {
                return VoidResult::Err("Expected MlkemCiphertext, got " + std::string(MsgTypeName(type)));
            }
            
            auto decapResult = m_crypto.decapsulateSessionKey(
                m_myKeys, m_peerKeys, payload.data(), payload.size());
            
            if (!decapResult) {
                return VoidResult::Err(decapResult.error());
            }
            
            m_sessionKeys.key = std::move(decapResult.value());
            
            // Send SessionOk
            sendResult = m_frameIo->writeFrame(MsgType::SessionOk);
            if (!sendResult) {
                return VoidResult::Err("Failed to send SessionOk: " + sendResult.error());
            }
        }
        
        // Step 5: Key confirmation (both sides prove they derived same key)
        LOG_DEBUG("Starting key confirmation exchange...");
        
        // Generate our confirmation token
        auto confirmResult = m_crypto.generateKeyConfirmToken(m_sessionKeys.key, m_role);
        if (!confirmResult) {
            return VoidResult::Err("Failed to generate key confirm: " + confirmResult.error());
        }
        
        // Send our confirmation
        sendResult = m_frameIo->writeFrame(MsgType::KeyConfirm, confirmResult.value());
        if (!sendResult) {
            return VoidResult::Err("Failed to send KeyConfirm: " + sendResult.error());
        }
        
        // Receive peer's confirmation
        recvResult = m_frameIo->readFrame();
        if (!recvResult) {
            return VoidResult::Err("Failed to receive KeyConfirm: " + recvResult.error());
        }
        
        std::tie(type, payload) = recvResult.value();
        if (type != MsgType::KeyConfirm) {
            return VoidResult::Err("Expected KeyConfirm, got " + std::string(MsgTypeName(type)));
        }
        
        // Verify peer's confirmation (peer role is opposite of ours)
        HandshakeRole confirmPeerRole = (m_role == HandshakeRole::Initiator) 
                                        ? HandshakeRole::Responder 
                                        : HandshakeRole::Initiator;
        auto verifyResult = m_crypto.verifyKeyConfirmToken(m_sessionKeys.key, confirmPeerRole, payload);
        if (!verifyResult) {
            return VoidResult::Err("Key confirmation failed: " + verifyResult.error());
        }
        
        LOG_INFO("Key confirmation successful");
        
        // Initialize rekey timer
        m_sessionKeys.resetRekeyTimer();
        
        setState(ConnectionState::Ready);
        LOG_INFO("Handshake complete - session ready (Hybrid X25519 + ML-KEM-768)");
        
        return VoidResult::Ok();
    }
    
    // -------------------------------------------------------------------------
    // Receive Loop
    // -------------------------------------------------------------------------
    void recvLoop() {
        LOG_DEBUG("Receive loop started");
        
        while (m_running.load()) {
            auto result = m_frameIo->readFrame();
            
            if (!result) {
                if (m_running.load()) {
                    LOG_WARNING("Read failed: " + result.error());
                    notifyError(SessionError::ProtocolError, result.error());
                }
                break;
            }
            
            auto& [type, payload] = result.value();
            
            switch (type) {
            case MsgType::Data:
                handleDataMessage(payload);
                break;
                
            case MsgType::RekeyRequest:
                {
                    auto rekeyResult = handleRekeyRequest(payload);
                    if (!rekeyResult) {
                        notifyError(SessionError::KeyExchangeFail, rekeyResult.error());
                    }
                }
                break;
                
            case MsgType::RekeyComplete:
                {
                    auto rekeyResult = handleRekeyComplete(payload);
                    if (!rekeyResult) {
                        notifyError(SessionError::KeyExchangeFail, rekeyResult.error());
                    }
                }
                break;
                
            case MsgType::MlkemCiphertext:
                // During rekey, responder receives ciphertext separately
                if (m_sessionKeys.rekeyState == RekeyState::InProgress && m_role == HandshakeRole::Responder) {
                    auto decapResult = m_crypto.decapsulateSessionKey(
                        m_rekeyKeys, m_peerRekeyKeys, payload.data(), payload.size());
                    if (!decapResult) {
                        notifyError(SessionError::KeyExchangeFail, decapResult.error());
                    } else {
                        std::lock_guard<std::mutex> lock(m_rekeyMutex);
                        m_myKeys = std::move(m_rekeyKeys);
                        m_peerKeys = std::move(m_peerRekeyKeys);
                        m_sessionKeys.key = std::move(decapResult.value());
                        m_sessionKeys.sendCounter.store(0);
                        m_sessionKeys.recvCounterMax = 0;
                        m_sessionKeys.replayWindow = 0;
                        m_sessionKeys.rekeyState = RekeyState::None;
                        m_sessionKeys.resetRekeyTimer();
                        LOG_INFO("Rekey complete (responder decapsulated ciphertext)");
                    }
                } else {
                    LOG_WARNING("Unexpected MlkemCiphertext message");
                }
                break;
                
            case MsgType::Goodbye:
                LOG_INFO("Received graceful disconnect from peer");
                m_running.store(false);
                break;
                
            default:
                LOG_WARNING("Unexpected message type: " + std::string(MsgTypeName(type)));
                break;
            }
        }
        
        LOG_DEBUG("Receive loop ended");
        setState(ConnectionState::Disconnected);
    }
    
    // -------------------------------------------------------------------------
    // Handle Data Message
    // -------------------------------------------------------------------------
    void handleDataMessage(const std::vector<uint8_t>& payload) {
        auto result = m_crypto.decryptMessage(m_sessionKeys, payload);
        
        if (!result) {
            notifyError(SessionError::DecryptionFail, result.error());
            return;
        }
        
        auto& msg = result.value();
        
        if (m_onMessage) {
            m_onMessage(msg.message, msg.timestamp);
        }
    }
    
    // -------------------------------------------------------------------------
    // Members
    // -------------------------------------------------------------------------
    std::atomic<bool>           m_running{false};
    std::atomic<ConnectionState> m_state{ConnectionState::Disconnected};
    HandshakeRole               m_role = HandshakeRole::Initiator;
    
    Socket                      m_socket;
    std::unique_ptr<FrameIO>    m_frameIo;
    std::thread                 m_recvThread;
    std::thread                 m_rekeyTimerThread;
    
    CryptoEngine                m_crypto;
    KeyMaterial                 m_myKeys;
    PeerKeyMaterial             m_peerKeys;
    SessionKeys                 m_sessionKeys;
    
    // Rekeying state
    std::mutex                  m_rekeyMutex;
    KeyMaterial                 m_rekeyKeys;
    PeerKeyMaterial             m_peerRekeyKeys;
    
    PeerIdentity                m_localIdentity;
    PeerIdentity                m_remoteIdentity;
    
    MessageHandler              m_onMessage;
    StateHandler                m_onState;
    ErrorHandler                m_onError;
};

} // namespace p2p
