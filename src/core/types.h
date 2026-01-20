#pragma once
// =============================================================================
// types.h - Core type definitions and constants
// =============================================================================

#include <cstdint>
#include <string>
#include <vector>
#include <functional>

namespace p2p {

// -----------------------------------------------------------------------------
// Protocol Constants
// -----------------------------------------------------------------------------
constexpr uint8_t  PROTOCOL_VERSION     = 2;          // v2: X25519 + ML-KEM-768
constexpr size_t   MAX_FRAME_SIZE       = 4000 * 1024;  // 4MB max message (or 4.096MB in binary)
constexpr size_t   PEER_ID_SIZE         = 32;
constexpr size_t   SESSION_KEY_SIZE     = 32;         // AES-256

// X25519 key sizes
constexpr size_t   X25519_PUBLIC_KEY_SIZE  = 32;
constexpr size_t   X25519_PRIVATE_KEY_SIZE = 32;
constexpr size_t   X25519_SHARED_KEY_SIZE  = 32;

// ML-KEM-768 (NIST-standardized Kyber) key sizes
constexpr size_t   MLKEM768_PUBLIC_KEY_SIZE  = 1184;
constexpr size_t   MLKEM768_SECRET_KEY_SIZE  = 2400;
constexpr size_t   MLKEM768_CIPHERTEXT_SIZE  = 1088;
constexpr size_t   MLKEM768_SHARED_KEY_SIZE  = 32;

// Symmetric crypto
constexpr size_t   GCM_NONCE_SIZE       = 12;
constexpr size_t   GCM_TAG_SIZE         = 16;
constexpr size_t   HMAC_SIZE            = 32;

// -----------------------------------------------------------------------------
// Timing Constants
// -----------------------------------------------------------------------------
constexpr int      CONNECT_TIMEOUT_SEC  = 15;
constexpr int      REKEY_INTERVAL_SEC   = 60;
constexpr int      TIMESTAMP_WINDOW_SEC = 300;        // 5 minute drift allowed
constexpr int      KEEPALIVE_IDLE_MS    = 30000;
constexpr int      KEEPALIVE_INTERVAL   = 5000;

// Rekeying
constexpr uint64_t REKEY_AFTER_MESSAGES = (1ULL << 20);  // Rekey after ~1M messages
constexpr uint64_t REKEY_WARN_THRESHOLD = REKEY_AFTER_MESSAGES - 1000;  // Warn at this point

// Sliding Window Anti-Replay
constexpr size_t   REPLAY_WINDOW_SIZE   = 64;         // Accept up to 64 out-of-order packets
constexpr uint64_t REPLAY_WINDOW_MASK   = UINT64_MAX; // All 64 bits set

// -----------------------------------------------------------------------------
// Message Types
// -----------------------------------------------------------------------------
enum class MsgType : uint8_t {
    // Control messages (0x00-0x0F)
    Hello            = 0x00,  // Version + capabilities
    X25519PublicKey  = 0x01,  // X25519 public key (32 bytes)
    MlkemPublicKey   = 0x02,  // ML-KEM-768 public key (1184 bytes)
    MlkemCiphertext  = 0x03,  // ML-KEM-768 ciphertext (1088 bytes)
    SessionOk        = 0x04,  // Handshake complete ACK
    SessionError     = 0x05,  // Handshake/session error
    PeerHello        = 0x06,  // Peer ID exchange
    Goodbye          = 0x07,  // Graceful disconnect
    KeyConfirm       = 0x08,  // Key confirmation (encrypted challenge-response)
    
    // Data messages (0x10-0x1F)
    Data             = 0x11,  // Encrypted application data
    
    // Rekey messages (0x20-0x2F)
    RekeyRequest     = 0x20,
    RekeyComplete    = 0x21
};

inline const char* MsgTypeName(MsgType t) {
    switch (t) {
        case MsgType::Hello:           return "Hello";
        case MsgType::X25519PublicKey: return "X25519PublicKey";
        case MsgType::MlkemPublicKey:  return "MlkemPublicKey";
        case MsgType::MlkemCiphertext: return "MlkemCiphertext";
        case MsgType::SessionOk:       return "SessionOk";
        case MsgType::SessionError:    return "SessionError";
        case MsgType::PeerHello:       return "PeerHello";
        case MsgType::Goodbye:         return "Goodbye";
        case MsgType::KeyConfirm:      return "KeyConfirm";
        case MsgType::Data:            return "Data";
        case MsgType::RekeyRequest:    return "RekeyRequest";
        case MsgType::RekeyComplete:   return "RekeyComplete";
        default:                       return "Unknown";
    }
}

// -----------------------------------------------------------------------------
// Session Error Codes
// -----------------------------------------------------------------------------
enum class SessionError : uint8_t {
    None            = 0,
    VersionMismatch = 1,
    KeyExchangeFail = 2,
    DecryptionFail  = 3,
    AuthFail        = 4,
    Timeout         = 5,
    ProtocolError   = 6,
    InternalError   = 7
};

inline const char* SessionErrorName(SessionError e) {
    switch (e) {
        case SessionError::None:            return "None";
        case SessionError::VersionMismatch: return "VersionMismatch";
        case SessionError::KeyExchangeFail: return "KeyExchangeFail";
        case SessionError::DecryptionFail:  return "DecryptionFail";
        case SessionError::AuthFail:        return "AuthFail";
        case SessionError::Timeout:         return "Timeout";
        case SessionError::ProtocolError:   return "ProtocolError";
        case SessionError::InternalError:   return "InternalError";
        default:                            return "Unknown";
    }
}

// -----------------------------------------------------------------------------
// Connection Role
// -----------------------------------------------------------------------------
enum class HandshakeRole : uint8_t {
    Initiator = 0,  // Outbound connection (sends SessionKey)
    Responder = 1   // Inbound connection (receives SessionKey)
};

// -----------------------------------------------------------------------------
// Connection State
// -----------------------------------------------------------------------------
enum class ConnectionState {
    Disconnected,
    Connecting,
    Handshaking,
    Ready,
    Disconnecting
};

inline const char* ConnectionStateName(ConnectionState s) {
    switch (s) {
        case ConnectionState::Disconnected:   return "Disconnected";
        case ConnectionState::Connecting:     return "Connecting";
        case ConnectionState::Handshaking:    return "Handshaking";
        case ConnectionState::Ready:          return "Ready";
        case ConnectionState::Disconnecting:  return "Disconnecting";
        default:                              return "Unknown";
    }
}

// -----------------------------------------------------------------------------
// Log Levels
// -----------------------------------------------------------------------------
enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error
};

inline const char* LogLevelPrefix(LogLevel level) {
    switch (level) {
        case LogLevel::Debug:   return "[DBG]";
        case LogLevel::Info:    return "[INF]";
        case LogLevel::Warning: return "[WRN]";
        case LogLevel::Error:   return "[ERR]";
        default:                return "[???]";
    }
}

// -----------------------------------------------------------------------------
// Callback Types
// -----------------------------------------------------------------------------
using LogCallback     = std::function<void(LogLevel, const std::string&)>;
using MessageCallback = std::function<void(const std::string&, uint64_t timestamp)>;
using StateCallback   = std::function<void(ConnectionState)>;
using ErrorCallback   = std::function<void(SessionError, const std::string&)>;

// -----------------------------------------------------------------------------
// Peer Identity
// -----------------------------------------------------------------------------
struct PeerIdentity {
    std::vector<uint8_t> id;           // 32-byte unique ID
    std::string          fingerprint;  // Human-readable hex fingerprint
    
    bool isValid() const { return id.size() == PEER_ID_SIZE; }
    
    std::string shortFingerprint() const {
        if (fingerprint.size() < 16) return fingerprint;
        return fingerprint.substr(0, 8) + "..." + fingerprint.substr(fingerprint.size() - 8);
    }
};

// -----------------------------------------------------------------------------
// Connection Configuration
// -----------------------------------------------------------------------------
struct ConnectionConfig {
    std::string remoteHost;
    uint16_t    listenPort      = 27015;
    uint16_t    remotePort      = 27015;
    bool        listenOnly      = false;
    bool        connectOnly     = false;
    bool        useHmac         = true;
    bool        autoMap         = false;
    
    bool isValid() const {
        if (listenOnly && connectOnly) return false;
        if (!connectOnly && listenPort == 0) return false;
        if (!listenOnly && (remoteHost.empty() || remotePort == 0)) return false;
        return true;
    }
};

} // namespace p2p
