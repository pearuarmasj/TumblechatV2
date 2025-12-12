#pragma once
// =============================================================================
// crypto_engine.h - Cryptographic operations (X25519 + ML-KEM-768 + AES-GCM)
// =============================================================================
//
// Hybrid post-quantum key exchange:
//   - X25519 (classical ECDH, 128-bit security)
//   - ML-KEM-768 (NIST-standardized Kyber, 192-bit post-quantum security)
//   - Combined via HKDF-SHA256
//
// Symmetric encryption:
//   - AES-256-GCM with 12-byte nonce and 16-byte tag
//
// =============================================================================

// Prevent Windows min/max macros from interfering with std::min/std::max
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <vector>
#include <string>
#include <cstring>
#include <chrono>
#include <fstream>
#include <algorithm>
#include <map>

// Crypto++ headers
#include <osrng.h>
#include <secblock.h>
#include <gcm.h>
#include <aes.h>
#include <filters.h>
#include <sha.h>
#include <hmac.h>
#include <hkdf.h>
#include <hex.h>
#include <xed25519.h>

// liboqs for ML-KEM (post-quantum)
#include <oqs/oqs.h>

#include "../core/types.h"
#include "../core/result.h"
#include "../core/logger.h"

#pragma comment(lib, "cryptlib.lib")
#pragma comment(lib, "oqs.lib")

namespace p2p {

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------
inline std::string toHex(const uint8_t* data, size_t len, size_t maxLen = 64) {
    std::string result;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result));
    encoder.Put(data, (std::min)(len, maxLen));
    encoder.MessageEnd();
    
    if (len > maxLen) {
        result += "...";
    }
    return result;
}

inline std::string toHex(const CryptoPP::SecByteBlock& data, size_t maxLen = 64) {
    return toHex(data.data(), data.size(), maxLen);
}

inline std::string sha256Fingerprint(const uint8_t* data, size_t len) {
    CryptoPP::SHA256 sha;
    uint8_t digest[CryptoPP::SHA256::DIGESTSIZE];
    sha.CalculateDigest(digest, data, len);
    return toHex(digest, sizeof(digest), sizeof(digest));
}

// -----------------------------------------------------------------------------
// Key Material (X25519 + ML-KEM-768)
// -----------------------------------------------------------------------------
struct KeyMaterial {
    // X25519 (32 bytes each)
    CryptoPP::SecByteBlock x25519Private;
    CryptoPP::SecByteBlock x25519Public;
    
    // ML-KEM-768 (post-quantum)
    std::vector<uint8_t>      mlkemPublic;   // 1184 bytes
    CryptoPP::SecByteBlock    mlkemSecret;   // 2400 bytes (secure memory)
    
    std::string fingerprint() const {
        // Fingerprint is hash of both public keys
        std::vector<uint8_t> combined;
        combined.insert(combined.end(), x25519Public.begin(), x25519Public.end());
        combined.insert(combined.end(), mlkemPublic.begin(), mlkemPublic.end());
        return sha256Fingerprint(combined.data(), combined.size());
    }
    
    std::vector<uint8_t> serializeX25519Public() const {
        return {x25519Public.begin(), x25519Public.end()};
    }
    
    std::vector<uint8_t> serializeMlkemPublic() const {
        return mlkemPublic;
    }
};

// -----------------------------------------------------------------------------
// Peer Key Material (received from remote)
// -----------------------------------------------------------------------------
struct PeerKeyMaterial {
    CryptoPP::SecByteBlock x25519Public;
    std::vector<uint8_t>   mlkemPublic;
    bool                   x25519Valid = false;
    bool                   mlkemValid  = false;
    
    std::string fingerprint() const {
        if (!x25519Valid || !mlkemValid) return "";
        std::vector<uint8_t> combined;
        combined.insert(combined.end(), x25519Public.begin(), x25519Public.end());
        combined.insert(combined.end(), mlkemPublic.begin(), mlkemPublic.end());
        return sha256Fingerprint(combined.data(), combined.size());
    }
};

// -----------------------------------------------------------------------------
// Rekey State
// -----------------------------------------------------------------------------
enum class RekeyState : uint8_t {
    None      = 0,  // Normal operation
    Requested = 1,  // We sent RekeyRequest, awaiting peer's new keys
    Pending   = 2,  // We received RekeyRequest, preparing new keys
    InProgress= 3   // Key exchange in progress
};

// -----------------------------------------------------------------------------
// Session Keys (for message encryption)
// -----------------------------------------------------------------------------
struct SessionKeys {
    CryptoPP::SecByteBlock    key;            // AES-256 key (32 bytes)
    std::atomic<uint64_t>     sendCounter{0};
    
    // Sliding window anti-replay
    uint64_t                  recvCounterMax = 0;  // Highest counter seen
    uint64_t                  replayWindow   = 0;  // Bitmap for last REPLAY_WINDOW_SIZE counters
    
    // Rekeying
    RekeyState                rekeyState = RekeyState::None;
    std::chrono::steady_clock::time_point lastRekeyTime;  // Time of last rekey
    
    bool                      useHmac     = true;
    
    bool isValid() const { return key.size() == SESSION_KEY_SIZE; }
    
    // Initialize rekey timer (call after handshake)
    void resetRekeyTimer() {
        lastRekeyTime = std::chrono::steady_clock::now();
    }
    
    // Check and update anti-replay window. Returns true if packet is valid.
    bool checkReplay(uint64_t counter) {
        if (counter == 0) {
            return false;  // Counter 0 is never valid
        }
        
        if (counter > recvCounterMax) {
            // New highest counter - update window
            uint64_t shift = counter - recvCounterMax;
            if (shift >= REPLAY_WINDOW_SIZE) {
                // New counter is way ahead - reset window
                replayWindow = 1;  // Mark current counter as seen
            } else {
                // Shift window and mark new counter
                replayWindow = (replayWindow << shift) | 1;
            }
            recvCounterMax = counter;
            return true;
        }
        
        // Counter is within or below window
        uint64_t delta = recvCounterMax - counter;
        if (delta >= REPLAY_WINDOW_SIZE) {
            // Too old - outside window
            return false;
        }
        
        // Check if already seen
        uint64_t bit = 1ULL << delta;
        if (replayWindow & bit) {
            return false;  // Replay detected
        }
        
        // Mark as seen
        replayWindow |= bit;
        return true;
    }
    
    // Check if we should initiate rekeying (time-based: every 60 seconds)
    bool shouldRekey() const {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastRekeyTime).count();
        return elapsed >= REKEY_INTERVAL_SEC;
    }
    
    // Check if we should warn about upcoming rekey (5 seconds before)
    bool shouldWarnRekey() const {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastRekeyTime).count();
        return elapsed >= (REKEY_INTERVAL_SEC - 5) && elapsed < REKEY_INTERVAL_SEC;
    }
    
    // Get seconds until next rekey
    int64_t secondsUntilRekey() const {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastRekeyTime).count();
        return REKEY_INTERVAL_SEC - elapsed;
    }
};

// -----------------------------------------------------------------------------
// Encapsulation Result (sent to peer for key derivation)
// -----------------------------------------------------------------------------
struct EncapsulationResult {
    std::vector<uint8_t> mlkemCiphertext;  // 1088 bytes for ML-KEM-768
    CryptoPP::SecByteBlock sessionKey;     // Derived 32-byte key
};

// -----------------------------------------------------------------------------
// Crypto Engine
// -----------------------------------------------------------------------------
class CryptoEngine {
public:
    CryptoEngine() {
        // Initialize liboqs
        OQS_init();
    }
    
    ~CryptoEngine() {
        // Cleanup liboqs
        OQS_destroy();
    }
    
    // -------------------------------------------------------------------------
    // Key Generation
    // -------------------------------------------------------------------------
    VoidResult generateKeyPair(KeyMaterial& keys) {
        try {
            LOG_INFO("Generating X25519 key pair...");
            
            // X25519 via Crypto++
            CryptoPP::x25519 x25519(m_rng);
            keys.x25519Private.CleanNew(CryptoPP::x25519::SECRET_KEYLENGTH);
            keys.x25519Public.CleanNew(CryptoPP::x25519::PUBLIC_KEYLENGTH);
            
            // Use GenerateKeyPair to get raw keys
            x25519.GenerateKeyPair(m_rng, keys.x25519Private, keys.x25519Public);
            
            LOG_INFO("Generating ML-KEM-768 key pair...");
            
            // ML-KEM-768 via liboqs
            keys.mlkemPublic.resize(OQS_KEM_ml_kem_768_length_public_key);
            keys.mlkemSecret.CleanNew(OQS_KEM_ml_kem_768_length_secret_key);
            
            OQS_STATUS status = OQS_KEM_ml_kem_768_keypair(
                keys.mlkemPublic.data(),
                keys.mlkemSecret.data()
            );
            
            if (status != OQS_SUCCESS) {
                return VoidResult::Err("ML-KEM-768 key generation failed");
            }
            
            LOG_INFO("Key generation complete. Fingerprint: " + 
                     keys.fingerprint().substr(0, 16) + "...");
            
            return VoidResult::Ok();
        }
        catch (const CryptoPP::Exception& e) {
            return VoidResult::Err(std::string("Key generation failed: ") + e.what());
        }
    }
    
    // -------------------------------------------------------------------------
    // Key Loading
    // -------------------------------------------------------------------------
    VoidResult loadX25519PublicKey(const uint8_t* data, size_t len, PeerKeyMaterial& peer) {
        try {
            if (len != X25519_PUBLIC_KEY_SIZE) {
                return VoidResult::Err("Invalid X25519 public key size");
            }
            
            peer.x25519Public.Assign(data, len);
            peer.x25519Valid = true;
            
            LOG_DEBUG("Loaded peer X25519 public key (" + std::to_string(len) + " bytes)");
            return VoidResult::Ok();
        }
        catch (const CryptoPP::Exception& e) {
            return VoidResult::Err(std::string("Failed to load X25519 key: ") + e.what());
        }
    }
    
    VoidResult loadMlkemPublicKey(const uint8_t* data, size_t len, PeerKeyMaterial& peer) {
        if (len != MLKEM768_PUBLIC_KEY_SIZE) {
            return VoidResult::Err("Invalid ML-KEM-768 public key size (expected " + 
                                   std::to_string(MLKEM768_PUBLIC_KEY_SIZE) + ", got " + 
                                   std::to_string(len) + ")");
        }
        
        peer.mlkemPublic.assign(data, data + len);
        peer.mlkemValid = true;
        
        LOG_DEBUG("Loaded peer ML-KEM-768 public key (" + std::to_string(len) + " bytes)");
        return VoidResult::Ok();
    }
    
    // -------------------------------------------------------------------------
    // Hybrid Key Encapsulation (Initiator)
    // -------------------------------------------------------------------------
    // The initiator:
    // 1. Performs X25519 key agreement
    // 2. Encapsulates to peer's ML-KEM public key
    // 3. Combines both shared secrets via HKDF
    // -------------------------------------------------------------------------
    Result<EncapsulationResult, std::string>
    encapsulateSessionKey(const KeyMaterial& myKeys, const PeerKeyMaterial& peerKeys) {
        try {
            if (!peerKeys.x25519Valid || !peerKeys.mlkemValid) {
                return Result<EncapsulationResult, std::string>::Err("Peer keys not fully loaded");
            }
            
            EncapsulationResult result;
            
            // 1. X25519 key agreement
            CryptoPP::SecByteBlock x25519Shared(CryptoPP::x25519::SHARED_KEYLENGTH);
            CryptoPP::x25519 x25519;
            
            // Agree returns false if peer key has small order (invalid)
            if (!x25519.Agree(x25519Shared, myKeys.x25519Private, peerKeys.x25519Public)) {
                return Result<EncapsulationResult, std::string>::Err("X25519 agreement failed (invalid peer key)");
            }
            
            // 2. ML-KEM-768 encapsulation
            result.mlkemCiphertext.resize(OQS_KEM_ml_kem_768_length_ciphertext);
            CryptoPP::SecByteBlock mlkemShared(OQS_KEM_ml_kem_768_length_shared_secret);
            
            OQS_STATUS status = OQS_KEM_ml_kem_768_encaps(
                result.mlkemCiphertext.data(),
                mlkemShared.data(),
                peerKeys.mlkemPublic.data()
            );
            
            if (status != OQS_SUCCESS) {
                return Result<EncapsulationResult, std::string>::Err("ML-KEM-768 encapsulation failed");
            }
            
            // 3. Combine via HKDF: ikm = x25519_shared || mlkem_shared
            CryptoPP::SecByteBlock ikm;
            ikm.Assign(x25519Shared.data(), x25519Shared.size());
            ikm.Append(mlkemShared.data(), mlkemShared.size());
            
            result.sessionKey.CleanNew(SESSION_KEY_SIZE);
            CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
            
            const std::string salt = "p2p-hybrid-pq-salt-v2";
            const std::string info = "p2p-session-key-x25519-mlkem768-v2";
            
            hkdf.DeriveKey(result.sessionKey, result.sessionKey.size(),
                ikm, ikm.size(),
                reinterpret_cast<const CryptoPP::byte*>(salt.data()), salt.size(),
                reinterpret_cast<const CryptoPP::byte*>(info.data()), info.size());
            
            // Note: x25519Shared and mlkemShared are SecByteBlocks - automatically zeroed on destruction

            LOG_INFO("Derived hybrid session key (X25519 + ML-KEM-768)");
            
            return Result<EncapsulationResult, std::string>::Ok(std::move(result));
        }
        catch (const CryptoPP::Exception& e) {
            return Result<EncapsulationResult, std::string>::Err(
                std::string("Key encapsulation failed: ") + e.what());
        }
    }
    
    // -------------------------------------------------------------------------
    // Hybrid Key Decapsulation (Responder)
    // -------------------------------------------------------------------------
    // The responder:
    // 1. Performs X25519 key agreement
    // 2. Decapsulates the ML-KEM ciphertext
    // 3. Combines both shared secrets via HKDF (same as initiator)
    // -------------------------------------------------------------------------
    Result<CryptoPP::SecByteBlock, std::string>
    decapsulateSessionKey(const KeyMaterial& myKeys, const PeerKeyMaterial& peerKeys,
                          const uint8_t* mlkemCiphertext, size_t ciphertextLen) {
        try {
            if (!peerKeys.x25519Valid) {
                return Result<CryptoPP::SecByteBlock, std::string>::Err("Peer X25519 key not loaded");
            }
            
            if (ciphertextLen != MLKEM768_CIPHERTEXT_SIZE) {
                return Result<CryptoPP::SecByteBlock, std::string>::Err(
                    "Invalid ML-KEM ciphertext size (expected " + 
                    std::to_string(MLKEM768_CIPHERTEXT_SIZE) + ", got " + 
                    std::to_string(ciphertextLen) + ")");
            }
            
            // 1. X25519 key agreement
            CryptoPP::SecByteBlock x25519Shared(CryptoPP::x25519::SHARED_KEYLENGTH);
            CryptoPP::x25519 x25519;
            
            if (!x25519.Agree(x25519Shared, myKeys.x25519Private, peerKeys.x25519Public)) {
                return Result<CryptoPP::SecByteBlock, std::string>::Err("X25519 agreement failed (invalid peer key)");
            }
            
            // 2. ML-KEM-768 decapsulation
            CryptoPP::SecByteBlock mlkemShared(OQS_KEM_ml_kem_768_length_shared_secret);
            
            OQS_STATUS status = OQS_KEM_ml_kem_768_decaps(
                mlkemShared.data(),
                mlkemCiphertext,
                myKeys.mlkemSecret.data()
            );
            
            if (status != OQS_SUCCESS) {
                return Result<CryptoPP::SecByteBlock, std::string>::Err("ML-KEM-768 decapsulation failed");
            }
            
            // 3. Combine via HKDF (same as encapsulator)
            CryptoPP::SecByteBlock ikm;
            ikm.Assign(x25519Shared.data(), x25519Shared.size());
            ikm.Append(mlkemShared.data(), mlkemShared.size());
            
            CryptoPP::SecByteBlock sessionKey(SESSION_KEY_SIZE);
            CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
            
            const std::string salt = "p2p-hybrid-pq-salt-v2";
            const std::string info = "p2p-session-key-x25519-mlkem768-v2";
            
            hkdf.DeriveKey(sessionKey, sessionKey.size(),
                ikm, ikm.size(),
                reinterpret_cast<const CryptoPP::byte*>(salt.data()), salt.size(),
                reinterpret_cast<const CryptoPP::byte*>(info.data()), info.size());
            
            // Note: x25519Shared and mlkemShared are SecByteBlocks - automatically zeroed on destruction

            LOG_INFO("Decapsulated hybrid session key (X25519 + ML-KEM-768)");
            
            return Result<CryptoPP::SecByteBlock, std::string>::Ok(std::move(sessionKey));
        }
        catch (const CryptoPP::Exception& e) {
            return Result<CryptoPP::SecByteBlock, std::string>::Err(
                std::string("Key decapsulation failed: ") + e.what());
        }
    }
    
    // -------------------------------------------------------------------------
    // Message Encryption (AES-256-GCM)
    // -------------------------------------------------------------------------
    Result<std::vector<uint8_t>, std::string>
    encryptMessage(SessionKeys& keys, const std::string& message) {
        try {
            // Generate nonce
            CryptoPP::SecByteBlock nonce(GCM_NONCE_SIZE);
            m_rng.GenerateBlock(nonce, nonce.size());
            
            // Build plaintext: [counter:8][timestamp:8][message][hmac:32 optional]
            uint64_t counter = ++keys.sendCounter;
            uint64_t timestamp = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            
            std::string plain;
            plain.resize(16);
            writeU64BE(counter, plain, 0);
            writeU64BE(timestamp, plain, 8);
            plain.append(message);
            
            if (keys.useHmac) {
                CryptoPP::HMAC<CryptoPP::SHA256> hmac(keys.key, keys.key.size());
                hmac.Update(reinterpret_cast<const CryptoPP::byte*>(plain.data()), plain.size());
                CryptoPP::byte mac[HMAC_SIZE];
                hmac.Final(mac);
                plain.append(reinterpret_cast<const char*>(mac), HMAC_SIZE);
            }
            
            // AES-GCM encrypt
            CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
            enc.SetKeyWithIV(keys.key, keys.key.size(), nonce, nonce.size());
            
            std::string cipher;
            CryptoPP::AuthenticatedEncryptionFilter aef(enc, 
                new CryptoPP::StringSink(cipher), false, GCM_TAG_SIZE);
            CryptoPP::StringSource ss(plain, true, new CryptoPP::Redirector(aef));
            
            // Build output: [nonce_len:1][nonce][cipher_len:4][cipher]
            std::vector<uint8_t> output;
            output.reserve(1 + nonce.size() + 4 + cipher.size());
            
            output.push_back(static_cast<uint8_t>(nonce.size()));
            output.insert(output.end(), nonce.begin(), nonce.end());
            
            uint32_t cipherLen = static_cast<uint32_t>(cipher.size());
            output.push_back(static_cast<uint8_t>((cipherLen >> 24) & 0xFF));
            output.push_back(static_cast<uint8_t>((cipherLen >> 16) & 0xFF));
            output.push_back(static_cast<uint8_t>((cipherLen >> 8) & 0xFF));
            output.push_back(static_cast<uint8_t>(cipherLen & 0xFF));
            
            output.insert(output.end(), cipher.begin(), cipher.end());
            
            return Result<std::vector<uint8_t>, std::string>::Ok(std::move(output));
        }
        catch (const CryptoPP::Exception& e) {
            return Result<std::vector<uint8_t>, std::string>::Err(
                std::string("Encryption failed: ") + e.what());
        }
    }
    
    // -------------------------------------------------------------------------
    // Message Decryption (AES-256-GCM)
    // -------------------------------------------------------------------------
    struct DecryptedMessage {
        std::string message;
        uint64_t    counter;
        uint64_t    timestamp;
    };
    
    Result<DecryptedMessage, std::string>
    decryptMessage(SessionKeys& keys, const std::vector<uint8_t>& data) {
        try {
            if (data.size() < 1 + GCM_NONCE_SIZE + 4 + GCM_TAG_SIZE) {
                return Result<DecryptedMessage, std::string>::Err("Message too short");
            }
            
            size_t idx = 0;
            
            // Read nonce
            uint8_t nonceLen = data[idx++];
            if (data.size() < idx + nonceLen + 4) {
                return Result<DecryptedMessage, std::string>::Err("Invalid nonce length");
            }
            
            CryptoPP::SecByteBlock nonce(nonceLen);
            std::memcpy(nonce.data(), data.data() + idx, nonceLen);
            idx += nonceLen;
            
            // Read cipher length
            uint32_t cipherLen = (static_cast<uint32_t>(data[idx]) << 24) |
                                 (static_cast<uint32_t>(data[idx + 1]) << 16) |
                                 (static_cast<uint32_t>(data[idx + 2]) << 8) |
                                 static_cast<uint32_t>(data[idx + 3]);
            idx += 4;
            
            if (data.size() < idx + cipherLen) {
                return Result<DecryptedMessage, std::string>::Err("Truncated ciphertext");
            }
            
            // AES-GCM decrypt
            CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
            dec.SetKeyWithIV(keys.key, keys.key.size(), nonce, nonce.size());
            
            std::string plain;
            CryptoPP::AuthenticatedDecryptionFilter adf(dec, 
                new CryptoPP::StringSink(plain),
                CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION, GCM_TAG_SIZE);
            CryptoPP::StringSource ss(data.data() + idx, cipherLen, true, 
                new CryptoPP::Redirector(adf));
            
            if (plain.size() < 16) {
                return Result<DecryptedMessage, std::string>::Err("Decrypted data too short");
            }
            
            // Verify HMAC if expected
            size_t messageEnd = plain.size();
            if (keys.useHmac) {
                if (plain.size() < 16 + HMAC_SIZE) {
                    return Result<DecryptedMessage, std::string>::Err("Missing HMAC");
                }
                messageEnd = plain.size() - HMAC_SIZE;
                
                CryptoPP::HMAC<CryptoPP::SHA256> hmac(keys.key, keys.key.size());
                hmac.Update(reinterpret_cast<const CryptoPP::byte*>(plain.data()), messageEnd);
                CryptoPP::byte expectedMac[HMAC_SIZE];
                hmac.Final(expectedMac);
                
                if (std::memcmp(expectedMac, plain.data() + messageEnd, HMAC_SIZE) != 0) {
                    return Result<DecryptedMessage, std::string>::Err("HMAC verification failed");
                }
            }
            
            // Parse counter and timestamp
            DecryptedMessage result;
            result.counter   = readU64BE(plain, 0);
            result.timestamp = readU64BE(plain, 8);
            result.message   = plain.substr(16, messageEnd - 16);
            
            // Verify counter (sliding window anti-replay)
            if (!keys.checkReplay(result.counter)) {
                return Result<DecryptedMessage, std::string>::Err(
                    "Replay detected (counter: " + std::to_string(result.counter) + 
                    ", window max: " + std::to_string(keys.recvCounterMax) + ")");
            }
            
            // Verify timestamp (within window)
            uint64_t now = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            
            int64_t drift = static_cast<int64_t>(now) - static_cast<int64_t>(result.timestamp);
            if (std::abs(drift) > TIMESTAMP_WINDOW_SEC * 1000) {
                return Result<DecryptedMessage, std::string>::Err(
                    "Timestamp outside acceptable window (" + std::to_string(drift / 1000) + "s drift)");
            }

            return Result<DecryptedMessage, std::string>::Ok(std::move(result));
        }
        catch (const CryptoPP::Exception& e) {
            return Result<DecryptedMessage, std::string>::Err(
                std::string("Decryption failed: ") + e.what());
        }
    }
    
    // -------------------------------------------------------------------------
    // Peer ID Management
    // -------------------------------------------------------------------------
    VoidResult loadOrCreatePeerId(PeerIdentity& identity, const std::string& filename = "peer_id.bin") {
        std::ifstream in(filename, std::ios::binary);
        if (in) {
            identity.id.resize(PEER_ID_SIZE);
            in.read(reinterpret_cast<char*>(identity.id.data()), PEER_ID_SIZE);
            if (in.gcount() == PEER_ID_SIZE) {
                identity.fingerprint = toHex(identity.id.data(), identity.id.size(), identity.id.size());
                LOG_INFO("Loaded peer ID: " + identity.shortFingerprint());
                return VoidResult::Ok();
            }
        }
        
        // Generate new ID
        identity.id.resize(PEER_ID_SIZE);
        m_rng.GenerateBlock(identity.id.data(), identity.id.size());
        identity.fingerprint = toHex(identity.id.data(), identity.id.size(), identity.id.size());
        
        std::ofstream out(filename, std::ios::binary | std::ios::trunc);
        if (!out) {
            return VoidResult::Err("Failed to save peer ID");
        }
        out.write(reinterpret_cast<const char*>(identity.id.data()), identity.id.size());
        
        LOG_INFO("Generated new peer ID: " + identity.shortFingerprint());
        return VoidResult::Ok();
    }

    // -------------------------------------------------------------------------
    // Known Peer Fingerprint Management (TOFU)
    // -------------------------------------------------------------------------
    // Stores fingerprints keyed by endpoint (ip:port) in a simple text file.
    // Returns: Ok if new peer or fingerprint matches, Err if fingerprint changed (MITM warning)
    // -------------------------------------------------------------------------
    enum class FingerprintCheckResult {
        NewPeer,          // First time seeing this endpoint
        Matched,          // Fingerprint matches stored value
        Changed           // DANGER: Fingerprint changed from stored value
    };

    Result<FingerprintCheckResult, std::string>
    checkAndStorePeerFingerprint(const std::string& endpoint, const std::string& fingerprint,
                                  const std::string& filename = "known_peers.txt") {
        // Load existing known peers
        std::map<std::string, std::string> knownPeers;
        std::ifstream in(filename);
        if (in) {
            std::string line;
            while (std::getline(in, line)) {
                auto sep = line.find('|');
                if (sep != std::string::npos) {
                    knownPeers[line.substr(0, sep)] = line.substr(sep + 1);
                }
            }
        }

        // Check if we know this endpoint
        auto it = knownPeers.find(endpoint);
        if (it != knownPeers.end()) {
            if (it->second == fingerprint) {
                LOG_INFO("Peer fingerprint verified for " + endpoint);
                return Result<FingerprintCheckResult, std::string>::Ok(FingerprintCheckResult::Matched);
            } else {
                LOG_ERROR("FINGERPRINT CHANGED for " + endpoint + "!");
                LOG_ERROR("  Expected: " + it->second.substr(0, 16) + "...");
                LOG_ERROR("  Got:      " + fingerprint.substr(0, 16) + "...");
                LOG_ERROR("  This could indicate a MITM attack!");
                return Result<FingerprintCheckResult, std::string>::Ok(FingerprintCheckResult::Changed);
            }
        }

        // New peer - store fingerprint
        knownPeers[endpoint] = fingerprint;

        std::ofstream out(filename, std::ios::trunc);
        if (!out) {
            return Result<FingerprintCheckResult, std::string>::Err("Failed to save known peers");
        }

        for (const auto& [ep, fp] : knownPeers) {
            out << ep << "|" << fp << "\n";
        }

        LOG_INFO("New peer " + endpoint + " - fingerprint stored (TOFU)");
        return Result<FingerprintCheckResult, std::string>::Ok(FingerprintCheckResult::NewPeer);
    }

    // Clear a stored fingerprint (use if user confirms fingerprint change is expected)
    VoidResult clearPeerFingerprint(const std::string& endpoint,
                                     const std::string& filename = "known_peers.txt") {
        std::map<std::string, std::string> knownPeers;
        std::ifstream in(filename);
        if (in) {
            std::string line;
            while (std::getline(in, line)) {
                auto sep = line.find('|');
                if (sep != std::string::npos) {
                    knownPeers[line.substr(0, sep)] = line.substr(sep + 1);
                }
            }
        }

        knownPeers.erase(endpoint);

        std::ofstream out(filename, std::ios::trunc);
        if (!out) {
            return VoidResult::Err("Failed to save known peers");
        }

        for (const auto& [ep, fp] : knownPeers) {
            out << ep << "|" << fp << "\n";
        }

        LOG_INFO("Cleared stored fingerprint for " + endpoint);
        return VoidResult::Ok();
    }

    // -------------------------------------------------------------------------
    // Key Confirmation
    // -------------------------------------------------------------------------
    // Generates a confirmation token: HMAC-SHA256(key, "KEY_CONFIRM" || role || random_nonce)
    // Returns: [nonce:32][hmac:32]
    // -------------------------------------------------------------------------
    static constexpr size_t KEY_CONFIRM_NONCE_SIZE = 32;
    static constexpr size_t KEY_CONFIRM_TOKEN_SIZE = KEY_CONFIRM_NONCE_SIZE + HMAC_SIZE;
    
    Result<std::vector<uint8_t>, std::string>
    generateKeyConfirmToken(const CryptoPP::SecByteBlock& sessionKey, HandshakeRole role) {
        try {
            std::vector<uint8_t> token(KEY_CONFIRM_TOKEN_SIZE);
            
            // Generate random nonce
            m_rng.GenerateBlock(token.data(), KEY_CONFIRM_NONCE_SIZE);
            
            // Build HMAC input: "KEY_CONFIRM" || role || nonce
            const std::string prefix = "KEY_CONFIRM";
            std::vector<uint8_t> hmacInput;
            hmacInput.reserve(prefix.size() + 1 + KEY_CONFIRM_NONCE_SIZE);
            hmacInput.insert(hmacInput.end(), prefix.begin(), prefix.end());
            hmacInput.push_back(static_cast<uint8_t>(role));
            hmacInput.insert(hmacInput.end(), token.begin(), token.begin() + KEY_CONFIRM_NONCE_SIZE);
            
            // Compute HMAC
            CryptoPP::HMAC<CryptoPP::SHA256> hmac(sessionKey, sessionKey.size());
            hmac.Update(hmacInput.data(), hmacInput.size());
            hmac.Final(token.data() + KEY_CONFIRM_NONCE_SIZE);
            
            return Result<std::vector<uint8_t>, std::string>::Ok(std::move(token));
        }
        catch (const CryptoPP::Exception& e) {
            return Result<std::vector<uint8_t>, std::string>::Err(
                std::string("Key confirm generation failed: ") + e.what());
        }
    }
    
    // Verify peer's key confirmation token
    VoidResult verifyKeyConfirmToken(const CryptoPP::SecByteBlock& sessionKey,
                                      HandshakeRole peerRole,
                                      const std::vector<uint8_t>& token) {
        try {
            if (token.size() != KEY_CONFIRM_TOKEN_SIZE) {
                return VoidResult::Err("Invalid key confirm token size");
            }
            
            // Build HMAC input: "KEY_CONFIRM" || peerRole || nonce
            const std::string prefix = "KEY_CONFIRM";
            std::vector<uint8_t> hmacInput;
            hmacInput.reserve(prefix.size() + 1 + KEY_CONFIRM_NONCE_SIZE);
            hmacInput.insert(hmacInput.end(), prefix.begin(), prefix.end());
            hmacInput.push_back(static_cast<uint8_t>(peerRole));
            hmacInput.insert(hmacInput.end(), token.begin(), token.begin() + KEY_CONFIRM_NONCE_SIZE);
            
            // Compute expected HMAC
            CryptoPP::HMAC<CryptoPP::SHA256> hmac(sessionKey, sessionKey.size());
            hmac.Update(hmacInput.data(), hmacInput.size());
            CryptoPP::byte expectedMac[HMAC_SIZE];
            hmac.Final(expectedMac);
            
            // Constant-time comparison
            if (!CryptoPP::VerifyBufsEqual(expectedMac, token.data() + KEY_CONFIRM_NONCE_SIZE, HMAC_SIZE)) {
                return VoidResult::Err("Key confirmation failed - peer may have different key");
            }
            
            return VoidResult::Ok();
        }
        catch (const CryptoPP::Exception& e) {
            return VoidResult::Err(std::string("Key confirm verification failed: ") + e.what());
        }
    }

private:
    static void writeU64BE(uint64_t val, std::string& out, size_t offset) {
        for (int i = 7; i >= 0; --i) {
            out[offset + (7 - i)] = static_cast<char>((val >> (i * 8)) & 0xFF);
        }
    }
    
    static uint64_t readU64BE(const std::string& in, size_t offset) {
        uint64_t val = 0;
        for (int i = 0; i < 8; ++i) {
            val = (val << 8) | static_cast<uint8_t>(in[offset + i]);
        }
        return val;
    }
    
    CryptoPP::AutoSeededRandomPool m_rng;
};

} // namespace p2p
