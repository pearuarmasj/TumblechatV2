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
    std::vector<uint8_t>   mlkemPublic;   // 1184 bytes
    std::vector<uint8_t>   mlkemSecret;   // 2400 bytes
    
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
// Session Keys (for message encryption)
// -----------------------------------------------------------------------------
struct SessionKeys {
    CryptoPP::SecByteBlock    key;            // AES-256 key (32 bytes)
    std::atomic<uint64_t>     sendCounter{0};
    uint64_t                  recvCounter = 0;
    bool                      useHmac     = true;
    
    bool isValid() const { return key.size() == SESSION_KEY_SIZE; }
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
            
            LOG_INFO("Generating ML-KEM-768 key pair (post-quantum)...");
            
            // ML-KEM-768 via liboqs
            keys.mlkemPublic.resize(OQS_KEM_ml_kem_768_length_public_key);
            keys.mlkemSecret.resize(OQS_KEM_ml_kem_768_length_secret_key);
            
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
            
            // Securely clear intermediate secrets
            CryptoPP::SecByteBlock zero((std::max)(x25519Shared.size(), mlkemShared.size()));
            std::memset(zero.data(), 0, zero.size());
            std::memcpy(x25519Shared.data(), zero.data(), x25519Shared.size());
            std::memcpy(mlkemShared.data(), zero.data(), mlkemShared.size());
            
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
            
            // Securely clear intermediate secrets
            CryptoPP::SecByteBlock zero((std::max)(x25519Shared.size(), mlkemShared.size()));
            std::memset(zero.data(), 0, zero.size());
            std::memcpy(x25519Shared.data(), zero.data(), x25519Shared.size());
            std::memcpy(mlkemShared.data(), zero.data(), mlkemShared.size());
            
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
            
            // Verify counter (anti-replay)
            if (result.counter <= keys.recvCounter) {
                return Result<DecryptedMessage, std::string>::Err(
                    "Replay detected (counter: " + std::to_string(result.counter) + 
                    ", expected > " + std::to_string(keys.recvCounter) + ")");
            }
            keys.recvCounter = result.counter;
            
            // Verify timestamp (within window)
            uint64_t now = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            
            int64_t drift = static_cast<int64_t>(now) - static_cast<int64_t>(result.timestamp);
            if (std::abs(drift) > TIMESTAMP_WINDOW_SEC * 1000) {
                LOG_WARNING("Large timestamp drift: " + std::to_string(drift / 1000) + "s");
                // Not a hard error, just warn
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
