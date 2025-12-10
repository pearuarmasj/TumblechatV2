#pragma once
// =============================================================================
// frame_io.h - Thread-safe framed message I/O
// =============================================================================

#include <winsock2.h>
#include <vector>
#include <mutex>
#include <string>
#include "../core/types.h"
#include "../core/result.h"
#include "../core/logger.h"

namespace p2p {

// -----------------------------------------------------------------------------
// Frame Format:
//   [4 bytes] Total length (big-endian, includes type byte)
//   [1 byte]  Message type
//   [N bytes] Payload
// -----------------------------------------------------------------------------

class FrameIO {
public:
    explicit FrameIO(SOCKET socket) : m_socket(socket) {}
    
    // Thread-safe write
    VoidResult writeFrame(MsgType type, const std::vector<uint8_t>& payload) {
        if (payload.size() > MAX_FRAME_SIZE - 1) {
            return VoidResult::Err("Payload too large: " + std::to_string(payload.size()));
        }
        
        std::lock_guard<std::mutex> lock(m_writeMutex);
        
        uint32_t totalLen = 1 + static_cast<uint32_t>(payload.size());
        
        // Header (4 bytes, big-endian)
        uint8_t header[4] = {
            static_cast<uint8_t>((totalLen >> 24) & 0xFF),
            static_cast<uint8_t>((totalLen >> 16) & 0xFF),
            static_cast<uint8_t>((totalLen >> 8) & 0xFF),
            static_cast<uint8_t>(totalLen & 0xFF)
        };
        
        if (!sendAll(header, 4)) {
            return VoidResult::Err("Failed to send header: " + std::to_string(WSAGetLastError()));
        }
        
        // Type byte
        uint8_t typeByte = static_cast<uint8_t>(type);
        if (!sendAll(&typeByte, 1)) {
            return VoidResult::Err("Failed to send type: " + std::to_string(WSAGetLastError()));
        }
        
        // Payload
        if (!payload.empty()) {
            if (!sendAll(payload.data(), payload.size())) {
                return VoidResult::Err("Failed to send payload: " + std::to_string(WSAGetLastError()));
            }
        }
        
        return VoidResult::Ok();
    }
    
    // Read (not thread-safe, intended for single reader thread)
    Result<std::pair<MsgType, std::vector<uint8_t>>, std::string> readFrame() {
        // Read header
        uint8_t header[4];
        if (!recvAll(header, 4)) {
            return Result<std::pair<MsgType, std::vector<uint8_t>>, std::string>::Err(
                "Failed to read header: " + std::to_string(WSAGetLastError()));
        }
        
        uint32_t totalLen = (static_cast<uint32_t>(header[0]) << 24) |
                            (static_cast<uint32_t>(header[1]) << 16) |
                            (static_cast<uint32_t>(header[2]) << 8) |
                            static_cast<uint32_t>(header[3]);
        
        if (totalLen < 1) {
            return Result<std::pair<MsgType, std::vector<uint8_t>>, std::string>::Err(
                "Invalid frame length: 0");
        }
        
        if (totalLen > MAX_FRAME_SIZE) {
            return Result<std::pair<MsgType, std::vector<uint8_t>>, std::string>::Err(
                "Frame too large: " + std::to_string(totalLen));
        }
        
        // Read type
        uint8_t typeByte;
        if (!recvAll(&typeByte, 1)) {
            return Result<std::pair<MsgType, std::vector<uint8_t>>, std::string>::Err(
                "Failed to read type: " + std::to_string(WSAGetLastError()));
        }
        
        // Read payload
        uint32_t payloadLen = totalLen - 1;
        std::vector<uint8_t> payload(payloadLen);
        
        if (payloadLen > 0) {
            if (!recvAll(payload.data(), payloadLen)) {
                return Result<std::pair<MsgType, std::vector<uint8_t>>, std::string>::Err(
                    "Failed to read payload: " + std::to_string(WSAGetLastError()));
            }
        }
        
        return Result<std::pair<MsgType, std::vector<uint8_t>>, std::string>::Ok(
            {static_cast<MsgType>(typeByte), std::move(payload)});
    }
    
    // Convenience for empty payloads
    VoidResult writeFrame(MsgType type) {
        return writeFrame(type, {});
    }
    
private:
    bool sendAll(const uint8_t* data, size_t len) {
        size_t sent = 0;
        while (sent < len) {
            int n = send(m_socket, reinterpret_cast<const char*>(data + sent), 
                        static_cast<int>(len - sent), 0);
            if (n == SOCKET_ERROR) return false;
            sent += static_cast<size_t>(n);
        }
        return true;
    }
    
    bool recvAll(uint8_t* data, size_t len) {
        size_t received = 0;
        while (received < len) {
            int n = recv(m_socket, reinterpret_cast<char*>(data + received), 
                        static_cast<int>(len - received), 0);
            if (n <= 0) return false;  // 0 = graceful close, -1 = error
            received += static_cast<size_t>(n);
        }
        return true;
    }
    
    SOCKET      m_socket;
    std::mutex  m_writeMutex;
};

} // namespace p2p
