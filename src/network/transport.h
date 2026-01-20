#pragma once
// =============================================================================
// transport.h - Abstract transport interface for TCP and UDP
// =============================================================================

#include "../core/types.h"
#include "../core/result.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace p2p {

/**
 * Transport type enumeration.
 */
enum class TransportType {
    TCP,
    UDP
};

/**
 * Abstract transport interface for sending and receiving framed messages.
 * Both TCP and UDP implementations should conform to this interface.
 */
class ITransport {
public:
    virtual ~ITransport() = default;

    /**
     * Send a message with the given type and payload.
     * @param type The message type.
     * @param payload The message payload bytes.
     * @return VoidResult indicating success or failure.
     */
    virtual VoidResult send(MsgType type, const std::vector<uint8_t>& payload) = 0;

    /**
     * Receive the next message.
     * @return A Result containing the message type and payload, or an error string.
     */
    virtual Result<std::pair<MsgType, std::vector<uint8_t>>, std::string> receive() = 0;

    /**
     * Close the transport connection.
     */
    virtual void close() = 0;

    /**
     * Check if the transport is currently connected.
     * @return true if connected, false otherwise.
     */
    virtual bool isConnected() const = 0;

    /**
     * Get a string representation of the remote endpoint.
     * @return Remote endpoint as a string (e.g., "192.168.1.1:8080").
     */
    virtual std::string remoteEndpoint() const = 0;
};

} // namespace p2p
