#pragma once
// =============================================================================
// tcp_transport.h - TCP implementation of ITransport
// =============================================================================
//
// Wraps Socket + FrameIO into the ITransport interface for TCP connections.
// =============================================================================

#include "transport.h"
#include "socket_wrapper.h"
#include "frame_io.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace p2p {

/**
 * TCP transport implementation.
 *
 * Wraps a Socket and FrameIO to provide the ITransport interface for
 * reliable, ordered message delivery over TCP.
 */
class TcpTransport : public ITransport {
public:
    /**
     * Create a TcpTransport by connecting to a remote host.
     *
     * @param host The hostname or IP address to connect to.
     * @param port The port number to connect to.
     * @return Result containing the transport or an error string.
     */
    static Result<std::unique_ptr<TcpTransport>, std::string> connect(
        const std::string& host, uint16_t port)
    {
        // Create TCP socket
        auto socketResult = Socket::createTcp();
        if (!socketResult) {
            return Result<std::unique_ptr<TcpTransport>, std::string>::Err(
                "Failed to create socket: " + socketResult.error());
        }

        Socket socket = std::move(socketResult.value());

        // Connect to remote host
        auto connectResult = socket.connect(host.c_str(), port);
        if (!connectResult) {
            return Result<std::unique_ptr<TcpTransport>, std::string>::Err(
                "Failed to connect to " + host + ":" + std::to_string(port) +
                ": " + connectResult.error());
        }

        // Create transport from connected socket
        return fromSocket(std::move(socket));
    }

    /**
     * Create a TcpTransport from an existing connected socket.
     *
     * @param socket The connected socket (ownership transferred).
     * @return Result containing the transport or an error string.
     */
    static Result<std::unique_ptr<TcpTransport>, std::string> fromSocket(Socket socket)
    {
        if (!socket.isValid()) {
            return Result<std::unique_ptr<TcpTransport>, std::string>::Err(
                "Invalid socket provided");
        }

        // Configure TCP options
        auto noDelayResult = socket.setNoDelay(true);
        if (!noDelayResult) {
            // Log warning but continue - not fatal
        }

        auto keepaliveResult = socket.setKeepalive(KEEPALIVE_IDLE_MS, KEEPALIVE_INTERVAL);
        if (!keepaliveResult) {
            // Log warning but continue - not fatal
        }

        // Create transport (use private constructor via unique_ptr)
        auto transport = std::unique_ptr<TcpTransport>(new TcpTransport(std::move(socket)));

        return Result<std::unique_ptr<TcpTransport>, std::string>::Ok(std::move(transport));
    }

    // Non-copyable, non-movable (due to FrameIO mutex)
    TcpTransport(const TcpTransport&) = delete;
    TcpTransport& operator=(const TcpTransport&) = delete;
    TcpTransport(TcpTransport&&) = delete;
    TcpTransport& operator=(TcpTransport&&) = delete;

    ~TcpTransport() override = default;

    // -------------------------------------------------------------------------
    // ITransport implementation
    // -------------------------------------------------------------------------

    /**
     * Send a message with the given type and payload.
     * Thread-safe (FrameIO handles internal locking for writes).
     */
    VoidResult send(MsgType type, const std::vector<uint8_t>& payload) override
    {
        if (!isConnected()) {
            return VoidResult::Err("Transport not connected");
        }
        return m_frameIO->writeFrame(type, payload);
    }

    /**
     * Receive the next message.
     * Not thread-safe - should only be called from a single reader thread.
     */
    Result<std::pair<MsgType, std::vector<uint8_t>>, std::string> receive() override
    {
        if (!isConnected()) {
            return Result<std::pair<MsgType, std::vector<uint8_t>>, std::string>::Err(
                "Transport not connected");
        }
        return m_frameIO->readFrame();
    }

    /**
     * Close the transport connection.
     */
    void close() override
    {
        m_socket.close();
    }

    /**
     * Check if the transport is currently connected.
     */
    bool isConnected() const override
    {
        return m_socket.isValid();
    }

    /**
     * Get a string representation of the remote endpoint.
     */
    std::string remoteEndpoint() const override
    {
        return m_socket.remoteAddress();
    }

    // -------------------------------------------------------------------------
    // Additional accessors
    // -------------------------------------------------------------------------

    /**
     * Get the local endpoint address.
     */
    std::string localEndpoint() const
    {
        return m_socket.localAddress();
    }

    /**
     * Get the full connection tuple (local -> remote).
     */
    std::string connectionTuple() const
    {
        return m_socket.connectionTuple();
    }

private:
    /**
     * Private constructor - use factory methods connect() or fromSocket().
     */
    explicit TcpTransport(Socket socket)
        : m_socket(std::move(socket))
        , m_frameIO(std::make_unique<FrameIO>(m_socket.handle()))
    {
    }

    Socket                   m_socket;
    std::unique_ptr<FrameIO> m_frameIO;
};

} // namespace p2p
