#pragma once

#include <QObject>
#include <QString>
#include <QTimer>
#include <memory>
#include <atomic>

// Include types directly (forward-declaring enums with underlying types is problematic)
#include "../../core/types.h"
#include "../../network/transport.h"
#include "../../session/connection_manager.h"  // For p2p::nat::NatMapping

// Forward declare Session class only
namespace p2p {
    class Session;
    class ITransport;
}

/**
 * @brief Qt wrapper for p2p::Session - marshals worker thread callbacks to Qt main thread
 *
 * Session callbacks fire on the recv worker thread. This bridge uses
 * QTimer::singleShot(0, ...) to safely emit Qt signals on the main thread.
 */
class SessionBridge : public QObject
{
    Q_OBJECT

public:
    explicit SessionBridge(QObject *parent = nullptr);
    ~SessionBridge() override;

    // Initialize crypto (call once before start)
    bool initialize();

    // Start session with TCP socket (legacy - wraps in TcpTransport)
    // role: true = Initiator, false = Responder
    bool startTcp(qintptr socketHandle, bool asInitiator);

    // Start TCP with simultaneous listen+connect (like Win32 GUI)
    // Both threads race - first connection wins. Order doesn't matter.
    bool startTcpSimultaneous(quint16 localPort, const QString &peerHost, quint16 peerPort, bool asInitiator);

    // Start session with UDP transport from hole punch
    // socketHandle: UDP socket from hole punch
    // peerIp, peerPort: peer's endpoint from hole punch
    bool startUdp(qintptr socketHandle, const QString &peerIp, quint16 peerPort, bool asInitiator);

    // Start session with pre-created transport (most flexible)
    bool start(std::unique_ptr<p2p::ITransport> transport, bool asInitiator);

    // Check state
    bool isConnected() const;
    bool isReady() const;
    QString peerFingerprint() const;

signals:
    // Emitted when connection state changes
    void stateChanged(int state); // ConnectionState as int for Qt meta

    // Emitted when message received from peer
    void messageReceived(const QString &text, quint64 timestamp);

    // Emitted on error
    void errorOccurred(int error, const QString &detail); // SessionError as int

    // Convenience signals
    void connected(const QString &fingerprint);
    void disconnected();
    void ready();
    void rekeyCompleted(const QString &newFingerprint);  // Emitted after 60-second key rotation

public slots:
    // Send message to peer (thread-safe, can call from any thread)
    bool sendMessage(const QString &text);

    // Graceful disconnect
    void disconnect();

private:
    void setupCallbacks();
    void doTcpListen(quint16 localPort, bool asInitiator);
    void doTcpConnect(const std::string &host, quint16 port, bool asInitiator);
    void doUdpHandshake(qintptr sock, const std::string &peerIp, quint16 peerPort, bool asInitiator);

    std::unique_ptr<p2p::Session> m_session;
    QString m_peerFingerprint;
    bool m_initialized = false;
    p2p::nat::NatMapping m_natMapping;  // For NAT-PMP cleanup
    std::atomic<bool> m_sessionChosen{false};  // Race flag for TCP simultaneous open
};
