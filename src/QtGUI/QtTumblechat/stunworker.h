#pragma once

#include <QObject>
#include <QString>
#include <QThread>
#include <memory>

// Forward declarations
namespace p2p {
    class UdpHolePuncher;
    namespace stun {
        struct Endpoint;
    }
}

/**
 * @brief Qt wrapper for STUN discovery and UDP hole punching
 *
 * Runs network operations in background threads and emits Qt signals.
 */
class StunWorker : public QObject
{
    Q_OBJECT

public:
    static constexpr quint16 DEFAULT_LOCAL_PORT = 27015;

    explicit StunWorker(QObject *parent = nullptr);
    ~StunWorker() override;

    // Get the socket handle after successful hole punch (for Session)
    qintptr socketHandle() const { return m_socketHandle; }

    // Get peer endpoint after successful punch
    QString peerEndpoint() const { return m_peerEndpoint; }

    // Get discovered public endpoint after successful STUN discovery
    QString discoveredEndpoint() const { return m_discoveredEndpoint; }

public slots:
    // Start STUN discovery (runs in background, emits stunComplete or stunFailed)
    void startStunDiscovery(quint16 localPort = 0);

    // Start hole punching to peer (runs in background)
    void startHolePunch(const QString &peerEndpoint, quint16 localPort = 0);

    // Cancel any ongoing operation
    void cancel();

signals:
    // STUN discovery complete
    void stunComplete(const QString &publicEndpoint);
    void stunFailed(const QString &error);

    // Hole punch status
    void punchProgress(const QString &status);
    void punchComplete(qintptr socketHandle);
    void punchFailed(const QString &error);

private:
    void doStunDiscovery(quint16 localPort);
    void doHolePunch(const QString &peerEndpoint, quint16 localPort);

    std::unique_ptr<p2p::UdpHolePuncher> m_puncher;
    QThread *m_workerThread = nullptr;
    qintptr m_socketHandle = 0;
    QString m_peerEndpoint;
    QString m_discoveredEndpoint;
    std::atomic<bool> m_cancelled{false};
};
