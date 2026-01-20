#include "stunworker.h"
#include "../../network/udp_hole_punch.h"
#include "../../network/socket_wrapper.h"

#include <QTimer>
#include <future>

StunWorker::StunWorker(QObject *parent)
    : QObject(parent)
{
    // Ensure WinSock is initialized
    p2p::WinsockInit::instance();
}

StunWorker::~StunWorker()
{
    cancel();
}

void StunWorker::cancel()
{
    m_cancelled.store(true);
    if (m_puncher) {
        m_puncher->stop();
    }
}

void StunWorker::startStunDiscovery(quint16 localPort)
{
    m_cancelled.store(false);

    // Run in detached thread, emit result via queued signal
    std::thread([this, localPort]() {
        doStunDiscovery(localPort);
    }).detach();
}

void StunWorker::doStunDiscovery(quint16 localPort)
{
    // Use default port if none specified (matches Win32 behavior)
    if (localPort == 0) {
        localPort = DEFAULT_LOCAL_PORT;
    }

    // Create UDP socket
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        QTimer::singleShot(0, this, [this]() {
            emit stunFailed("Failed to create UDP socket");
        });
        return;
    }

    // Bind to local port
    sockaddr_in localAddr{};
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = htons(localPort);

    if (bind(sock, reinterpret_cast<sockaddr*>(&localAddr), sizeof(localAddr)) != 0) {
        closesocket(sock);
        QTimer::singleShot(0, this, [this]() {
            emit stunFailed("Failed to bind UDP socket");
        });
        return;
    }

    // Query STUN
    auto result = p2p::stun::discoverPublicEndpoint(sock, "stun.l.google.com", 19302, 5000);
    closesocket(sock);

    if (m_cancelled.load()) {
        return;
    }

    if (result.isOk()) {
        QString endpoint = QString::fromStdString(result.value().toString());
        m_discoveredEndpoint = endpoint;
        QTimer::singleShot(0, this, [this, endpoint]() {
            emit stunComplete(endpoint);
        });
    } else {
        QString error = QString::fromStdString(result.error());
        QTimer::singleShot(0, this, [this, error]() {
            emit stunFailed(error);
        });
    }
}

void StunWorker::startHolePunch(const QString &peerEndpoint, quint16 localPort)
{
    m_cancelled.store(false);
    m_peerEndpoint = peerEndpoint;

    // Run in detached thread
    std::thread([this, peerEndpoint, localPort]() {
        doHolePunch(peerEndpoint, localPort);
    }).detach();
}

void StunWorker::doHolePunch(const QString &peerEndpointStr, quint16 localPort)
{
    // Use default port if none specified (matches Win32 behavior)
    if (localPort == 0) {
        localPort = DEFAULT_LOCAL_PORT;
    }

    // Parse peer endpoint
    QStringList parts = peerEndpointStr.split(':');
    if (parts.size() != 2) {
        QTimer::singleShot(0, this, [this]() {
            emit punchFailed("Invalid peer endpoint format (expected ip:port)");
        });
        return;
    }

    p2p::stun::Endpoint peerEndpoint;
    peerEndpoint.ip = parts[0].toStdString();
    peerEndpoint.port = parts[1].toUShort();

    if (!peerEndpoint.isValid()) {
        QTimer::singleShot(0, this, [this]() {
            emit punchFailed("Invalid peer endpoint");
        });
        return;
    }

    // Create hole puncher
    m_puncher = std::make_unique<p2p::UdpHolePuncher>();

    // Set callbacks
    m_puncher->onSuccess([this](SOCKET sock, const p2p::stun::Endpoint& ep) {
        m_socketHandle = static_cast<qintptr>(sock);
        QTimer::singleShot(0, this, [this]() {
            emit punchComplete(m_socketHandle);
        });
    });

    m_puncher->onFailure([this](const std::string& error) {
        QString err = QString::fromStdString(error);
        QTimer::singleShot(0, this, [this, err]() {
            emit punchFailed(err);
        });
    });

    // Log progress
    QTimer::singleShot(0, this, [this]() {
        emit punchProgress("Starting UDP hole punch...");
    });

    // Start punching
    auto result = m_puncher->start(localPort, peerEndpoint);
    if (!result.isOk()) {
        QString error = QString::fromStdString(result.error());
        QTimer::singleShot(0, this, [this, error]() {
            emit punchFailed(error);
        });
    }
}
