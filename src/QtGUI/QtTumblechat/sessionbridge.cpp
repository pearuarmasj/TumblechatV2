#include "sessionbridge.h"

// Include full session header
#include "../../session/session.h"
#include "../../session/connection_manager.h"  // For NAT-PMP
#include "../../network/tcp_transport.h"
#include "../../network/udp_transport.h"

#include <QThread>
#include <thread>
#include <chrono>

SessionBridge::SessionBridge(QObject *parent)
    : QObject(parent)
    , m_session(std::make_unique<p2p::Session>())
{
    setupCallbacks();
}

SessionBridge::~SessionBridge()
{
    // Stop session first - this joins worker threads
    if (m_session) {
        m_session->stop();
    }

    // Clean up NAT-PMP mapping if we created one
    if (m_natMapping.active) {
        p2p::nat::removeNatPmpMapping(m_natMapping.internalPort);
    }
}

void SessionBridge::setupCallbacks()
{
    // Message callback - fires on recv worker thread
    m_session->onMessage([this](const std::string& msg, uint64_t timestamp) {
        QString text = QString::fromStdString(msg);
        // Marshal to Qt main thread
        QTimer::singleShot(0, this, [this, text, timestamp]() {
            emit messageReceived(text, timestamp);
        });
    });

    // State callback - fires on various threads
    m_session->onStateChange([this](p2p::ConnectionState state) {
        int stateInt = static_cast<int>(state);
        // Marshal to Qt main thread
        QTimer::singleShot(0, this, [this, state, stateInt]() {
            emit stateChanged(stateInt);

            // Emit convenience signals
            if (state == p2p::ConnectionState::Ready) {
                m_peerFingerprint = QString::fromStdString(m_session->peerFingerprint());
                emit connected(m_peerFingerprint);
                emit ready();
            } else if (state == p2p::ConnectionState::Disconnected) {
                emit disconnected();
            }
        });
    });

    // Error callback - fires on worker thread
    m_session->onError([this](p2p::SessionError err, const std::string& detail) {
        int errInt = static_cast<int>(err);
        QString detailStr = QString::fromStdString(detail);
        // Marshal to Qt main thread
        QTimer::singleShot(0, this, [this, errInt, detailStr]() {
            emit errorOccurred(errInt, detailStr);
        });
    });

    // Rekey callback - fires on recv worker thread after 60-second key rotation
    m_session->onRekey([this](const std::string& newFingerprint) {
        QString fp = QString::fromStdString(newFingerprint);
        // Marshal to Qt main thread
        QTimer::singleShot(0, this, [this, fp]() {
            m_peerFingerprint = fp;
            emit rekeyCompleted(fp);
        });
    });
}

bool SessionBridge::initialize()
{
    auto result = m_session->initialize(true);
    m_initialized = result.isOk();
    return m_initialized;
}

bool SessionBridge::startTcp(qintptr socketHandle, bool asInitiator)
{
    if (!m_initialized) {
        return false;
    }

    // Wrap the socket handle in a TcpTransport
    p2p::Socket socket(static_cast<SOCKET>(socketHandle));
    auto transportResult = p2p::TcpTransport::fromSocket(std::move(socket));
    if (!transportResult) {
        return false;
    }

    auto role = asInitiator ? p2p::HandshakeRole::Initiator : p2p::HandshakeRole::Responder;
    auto result = m_session->start(std::move(transportResult.value()), role);

    return result.isOk();
}

bool SessionBridge::startTcpSimultaneous(quint16 localPort, const QString &peerHost, quint16 peerPort, bool asInitiator)
{
    if (!m_initialized) {
        return false;
    }

    // Reset session chosen flag
    m_sessionChosen.store(false);

    // Request NAT-PMP port mapping so peer can reach us through NAT
    auto natResult = p2p::nat::addNatPmpMapping(localPort);
    if (natResult) {
        m_natMapping = natResult.value();
    }

    // Start BOTH listen and connect threads - first one to succeed wins
    std::string hostStr = peerHost.toStdString();

    // Listen thread
    std::thread([this, localPort, asInitiator]() {
        doTcpListen(localPort, asInitiator);
    }).detach();

    // Connect thread
    std::thread([this, hostStr, peerPort, asInitiator]() {
        doTcpConnect(hostStr, peerPort, asInitiator);
    }).detach();

    return true;  // Return immediately, success/failure comes via signals
}

void SessionBridge::doTcpListen(quint16 localPort, bool asInitiator)
{
    // Create TCP socket for listening
    auto socketResult = p2p::Socket::createTcp();
    if (!socketResult) {
        return;  // Listen failed, connect thread may still succeed
    }

    p2p::Socket listenSocket = std::move(socketResult.value());
    listenSocket.setReuseAddr(true);

    auto bindResult = listenSocket.bind(localPort);
    if (!bindResult) {
        return;  // Bind failed, connect thread may still succeed
    }

    auto listenResult = listenSocket.listen(1);
    if (!listenResult) {
        return;  // Listen failed, connect thread may still succeed
    }

    // Use select with timeout to allow checking m_sessionChosen periodically
    while (!m_sessionChosen.load()) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(listenSocket.handle(), &fds);
        timeval tv{1, 0};  // 1 second timeout

        int r = select(0, &fds, nullptr, nullptr, &tv);
        if (r <= 0) {
            continue;  // Timeout or error, check sessionChosen and retry
        }

        // Check again before accepting
        if (m_sessionChosen.load()) {
            return;
        }

        auto acceptResult = listenSocket.accept();
        if (!acceptResult) {
            continue;  // Accept failed, retry
        }

        // We got a connection - try to claim it
        bool expected = false;
        if (!m_sessionChosen.compare_exchange_strong(expected, true)) {
            // Connect thread already won, close this socket
            return;
        }

        // We won the race! Start the session
        auto transportResult = p2p::TcpTransport::fromSocket(std::move(acceptResult.value()));
        if (!transportResult) {
            m_sessionChosen.store(false);  // Allow connect thread to try
            QTimer::singleShot(0, this, [this]() {
                emit errorOccurred(0, "[listen] Failed to create transport");
            });
            return;
        }

        auto role = asInitiator ? p2p::HandshakeRole::Initiator : p2p::HandshakeRole::Responder;
        auto result = m_session->start(std::move(transportResult.value()), role);

        if (!result) {
            QTimer::singleShot(0, this, [this, err = result.error()]() {
                emit errorOccurred(0, QString::fromStdString("[listen] " + err));
            });
        }
        return;
    }
}

void SessionBridge::doTcpConnect(const std::string &host, quint16 port, bool asInitiator)
{
    // Small delay to give listen thread time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Retry loop with timeout
    auto start = std::chrono::steady_clock::now();
    while (!m_sessionChosen.load()) {
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > std::chrono::seconds(15)) {
            // Timeout
            return;
        }

        // Try to connect
        auto transportResult = p2p::TcpTransport::connect(host, port);
        if (!transportResult) {
            // Connect failed, sleep and retry
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        // We connected - try to claim it
        bool expected = false;
        if (!m_sessionChosen.compare_exchange_strong(expected, true)) {
            // Listen thread already won
            return;
        }

        // We won the race! Start the session
        auto role = asInitiator ? p2p::HandshakeRole::Initiator : p2p::HandshakeRole::Responder;
        auto result = m_session->start(std::move(transportResult.value()), role);

        if (!result) {
            QTimer::singleShot(0, this, [this, err = result.error()]() {
                emit errorOccurred(0, QString::fromStdString("[connect] " + err));
            });
        }
        return;
    }
}

bool SessionBridge::startUdp(qintptr socketHandle, const QString &peerIp, quint16 peerPort, bool asInitiator)
{
    if (!m_initialized) {
        emit errorOccurred(0, "SessionBridge not initialized");
        return false;
    }

    // Run handshake in background thread (like TCP simultaneous)
    // This allows the other peer time to click Connect
    std::string peerIpStr = peerIp.toStdString();
    std::thread([this, socketHandle, peerIpStr, peerPort, asInitiator]() {
        doUdpHandshake(socketHandle, peerIpStr, peerPort, asInitiator);
    }).detach();

    return true;  // Return immediately, success/failure comes via signals
}

void SessionBridge::doUdpHandshake(qintptr sock, const std::string &peerIp, quint16 peerPort, bool asInitiator)
{
    // Create UDP transport from hole-punched socket
    // This does the handshake which may take up to 60 seconds
    auto transportResult = p2p::UdpTransport::fromHolePunch(
        static_cast<SOCKET>(sock),
        peerIp,
        peerPort);

    if (!transportResult) {
        QTimer::singleShot(0, this, [this, err = transportResult.error()]() {
            emit errorOccurred(0, QString("UDP transport failed: %1").arg(QString::fromStdString(err)));
        });
        return;
    }

    auto role = asInitiator ? p2p::HandshakeRole::Initiator : p2p::HandshakeRole::Responder;
    auto result = m_session->start(std::move(transportResult.value()), role);

    if (!result) {
        QTimer::singleShot(0, this, [this, err = result.error()]() {
            emit errorOccurred(0, QString("Session start failed: %1").arg(QString::fromStdString(err)));
        });
        return;
    }

    // Success is signaled through the session callbacks (connected signal)
}

bool SessionBridge::start(std::unique_ptr<p2p::ITransport> transport, bool asInitiator)
{
    if (!m_initialized || !transport) {
        return false;
    }

    auto role = asInitiator ? p2p::HandshakeRole::Initiator : p2p::HandshakeRole::Responder;
    auto result = m_session->start(std::move(transport), role);

    return result.isOk();
}

bool SessionBridge::isConnected() const
{
    return m_session && m_session->isConnected();
}

bool SessionBridge::isReady() const
{
    return m_session && m_session->isReady();
}

QString SessionBridge::peerFingerprint() const
{
    return m_peerFingerprint;
}

bool SessionBridge::sendMessage(const QString &text)
{
    if (!m_session || !m_session->isReady()) {
        return false;
    }

    auto result = m_session->send(text.toStdString());
    return result.isOk();
}

void SessionBridge::disconnect()
{
    if (m_session) {
        m_session->stop();
    }
}
