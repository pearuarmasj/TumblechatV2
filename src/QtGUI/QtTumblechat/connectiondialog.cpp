#include "connectiondialog.h"
#include "chatwidget.h"
#include "stunworker.h"
#include "sessionbridge.h"

#include <QApplication>
#include <QClipboard>
#include <QMessageBox>

ConnectionDialog::ConnectionDialog(QWidget *parent)
    : QDialog(parent)
    , m_stunWorker(std::make_unique<StunWorker>(this))
    , m_sessionBridge(std::make_unique<SessionBridge>(this))
{
    setWindowTitle("New Connection");
    setMinimumSize(500, 500);
    setModal(true);

    setupUi();
    applyStyles();
    setStep(1);

    // Connect StunWorker signals
    connect(m_stunWorker.get(), &StunWorker::stunComplete, this, &ConnectionDialog::onStunComplete);
    connect(m_stunWorker.get(), &StunWorker::stunFailed, this, &ConnectionDialog::onStunFailed);
    connect(m_stunWorker.get(), &StunWorker::punchProgress, this, &ConnectionDialog::onPunchProgress);
    connect(m_stunWorker.get(), &StunWorker::punchComplete, this, &ConnectionDialog::onPunchComplete);
    connect(m_stunWorker.get(), &StunWorker::punchFailed, this, &ConnectionDialog::onPunchFailed);

    // Connect SessionBridge signals
    connect(m_sessionBridge.get(), &SessionBridge::connected, this, &ConnectionDialog::onSessionConnected);
    connect(m_sessionBridge.get(), &SessionBridge::errorOccurred, this, &ConnectionDialog::onSessionError);

    // Initialize session crypto
    if (!m_sessionBridge->initialize()) {
        appendLog("Warning: Failed to initialize session crypto");
    }
}

ConnectionDialog::~ConnectionDialog()
{
    // Cancel any pending operations
    if (m_stunWorker) {
        m_stunWorker->cancel();
    }

    // Clean up chat widget if dialog rejected
    if (m_chatWidget && result() != QDialog::Accepted) {
        delete m_chatWidget;
        m_chatWidget = nullptr;
    }
}

void ConnectionDialog::setupUi()
{
    m_mainLayout = new QVBoxLayout(this);
    m_mainLayout->setSpacing(12);

    // Step 1: STUN Discovery
    m_stunGroup = new QGroupBox("Step 1: Discover Your Endpoint");
    QVBoxLayout *stunLayout = new QVBoxLayout(m_stunGroup);

    m_stunBtn = new QPushButton("Query STUN Server");
    stunLayout->addWidget(m_stunBtn);

    QHBoxLayout *endpointLayout = new QHBoxLayout();
    m_yourEndpointLabel = new QLabel("Your endpoint:");
    m_yourEndpoint = new QLineEdit();
    m_yourEndpoint->setReadOnly(true);
    m_yourEndpoint->setPlaceholderText("Click 'Query STUN Server' first");
    m_copyBtn = new QPushButton("Copy");
    m_copyBtn->setEnabled(false);

    endpointLayout->addWidget(m_yourEndpointLabel);
    endpointLayout->addWidget(m_yourEndpoint, 1);
    endpointLayout->addWidget(m_copyBtn);
    stunLayout->addLayout(endpointLayout);

    m_mainLayout->addWidget(m_stunGroup);

    // Step 2: Peer Endpoint
    m_peerGroup = new QGroupBox("Step 2: Enter Peer's Endpoint");
    QHBoxLayout *peerLayout = new QHBoxLayout(m_peerGroup);

    QLabel *peerLabel = new QLabel("Peer endpoint:");
    m_peerEndpoint = new QLineEdit();
    m_peerEndpoint->setPlaceholderText("e.g., 123.45.67.89:12345");

    peerLayout->addWidget(peerLabel);
    peerLayout->addWidget(m_peerEndpoint, 1);

    m_mainLayout->addWidget(m_peerGroup);

    // Step 3: Hole Punch
    m_punchGroup = new QGroupBox("Step 3: NAT Traversal");
    QVBoxLayout *punchLayout = new QVBoxLayout(m_punchGroup);

    m_punchBtn = new QPushButton("Start Hole Punch");
    m_punchBtn->setEnabled(false);
    punchLayout->addWidget(m_punchBtn);

    m_mainLayout->addWidget(m_punchGroup);

    // Protocol selection (between step 3 and 4)
    m_protocolGroup = new QGroupBox("Protocol Selection");
    QHBoxLayout *protocolLayout = new QHBoxLayout(m_protocolGroup);

    m_tcpRadio = new QRadioButton("TCP (reliable, lower latency)");
    m_udpRadio = new QRadioButton("UDP (NAT-friendly, DTLS reliability)");
    m_udpRadio->setChecked(true); // Default to UDP since we're doing hole punch

    protocolLayout->addWidget(m_tcpRadio);
    protocolLayout->addWidget(m_udpRadio);

    m_mainLayout->addWidget(m_protocolGroup);

    // Step 4: Role selection
    m_roleGroup = new QGroupBox("Step 4: Select Your Role");
    QHBoxLayout *roleLayout = new QHBoxLayout(m_roleGroup);

    m_initiatorRadio = new QRadioButton("Initiator (start handshake)");
    m_responderRadio = new QRadioButton("Responder (wait for handshake)");
    m_initiatorRadio->setChecked(true); // Default

    roleLayout->addWidget(m_initiatorRadio);
    roleLayout->addWidget(m_responderRadio);

    m_mainLayout->addWidget(m_roleGroup);

    // Log area
    m_logArea = new QTextEdit();
    m_logArea->setReadOnly(true);
    m_logArea->setMaximumHeight(150);
    m_mainLayout->addWidget(m_logArea);

    // Step 4: Connect button
    m_connectBtn = new QPushButton("Connect");
    m_connectBtn->setEnabled(false);
    m_mainLayout->addWidget(m_connectBtn);

    // Cancel button
    m_buttonLayout = new QHBoxLayout();
    m_buttonLayout->addStretch();
    m_cancelBtn = new QPushButton("Cancel");
    m_buttonLayout->addWidget(m_cancelBtn);
    m_mainLayout->addLayout(m_buttonLayout);

    // Connect signals
    connect(m_stunBtn, &QPushButton::clicked, this, &ConnectionDialog::onStunQuery);
    connect(m_copyBtn, &QPushButton::clicked, this, &ConnectionDialog::onCopyEndpoint);
    connect(m_punchBtn, &QPushButton::clicked, this, &ConnectionDialog::onHolePunch);
    connect(m_connectBtn, &QPushButton::clicked, this, &ConnectionDialog::onConnect);
    connect(m_cancelBtn, &QPushButton::clicked, this, &QDialog::reject);

    // Enable punch button when peer endpoint is entered
    connect(m_peerEndpoint, &QLineEdit::textChanged, this, [this](const QString &text) {
        bool canPunch = m_stunComplete && !text.trimmed().isEmpty();
        m_punchBtn->setEnabled(canPunch);
    });
}

void ConnectionDialog::applyStyles()
{
    setStyleSheet(
        "QDialog { background-color: #0f0f1a; }"
        "QGroupBox { "
        "  color: #eee; "
        "  border: 1px solid #2d2d44; "
        "  border-radius: 4px; "
        "  margin-top: 12px; "
        "  padding-top: 12px; "
        "}"
        "QGroupBox::title { "
        "  subcontrol-origin: margin; "
        "  left: 10px; "
        "  padding: 0 5px; "
        "}"
        "QLabel { color: #ccc; }"
        "QLineEdit { "
        "  background-color: #1a1a2e; "
        "  border: 1px solid #2d2d44; "
        "  border-radius: 4px; "
        "  padding: 8px; "
        "  color: #eee; "
        "}"
        "QLineEdit:focus { border-color: #0f3460; }"
        "QLineEdit:read-only { background-color: #12121f; }"
        "QPushButton { "
        "  background-color: #0f3460; "
        "  color: white; "
        "  border: none; "
        "  border-radius: 4px; "
        "  padding: 10px 16px; "
        "  font-weight: bold; "
        "}"
        "QPushButton:hover { background-color: #1a4f7a; }"
        "QPushButton:pressed { background-color: #0a2540; }"
        "QPushButton:disabled { "
        "  background-color: #2d2d44; "
        "  color: #6b7280; "
        "}"
        "QTextEdit { "
        "  background-color: #12121f; "
        "  border: 1px solid #2d2d44; "
        "  border-radius: 4px; "
        "  color: #888; "
        "  font-family: monospace; "
        "  font-size: 11px; "
        "}"
        "QRadioButton { "
        "  color: #ccc; "
        "  spacing: 8px; "
        "}"
        "QRadioButton::indicator { "
        "  width: 16px; "
        "  height: 16px; "
        "  border: 2px solid #2d2d44; "
        "  border-radius: 9px; "
        "  background-color: #1a1a2e; "
        "}"
        "QRadioButton::indicator:checked { "
        "  background-color: #0f3460; "
        "  border-color: #1a4f7a; "
        "}"
        "QRadioButton::indicator:hover { "
        "  border-color: #1a4f7a; "
        "}"
    );
}

void ConnectionDialog::setStep(int step)
{
    m_currentStep = step;
}

void ConnectionDialog::appendLog(const QString &message)
{
    m_logArea->append(message);
}

// ============================================================================
// STUN Query
// ============================================================================

void ConnectionDialog::onStunQuery()
{
    m_stunBtn->setEnabled(false);
    m_stunBtn->setText("Querying...");
    appendLog("Querying STUN server (stun.l.google.com:19302)...");

    m_stunWorker->startStunDiscovery(0); // 0 = let OS choose port
}

void ConnectionDialog::onStunComplete(const QString &endpoint)
{
    m_yourEndpoint->setText(endpoint);
    m_copyBtn->setEnabled(true);
    m_stunComplete = true;

    appendLog("STUN query successful: " + endpoint);
    m_stunBtn->setText("Query STUN Server");
    m_stunBtn->setEnabled(true);

    setStep(2);

    // Enable punch if peer already entered
    if (!m_peerEndpoint->text().trimmed().isEmpty()) {
        m_punchBtn->setEnabled(true);
    }
}

void ConnectionDialog::onStunFailed(const QString &error)
{
    appendLog("STUN query failed: " + error);
    m_stunBtn->setText("Query STUN Server");
    m_stunBtn->setEnabled(true);
}

// ============================================================================
// Copy Endpoint
// ============================================================================

void ConnectionDialog::onCopyEndpoint()
{
    QApplication::clipboard()->setText(m_yourEndpoint->text());
    appendLog("Endpoint copied to clipboard");
}

// ============================================================================
// Hole Punch
// ============================================================================

void ConnectionDialog::onHolePunch()
{
    QString peerEp = m_peerEndpoint->text().trimmed();
    if (peerEp.isEmpty()) {
        QMessageBox::warning(this, "Error", "Enter peer endpoint first");
        return;
    }

    m_punchBtn->setEnabled(false);
    m_punchBtn->setText("Punching...");
    appendLog("Starting UDP hole punch to " + peerEp + "...");

    m_stunWorker->startHolePunch(peerEp, 27015);
}

void ConnectionDialog::onPunchProgress(const QString &status)
{
    appendLog(status);
}

void ConnectionDialog::onPunchComplete(qintptr socketHandle)
{
    m_socketHandle = socketHandle;
    m_punchComplete = true;
    m_connectBtn->setEnabled(true);

    QString peerEp = m_peerEndpoint->text().trimmed();
    appendLog("Hole punch successful - NAT traversal complete");
    appendLog("Connected to peer endpoint: " + peerEp);
    m_punchBtn->setText("Punch Complete");

    setStep(4);
}

void ConnectionDialog::onPunchFailed(const QString &error)
{
    appendLog("Hole punch failed: " + error);
    m_punchBtn->setText("Start Hole Punch");
    m_punchBtn->setEnabled(true);
}

// ============================================================================
// Connect (Session Handshake)
// ============================================================================

void ConnectionDialog::onConnect()
{
    if (!m_punchComplete || m_socketHandle == 0) {
        QMessageBox::warning(this, "Error", "Complete hole punch first");
        return;
    }

    m_connectBtn->setEnabled(false);
    m_connectBtn->setText("Connecting...");

    bool isInitiator = m_initiatorRadio->isChecked();
    bool useTcp = m_tcpRadio->isChecked();
    QString role = isInitiator ? "Initiator" : "Responder";
    QString protocol = useTcp ? "TCP" : "UDP";

    appendLog("Starting as " + role + " using " + protocol + "...");
    appendLog("Establishing encrypted session...");

    // Parse peer endpoint for IP and port
    QString peerEp = m_peerEndpoint->text().trimmed();
    int colonPos = peerEp.lastIndexOf(':');
    if (colonPos == -1) {
        appendLog("Invalid peer endpoint format");
        m_connectBtn->setText("Connect");
        m_connectBtn->setEnabled(true);
        return;
    }
    QString peerIp = peerEp.left(colonPos);
    quint16 peerPort = peerEp.mid(colonPos + 1).toUShort();

    bool started = false;

    if (useTcp) {
        // TCP path: Both sides listen AND connect simultaneously - first connection wins
        // Order doesn't matter - click Connect whenever ready
        appendLog("TCP: Starting simultaneous listen+connect (order doesn't matter)");
        appendLog("Listening on port " + QString::number(StunWorker::DEFAULT_LOCAL_PORT) + " + connecting to " + peerIp + ":" + QString::number(peerPort));
        started = m_sessionBridge->startTcpSimultaneous(StunWorker::DEFAULT_LOCAL_PORT, peerIp, peerPort, isInitiator);
    } else {
        // UDP path: Use the hole-punched socket directly with DTLS reliability
        appendLog("Using hole-punched UDP socket with DTLS reliability layer");
        appendLog("Waiting for peer to click Connect (up to 60 seconds)...");
        started = m_sessionBridge->startUdp(m_socketHandle, peerIp, peerPort, isInitiator);
    }

    if (!started) {
        appendLog("Failed to start session");
        m_connectBtn->setText("Connect");
        m_connectBtn->setEnabled(true);
    }
}

void ConnectionDialog::onSessionConnected(const QString &fingerprint)
{
    m_peerFingerprint = fingerprint;

    appendLog("Session established!");
    appendLog("Peer fingerprint: " + fingerprint);

    // Create the chat widget
    m_chatWidget = new ChatWidget();

    // Transfer session bridge ownership to chat widget
    m_chatWidget->setSessionBridge(m_sessionBridge.release());
    m_chatWidget->setConnected(true, fingerprint);

    accept(); // Close dialog with success
}

void ConnectionDialog::onSessionError(int error, const QString &detail)
{
    appendLog("Session error: " + detail);
    m_connectBtn->setText("Connect");
    m_connectBtn->setEnabled(true);
}

// ============================================================================
// Result
// ============================================================================

ChatWidget* ConnectionDialog::takeChatWidget()
{
    ChatWidget *widget = m_chatWidget;
    m_chatWidget = nullptr; // Transfer ownership
    return widget;
}
