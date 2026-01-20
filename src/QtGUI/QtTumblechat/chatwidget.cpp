#include "chatwidget.h"
#include "sessionbridge.h"
#include <QDateTime>
#include <QScrollBar>

ChatWidget::ChatWidget(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
    applyStyles();

    connect(m_sendBtn, &QPushButton::clicked, this, &ChatWidget::onSendClicked);
    connect(m_inputEdit, &QLineEdit::returnPressed, this, &ChatWidget::onReturnPressed);
}

ChatWidget::~ChatWidget()
{
    // SessionBridge is a child QObject, will be cleaned up automatically
    // But explicitly disconnect to be safe
    if (m_sessionBridge) {
        m_sessionBridge->disconnect();
    }
}

void ChatWidget::setupUi()
{
    m_mainLayout = new QVBoxLayout(this);
    m_mainLayout->setContentsMargins(0, 0, 0, 0);
    m_mainLayout->setSpacing(0);

    // Status bar at top
    m_statusLabel = new QLabel("Disconnected");
    m_statusLabel->setAlignment(Qt::AlignCenter);
    m_mainLayout->addWidget(m_statusLabel);

    // Message list (takes most space)
    m_messageList = new QListWidget();
    m_messageList->setWordWrap(true);
    m_messageList->setSpacing(4);
    m_mainLayout->addWidget(m_messageList, 1); // stretch factor 1

    // Input area at bottom
    QWidget *inputContainer = new QWidget();
    m_inputLayout = new QHBoxLayout(inputContainer);
    m_inputLayout->setContentsMargins(8, 8, 8, 8);

    m_inputEdit = new QLineEdit();
    m_inputEdit->setPlaceholderText("Type a message...");
    m_inputLayout->addWidget(m_inputEdit, 1);

    m_sendBtn = new QPushButton("Send");
    m_sendBtn->setEnabled(false); // Disabled until connected
    m_inputLayout->addWidget(m_sendBtn);

    m_mainLayout->addWidget(inputContainer);
}

void ChatWidget::applyStyles()
{
    // Status label
    m_statusLabel->setStyleSheet(
        "QLabel {"
        "  background-color: #1a1a2e;"
        "  color: #6b7280;"
        "  padding: 8px;"
        "  font-size: 12px;"
        "}"
    );

    // Message list
    m_messageList->setStyleSheet(
        "QListWidget {"
        "  background-color: #0f0f1a;"
        "  border: none;"
        "  padding: 8px;"
        "}"
        "QListWidget::item {"
        "  background-color: #1a1a2e;"
        "  border-radius: 8px;"
        "  padding: 8px 12px;"
        "  margin: 4px 0;"
        "  color: #eee;"
        "}"
    );

    // Input field
    m_inputEdit->setStyleSheet(
        "QLineEdit {"
        "  background-color: #1a1a2e;"
        "  border: 1px solid #2d2d44;"
        "  border-radius: 4px;"
        "  padding: 10px;"
        "  color: #eee;"
        "  font-size: 14px;"
        "}"
        "QLineEdit:focus {"
        "  border-color: #0f3460;"
        "}"
    );

    // Send button
    m_sendBtn->setStyleSheet(
        "QPushButton {"
        "  background-color: #0f3460;"
        "  color: white;"
        "  border: none;"
        "  border-radius: 4px;"
        "  padding: 10px 20px;"
        "  font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "  background-color: #1a4f7a;"
        "}"
        "QPushButton:pressed {"
        "  background-color: #0a2540;"
        "}"
        "QPushButton:disabled {"
        "  background-color: #2d2d44;"
        "  color: #6b7280;"
        "}"
    );
}

void ChatWidget::setConnected(bool connected, const QString &fingerprint)
{
    m_connected = connected;
    m_fingerprint = fingerprint;

    m_sendBtn->setEnabled(connected);
    m_inputEdit->setEnabled(connected);

    if (connected) {
        QString shortFp = fingerprint.left(16);
        m_statusLabel->setText("Connected: " + shortFp + "...");
        m_statusLabel->setStyleSheet(
            "QLabel {"
            "  background-color: #0f3460;"
            "  color: #4ade80;"
            "  padding: 8px;"
            "  font-size: 12px;"
            "}"
        );
        emit this->connected(fingerprint);
    } else {
        m_statusLabel->setText("Disconnected");
        m_statusLabel->setStyleSheet(
            "QLabel {"
            "  background-color: #1a1a2e;"
            "  color: #6b7280;"
            "  padding: 8px;"
            "  font-size: 12px;"
            "}"
        );
        emit disconnected();
    }
}

void ChatWidget::addMessage(const QString &text, bool fromSelf, quint64 timestamp)
{
    QString timeStr = formatTimestamp(timestamp);
    QString prefix = fromSelf ? "You" : "Peer";
    QString display = QString("[%1] %2: %3").arg(timeStr, prefix, text);

    QListWidgetItem *item = new QListWidgetItem(display);

    // Different alignment for self vs peer
    if (fromSelf) {
        item->setTextAlignment(Qt::AlignRight);
        item->setBackground(QBrush(QColor("#0f3460")));
    } else {
        item->setTextAlignment(Qt::AlignLeft);
        item->setBackground(QBrush(QColor("#1a1a2e")));
    }

    m_messageList->addItem(item);

    // Auto-scroll to bottom
    m_messageList->scrollToBottom();
}

void ChatWidget::onSendClicked()
{
    QString text = m_inputEdit->text().trimmed();
    if (text.isEmpty()) return;

    // Display locally
    quint64 now = QDateTime::currentMSecsSinceEpoch();
    addMessage(text, true, now);

    // Signal for actual sending (Session will handle this)
    emit messageSent(text);

    m_inputEdit->clear();
    m_inputEdit->setFocus();
}

void ChatWidget::onReturnPressed()
{
    onSendClicked();
}

QString ChatWidget::formatTimestamp(quint64 timestamp)
{
    if (timestamp == 0) {
        timestamp = QDateTime::currentMSecsSinceEpoch();
    }
    QDateTime dt = QDateTime::fromMSecsSinceEpoch(timestamp);
    return dt.toString("HH:mm:ss");
}

void ChatWidget::setSessionBridge(SessionBridge *bridge)
{
    // Clean up old bridge if any
    if (m_sessionBridge) {
        m_sessionBridge->disconnect();
        m_sessionBridge->deleteLater();
    }

    m_sessionBridge = bridge;

    if (m_sessionBridge) {
        // Reparent to this widget
        m_sessionBridge->setParent(this);

        // Connect session signals
        connect(m_sessionBridge, &SessionBridge::messageReceived,
                this, &ChatWidget::onSessionMessageReceived);
        connect(m_sessionBridge, &SessionBridge::disconnected,
                this, &ChatWidget::onSessionDisconnected);
        connect(m_sessionBridge, &SessionBridge::rekeyCompleted,
                this, &ChatWidget::onRekeyCompleted);

        // Connect our send signal to session
        connect(this, &ChatWidget::messageSent,
                m_sessionBridge, &SessionBridge::sendMessage);
    }
}

void ChatWidget::onSessionMessageReceived(const QString &text, quint64 timestamp)
{
    addMessage(text, false, timestamp);
}

void ChatWidget::onSessionDisconnected()
{
    setConnected(false);
}

void ChatWidget::onRekeyCompleted(const QString &newFingerprint)
{
    // Update fingerprint after 60-second key rotation
    m_fingerprint = newFingerprint;
    QString shortFp = newFingerprint.left(16);
    m_statusLabel->setText("Connected: " + shortFp + "...");

    // Notify MainWindow to update contact list and status bar
    emit fingerprintChanged(newFingerprint);
}
