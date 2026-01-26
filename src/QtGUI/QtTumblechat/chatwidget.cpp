#include "chatwidget.h"
#include "sessionbridge.h"
#include <QDateTime>
#include <QScrollBar>
#include <QFileDialog>
#include <QImage>
#include <QBuffer>
#include <QMessageBox>
#include <QMimeDatabase>
#include <QPixmap>

ChatWidget::ChatWidget(QWidget *parent)
    : QWidget(parent)
{
    setupUi();
    applyStyles();

    connect(m_sendBtn, &QPushButton::clicked, this, &ChatWidget::onSendClicked);
    connect(m_inputEdit, &QLineEdit::returnPressed, this, &ChatWidget::onReturnPressed);
    connect(m_imageBtn, &QPushButton::clicked, this, &ChatWidget::onImageClicked);
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

    m_imageBtn = new QPushButton();
    m_imageBtn->setIcon(QIcon::fromTheme("insert-image", QIcon(":/icons/image.png")));
    m_imageBtn->setToolTip("Send Image");
    m_imageBtn->setFixedSize(40, 40);
    m_imageBtn->setEnabled(false);
    m_inputLayout->insertWidget(0, m_imageBtn); // Insert before input field

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

    // Image button
    m_imageBtn->setStyleSheet(
        "QPushButton {"
        "  background-color: #2d2d44;"
        "  border: none;"
        "  border-radius: 4px;"
        "}"
        "QPushButton:hover {"
        "  background-color: #3d3d54;"
        "}"
        "QPushButton:disabled {"
        "  background-color: #1a1a2e;"
        "}"
    );
}

void ChatWidget::setConnected(bool connected, const QString &fingerprint)
{
    m_connected = connected;
    m_fingerprint = fingerprint;

    m_sendBtn->setEnabled(connected);
    m_imageBtn->setEnabled(connected);
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

    // Encode as text message with protocol header
    QByteArray textBytes = text.toUtf8();
    QByteArray encoded;
    encoded.reserve(5 + textBytes.size());
    encoded.append(static_cast<char>(MSG_TYPE_TEXT));
    // MIME length = 0 for text
    encoded.append(4, '\0');
    encoded.append(textBytes);

    emit binaryMessageSent(encoded);

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
        connect(m_sessionBridge, &SessionBridge::binaryMessageReceived,
                this, &ChatWidget::onSessionBinaryMessageReceived);
        connect(m_sessionBridge, &SessionBridge::disconnected,
                this, &ChatWidget::onSessionDisconnected);
        connect(m_sessionBridge, &SessionBridge::rekeyCompleted,
                this, &ChatWidget::onRekeyCompleted);

        // Connect our send signal to session
        connect(this, &ChatWidget::messageSent,
                m_sessionBridge, &SessionBridge::sendMessage);

        connect(this, &ChatWidget::binaryMessageSent,
                m_sessionBridge, &SessionBridge::sendBinaryMessage);
    }
}

void ChatWidget::onSessionMessageReceived(const QString &text, quint64 timestamp)
{
    addMessage(text, false, timestamp);
}

void ChatWidget::onSessionBinaryMessageReceived(const QByteArray &data, quint64 timestamp)
{
    auto [type, mimeType, payload] = decodeMessage(data);

    if (type == MSG_TYPE_IMAGE) {
        addImageMessage(payload, mimeType, false, timestamp);
    } else {
        QString text = QString::fromUtf8(payload);
        addMessage(text, false, timestamp);
    }
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

void ChatWidget::onImageClicked()
{
    QString filter = "Images (*.png *.jpg *.jpeg *.gif *.bmp *.webp);;All Files (*)";
    QString path = QFileDialog::getOpenFileName(this, "Select Image", QString(), filter);

    if (path.isEmpty()) return;

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }

    QByteArray imageData = file.readAll();
    file.close();

    // Check size (4MB limit minus protocol overhead)
    constexpr qint64 MAX_SIZE = 4000 * 1024 - 256;
    if (imageData.size() > MAX_SIZE) {
        QMessageBox::warning(this, "Image Too Large",
            QString("Image is %1 MB. Maximum is ~4 MB.")
                .arg(imageData.size() / (1024.0 * 1024.0), 0, 'f', 1));
        return;
    }

    // Detect MIME type
    QMimeDatabase mimeDb;
    QMimeType mime = mimeDb.mimeTypeForFile(path);
    QString mimeType = mime.name();

    // Encode message
    QByteArray encoded = encodeImageMessage(imageData, mimeType);

    // Display locally
    addImageMessage(imageData, mimeType, true, QDateTime::currentMSecsSinceEpoch());

    // Send via session bridge
    emit binaryMessageSent(encoded);
}

QByteArray ChatWidget::encodeImageMessage(const QByteArray &imageData, const QString &mimeType)
{
    QByteArray msg;
    msg.reserve(1 + 4 + mimeType.size() + imageData.size());

    // Type marker
    msg.append(static_cast<char>(MSG_TYPE_IMAGE));

    // MIME type length (4 bytes big-endian)
    uint32_t mimeLen = static_cast<uint32_t>(mimeType.toUtf8().size());
    msg.append(static_cast<char>((mimeLen >> 24) & 0xFF));
    msg.append(static_cast<char>((mimeLen >> 16) & 0xFF));
    msg.append(static_cast<char>((mimeLen >> 8) & 0xFF));
    msg.append(static_cast<char>(mimeLen & 0xFF));

    // MIME type string
    msg.append(mimeType.toUtf8());

    // Image data
    msg.append(imageData);

    return msg;
}

std::tuple<uint8_t, QString, QByteArray> ChatWidget::decodeMessage(const QByteArray &data)
{
    if (data.isEmpty()) {
        return {MSG_TYPE_TEXT, QString(), QByteArray()};
    }

    if (data.size() < 5) {
        // Too small for protocol header, treat as legacy text
        return {MSG_TYPE_TEXT, QString(), data};
    }

    uint8_t type = static_cast<uint8_t>(data[0]);

    // Check if first byte is a valid type marker
    if (type != MSG_TYPE_TEXT && type != MSG_TYPE_IMAGE) {
        // Legacy message - no protocol header, just text
        return {MSG_TYPE_TEXT, QString(), data};
    }

    if (type == MSG_TYPE_TEXT) {
        // Text message: type(1) + mimeLen(4) should be 0 + actual text
        uint32_t mimeLen = (static_cast<uint8_t>(data[1]) << 24) |
                          (static_cast<uint8_t>(data[2]) << 16) |
                          (static_cast<uint8_t>(data[3]) << 8) |
                          static_cast<uint8_t>(data[4]);
        if (mimeLen == 0) {
            return {MSG_TYPE_TEXT, QString(), data.mid(5)};
        }
    }
    else if (type == MSG_TYPE_IMAGE) {
        uint32_t mimeLen = (static_cast<uint8_t>(data[1]) << 24) |
                          (static_cast<uint8_t>(data[2]) << 16) |
                          (static_cast<uint8_t>(data[3]) << 8) |
                          static_cast<uint8_t>(data[4]);

        if (data.size() < 5 + static_cast<int>(mimeLen)) {
            return {MSG_TYPE_TEXT, QString(), data}; // Invalid, treat as text
        }

        QString mimeType = QString::fromUtf8(data.mid(5, mimeLen));
        QByteArray imageData = data.mid(5 + mimeLen);

        return {MSG_TYPE_IMAGE, mimeType, imageData};
    }

    // Malformed text message (non-zero mimeLen) - treat as legacy plain text
    return {MSG_TYPE_TEXT, QString(), data};
}

void ChatWidget::addImageMessage(const QByteArray &imageData, const QString &mimeType, bool fromSelf, quint64 timestamp)
{
    Q_UNUSED(mimeType);

    QString timeStr = formatTimestamp(timestamp);
    QString prefix = fromSelf ? "You" : "Peer";

    // Create pixmap from image data
    QPixmap pixmap;
    if (!pixmap.loadFromData(imageData)) {
        // Failed to load image, show error
        addMessage("[Failed to load image]", fromSelf, timestamp);
        return;
    }

    // Scale if too large (max 300x300 for thumbnail)
    if (pixmap.width() > 300 || pixmap.height() > 300) {
        pixmap = pixmap.scaled(300, 300, Qt::KeepAspectRatio, Qt::SmoothTransformation);
    }

    // Create a widget to hold the image
    QWidget *container = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(container);
    layout->setContentsMargins(8, 8, 8, 8);

    // Header with time and sender
    QLabel *header = new QLabel(QString("[%1] %2:").arg(timeStr, prefix));
    header->setStyleSheet("color: #888; font-size: 11px;");
    layout->addWidget(header);

    // Image label
    QLabel *imageLabel = new QLabel();
    imageLabel->setPixmap(pixmap);
    imageLabel->setStyleSheet("border-radius: 4px;");
    layout->addWidget(imageLabel);

    // Set background based on sender
    if (fromSelf) {
        container->setStyleSheet("background-color: #0f3460; border-radius: 8px;");
    } else {
        container->setStyleSheet("background-color: #1a1a2e; border-radius: 8px;");
    }

    // Calculate proper size for the item based on image + header + margins
    int width = pixmap.width() + 16;  // 8px margin each side
    int height = pixmap.height() + 30 + 16;  // header ~30px + 8px margin each side

    // Add to list widget
    QListWidgetItem *item = new QListWidgetItem();
    item->setSizeHint(QSize(width, height));
    m_messageList->addItem(item);
    m_messageList->setItemWidget(item, container);

    m_messageList->scrollToBottom();
}
