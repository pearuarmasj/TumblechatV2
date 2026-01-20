#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QListWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>

class SessionBridge;

class ChatWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ChatWidget(QWidget *parent = nullptr);
    ~ChatWidget();

    // Connection state
    bool isConnected() const { return m_connected; }
    QString fingerprint() const { return m_fingerprint; }

    // For testing without Session integration yet
    void setConnected(bool connected, const QString &fingerprint = QString());

    // Set the session bridge (takes ownership)
    void setSessionBridge(SessionBridge *bridge);

    // Add a message to the display
    void addMessage(const QString &text, bool fromSelf, quint64 timestamp = 0);

signals:
    void connected(const QString &fingerprint);
    void disconnected();
    void messageSent(const QString &text);
    void fingerprintChanged(const QString &newFingerprint);  // Emitted on rekey

private slots:
    void onSendClicked();
    void onReturnPressed();
    void onSessionMessageReceived(const QString &text, quint64 timestamp);
    void onSessionDisconnected();
    void onRekeyCompleted(const QString &newFingerprint);

private:
    void setupUi();
    void applyStyles();
    QString formatTimestamp(quint64 timestamp);

    QVBoxLayout *m_mainLayout;
    QLabel *m_statusLabel;
    QListWidget *m_messageList;
    QHBoxLayout *m_inputLayout;
    QLineEdit *m_inputEdit;
    QPushButton *m_sendBtn;

    bool m_connected = false;
    QString m_fingerprint;

    // Session bridge for encrypted communication
    SessionBridge *m_sessionBridge = nullptr;
};
