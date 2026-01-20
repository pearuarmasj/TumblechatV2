#pragma once

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QGroupBox>
#include <QRadioButton>
#include <QButtonGroup>
#include <memory>

class ChatWidget;
class StunWorker;
class SessionBridge;

class ConnectionDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ConnectionDialog(QWidget *parent = nullptr);
    ~ConnectionDialog();

    // After successful connection, take ownership of the ChatWidget
    ChatWidget* takeChatWidget();

    QString peerFingerprint() const { return m_peerFingerprint; }

private slots:
    void onStunQuery();
    void onCopyEndpoint();
    void onHolePunch();
    void onConnect();

    // StunWorker slots
    void onStunComplete(const QString &endpoint);
    void onStunFailed(const QString &error);
    void onPunchProgress(const QString &status);
    void onPunchComplete(qintptr socketHandle);
    void onPunchFailed(const QString &error);

    // Session slots
    void onSessionConnected(const QString &fingerprint);
    void onSessionError(int error, const QString &detail);

private:
    void setupUi();
    void applyStyles();
    void appendLog(const QString &message);
    void setStep(int step);

    // UI elements
    QVBoxLayout *m_mainLayout;

    // Step 1: STUN discovery
    QGroupBox *m_stunGroup;
    QPushButton *m_stunBtn;
    QLabel *m_yourEndpointLabel;
    QLineEdit *m_yourEndpoint;
    QPushButton *m_copyBtn;

    // Step 2: Peer endpoint
    QGroupBox *m_peerGroup;
    QLineEdit *m_peerEndpoint;

    // Step 3: Hole punch
    QGroupBox *m_punchGroup;
    QPushButton *m_punchBtn;

    // Protocol selection (between step 3 and 4)
    QGroupBox *m_protocolGroup;
    QRadioButton *m_tcpRadio;
    QRadioButton *m_udpRadio;

    // Step 4: Role selection
    QGroupBox *m_roleGroup;
    QRadioButton *m_initiatorRadio;
    QRadioButton *m_responderRadio;

    // Step 4: Connect
    QPushButton *m_connectBtn;

    // Log area
    QTextEdit *m_logArea;

    // Button box
    QHBoxLayout *m_buttonLayout;
    QPushButton *m_cancelBtn;

    // State
    int m_currentStep = 0;
    bool m_stunComplete = false;
    bool m_punchComplete = false;
    QString m_peerFingerprint;
    qintptr m_socketHandle = 0;

    // Workers
    std::unique_ptr<StunWorker> m_stunWorker;
    std::unique_ptr<SessionBridge> m_sessionBridge;

    // Result
    ChatWidget *m_chatWidget = nullptr;
};
