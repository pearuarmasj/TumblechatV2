#pragma once

#include <QMainWindow>
#include <QListWidgetItem>
#include <QMap>

QT_BEGIN_NAMESPACE
namespace Ui {
    class MainWindow;
}
QT_END_NAMESPACE

class ChatWidget;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onNewConnection();
    void onContactSelected(QListWidgetItem *current, QListWidgetItem *previous);
    void onAbout();

    // Called when a chat's connection state changes
    void onChatConnected(ChatWidget *chat, const QString &fingerprint);
    void onChatDisconnected(ChatWidget *chat);
    void onFingerprintChanged(ChatWidget *chat, const QString &newFingerprint);

private:
    void addChatTab(ChatWidget *chat, const QString &displayName);
    void updateContactStatus(ChatWidget *chat, bool connected);
    void setupConnections();

    Ui::MainWindow *ui;
    QMap<QListWidgetItem*, ChatWidget*> m_contactToChat;
    QMap<ChatWidget*, QListWidgetItem*> m_chatToContact;
};
