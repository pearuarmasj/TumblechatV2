#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "chatwidget.h"
#include "connectiondialog.h"

#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setupConnections();

    // Set dark theme for whole window
    setStyleSheet("QMainWindow { background-color: #0f0f1a; }");

    statusBar()->showMessage("Ready - Click 'New Connection' to start");
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setupConnections()
{
    // Menu actions
    connect(ui->actionNewConnection, &QAction::triggered, this, &MainWindow::onNewConnection);
    connect(ui->actionExit, &QAction::triggered, this, &QWidget::close);
    connect(ui->actionAbout, &QAction::triggered, this, &MainWindow::onAbout);

    // Sidebar button
    connect(ui->newConnectionBtn, &QPushButton::clicked, this, &MainWindow::onNewConnection);

    // Contact list selection
    connect(ui->contactList, &QListWidget::currentItemChanged,
            this, &MainWindow::onContactSelected);
}

void MainWindow::onNewConnection()
{
    ConnectionDialog dialog(this);

    if (dialog.exec() == QDialog::Accepted) {
        // Dialog succeeded - it gives us a connected ChatWidget
        ChatWidget *chat = dialog.takeChatWidget();
        if (chat) {
            QString displayName = dialog.peerFingerprint();
            if (displayName.length() > 16) {
                displayName = displayName.left(16) + "...";
            }
            addChatTab(chat, displayName);

            statusBar()->showMessage("Connected to peer: " + dialog.peerFingerprint());
        }
    }
}

void MainWindow::addChatTab(ChatWidget *chat, const QString &displayName)
{
    // Add to stacked widget
    int index = ui->chatStack->addWidget(chat);
    ui->chatStack->setCurrentIndex(index);

    // Add to contact list
    QListWidgetItem *item = new QListWidgetItem(displayName);
    item->setData(Qt::UserRole, QVariant::fromValue(reinterpret_cast<quintptr>(chat)));
    ui->contactList->addItem(item);
    ui->contactList->setCurrentItem(item);

    // Track mappings
    m_contactToChat[item] = chat;
    m_chatToContact[chat] = item;

    // Connect chat signals
    connect(chat, &ChatWidget::connected, this, [this, chat](const QString &fp) {
        onChatConnected(chat, fp);
    });
    connect(chat, &ChatWidget::disconnected, this, [this, chat]() {
        onChatDisconnected(chat);
    });
    connect(chat, &ChatWidget::fingerprintChanged, this, [this, chat](const QString &fp) {
        onFingerprintChanged(chat, fp);
    });
}

void MainWindow::onContactSelected(QListWidgetItem *current, QListWidgetItem *previous)
{
    Q_UNUSED(previous);

    if (!current) return;

    ChatWidget *chat = m_contactToChat.value(current, nullptr);
    if (chat) {
        ui->chatStack->setCurrentWidget(chat);
    }
}

void MainWindow::onChatConnected(ChatWidget *chat, const QString &fingerprint)
{
    updateContactStatus(chat, true);
    statusBar()->showMessage("Connected: " + fingerprint);
}

void MainWindow::onChatDisconnected(ChatWidget *chat)
{
    updateContactStatus(chat, false);
    statusBar()->showMessage("Disconnected");
}

void MainWindow::onFingerprintChanged(ChatWidget *chat, const QString &newFingerprint)
{
    // Update contact list item text
    QListWidgetItem *item = m_chatToContact.value(chat, nullptr);
    if (item) {
        QString displayName = newFingerprint;
        if (displayName.length() > 16) {
            displayName = displayName.left(16) + "...";
        }
        item->setText(displayName);
    }

    // Update status bar if this is the active chat
    if (ui->chatStack->currentWidget() == chat) {
        statusBar()->showMessage("Connected to peer: " + newFingerprint);
    }
}

void MainWindow::updateContactStatus(ChatWidget *chat, bool connected)
{
    QListWidgetItem *item = m_chatToContact.value(chat, nullptr);
    if (!item) return;

    if (connected) {
        item->setForeground(QBrush(QColor("#4ade80"))); // Green
    } else {
        item->setForeground(QBrush(QColor("#6b7280"))); // Grey
    }
}

void MainWindow::onAbout()
{
    QMessageBox::about(this, "About Tumblechat",
        "Tumblechat v2\n\n"
        "P2P encrypted messaging with post-quantum cryptography.\n\n"
        "X25519 + ML-KEM-768 hybrid key exchange\n"
        "AES-256-GCM encryption\n"
        "60-second automatic rekeying");
}
