// =============================================================================
// gui_client_v2.cpp - Clean, modular P2P encrypted messaging client
// =============================================================================

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <shobjidl.h>

#include <string>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>

#include "src/core/types.h"
#include "src/core/logger.h"
#include "src/network/socket_wrapper.h"
#include "src/session/session.h"
#include "src/session/connection_manager.h"
#include "src/network/udp_hole_punch.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "cryptlib.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")

using namespace p2p;

// =============================================================================
// UI Constants
// =============================================================================
namespace ui {

// Control IDs
enum ControlId {
    IDC_HOST        = 1001,
    IDC_LPORT       = 1002,
    IDC_CPORT       = 1003,
    IDC_HMAC        = 1004,
    IDC_LISTENONLY  = 1005,
    IDC_CONNECTONLY = 1006,
    IDC_AUTOMAP     = 1007,
    IDC_STUN        = 1008,
    IDC_START       = 1009,
    IDC_STOP        = 1010,
    IDC_LOG         = 1011,
    IDC_INPUT       = 1012,
    IDC_SEND        = 1013,
    IDC_STATUS      = 1014,
    IDC_PEERINFO    = 1015,
    // UDP Hole Punch
    IDC_MY_ENDPOINT   = 1016,
    IDC_PEER_ENDPOINT = 1017,
    IDC_HOLEPUNCH     = 1018,
    IDC_COPY_ENDPOINT = 1019
};

// Layout constants
constexpr int MARGIN        = 10;
constexpr int ROW_HEIGHT    = 24;
constexpr int LABEL_WIDTH   = 70;
constexpr int PORT_WIDTH    = 60;
constexpr int CHECK_WIDTH   = 90;
constexpr int BUTTON_WIDTH  = 70;

// Timer
constexpr UINT_PTR TIMER_REFRESH = 1;
constexpr UINT REFRESH_INTERVAL  = 100;  // ms

// Custom messages
constexpr UINT WM_STUN_COMPLETE = WM_USER + 1;

} // namespace ui

// =============================================================================
// Application State
// =============================================================================
class Application {
public:
    static Application& instance() {
        static Application s_instance;
        return s_instance;
    }
    
    // Initialize
    bool initialize() {
        // Initialize Winsock
        if (!WinsockInit::instance().isInitialized()) {
            MessageBoxA(nullptr, WinsockInit::instance().error().c_str(), 
                       "Initialization Error", MB_ICONERROR);
            return false;
        }
        
        // Setup logging callback
        Logger::instance().setCallback([this](LogLevel, const std::string&) {
            // UI will poll for new entries
        });
        
        LOG_INFO("Application initialized");
        return true;
    }
    
    // Shutdown
    void shutdown() {
        stop();
        LOG_INFO("Application shutdown");
    }
    
    // Start connection
    bool start(const ConnectionConfig& config) {
        if (m_connectionManager) {
            stop();
        }
        
        m_connectionManager = std::make_unique<ConnectionManager>();
        
        m_connectionManager->onSessionReady([this](std::shared_ptr<Session> session) {
            std::lock_guard<std::mutex> lock(m_sessionMutex);
            m_session = session;
            
            m_session->onMessage([this](const std::string& msg, uint64_t timestamp) {
                LOG_INFO(formatTimestamp(timestamp) + " Peer: " + msg);
            });
            
            m_session->onStateChange([](ConnectionState state) {
                LOG_INFO(std::string("State: ") + ConnectionStateName(state));
            });
            
            m_session->onError([](SessionError err, const std::string& detail) {
                LOG_ERROR(std::string(SessionErrorName(err)) + ": " + detail);
            });
        });
        
        m_connectionManager->onError([](const std::string& error) {
            LOG_ERROR(error);
        });
        
        auto result = m_connectionManager->start(config);
        if (!result) {
            LOG_ERROR("Start failed: " + result.error());
            m_connectionManager.reset();
            return false;
        }
        
        m_running = true;
        return true;
    }
    
    // Stop connection
    void stop() {
        m_running = false;
        
        {
            std::lock_guard<std::mutex> lock(m_sessionMutex);
            if (m_session) {
                m_session->stop();
                m_session.reset();
            }
        }
        
        if (m_connectionManager) {
            m_connectionManager->stop();
            m_connectionManager.reset();
        }
    }
    
    // Send message
    bool send(const std::string& message) {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        
        if (!m_session || !m_session->isReady()) {
            return false;
        }
        
        auto result = m_session->send(message);
        if (!result) {
            LOG_ERROR("Send failed: " + result.error());
            return false;
        }
        
        LOG_INFO(Logger::timestamp() + " You: " + message);
        return true;
    }
    
    // Query STUN
    void queryStun() {
        if (!m_connectionManager) {
            m_connectionManager = std::make_unique<ConnectionManager>();
        }
        
        auto result = m_connectionManager->queryStun();
        if (result) {
            LOG_INFO("External address: " + result.value().ip + ":" + 
                     std::to_string(result.value().port));
        } else {
            LOG_ERROR("STUN query failed: " + result.error());
        }
    }
    
    // State queries
    bool isRunning() const { return m_running; }
    
    ConnectionState connectionState() const {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        return m_session ? m_session->state() : ConnectionState::Disconnected;
    }
    
    std::string peerFingerprint() const {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        return m_session ? m_session->peerFingerprint() : "";
    }

private:
    Application() = default;
    
    static std::string formatTimestamp(uint64_t ms) {
        time_t sec = static_cast<time_t>(ms / 1000);
        uint64_t rem = ms % 1000;
        
        tm t{};
        localtime_s(&t, &sec);
        
        char buf[32];
        snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d", 
                 t.tm_hour, t.tm_min, t.tm_sec, static_cast<int>(rem));
        return buf;
    }
    
    mutable std::mutex                    m_sessionMutex;
    std::shared_ptr<Session>              m_session;
    std::unique_ptr<ConnectionManager>    m_connectionManager;
    std::atomic<bool>                     m_running{false};
};

// =============================================================================
// Main Window
// =============================================================================
class MainWindow {
public:
    MainWindow() = default;
    
    bool create(HINSTANCE hInstance) {
        m_hInstance = hInstance;
        
        // Register window class
        WNDCLASSEXW wc{};
        wc.cbSize        = sizeof(wc);
        wc.style         = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc   = windowProc;
        wc.hInstance     = hInstance;
        wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        wc.lpszClassName = L"TumblechatWindow";
        
        if (!RegisterClassExW(&wc)) {
            return false;
        }
        
        // Create window
        m_hwnd = CreateWindowExW(
            0,
            L"TumblechatWindow",
            L"Tumblechat",
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT,
            1140, 520,
            nullptr, nullptr, hInstance, this);
        
        return m_hwnd != nullptr;
    }
    
    void show(int nCmdShow = SW_SHOW) {
        ShowWindow(m_hwnd, nCmdShow);
        UpdateWindow(m_hwnd);
    }
    
    int messageLoop() {
        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0) > 0) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        return static_cast<int>(msg.wParam);
    }

private:
    // -------------------------------------------------------------------------
    // Window Procedure
    // -------------------------------------------------------------------------
    static LRESULT CALLBACK windowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        MainWindow* self;
        
        if (msg == WM_NCCREATE) {
            auto cs = reinterpret_cast<CREATESTRUCT*>(lParam);
            self = static_cast<MainWindow*>(cs->lpCreateParams);
            self->m_hwnd = hwnd;
            SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        } else {
            self = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
        }
        
        if (self) {
            return self->handleMessage(msg, wParam, lParam);
        }
        
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    
    LRESULT handleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
        case WM_CREATE:
            createControls();
            SetTimer(m_hwnd, ui::TIMER_REFRESH, ui::REFRESH_INTERVAL, nullptr);
            return 0;
            
        case WM_TIMER:
            if (wParam == ui::TIMER_REFRESH) {
                refreshUI();
            }
            return 0;
            
        case WM_COMMAND:
            handleCommand(LOWORD(wParam), HIWORD(wParam));
            return 0;
            
        case WM_SIZE:
            layoutControls();
            return 0;
            
        case WM_CLOSE:
            DestroyWindow(m_hwnd);
            return 0;
            
        case WM_DESTROY:
            KillTimer(m_hwnd, ui::TIMER_REFRESH);
            // Clean up STUN thread
            if (m_stunThread.joinable()) {
                m_stunThread.join();
            }
            PostQuitMessage(0);
            return 0;

        default:
            // Handle custom messages
            if (msg == ui::WM_STUN_COMPLETE) {
                onStunComplete();
                return 0;
            }
            return DefWindowProc(m_hwnd, msg, wParam, lParam);
        }
    }
    
    // -------------------------------------------------------------------------
    // Control Creation
    // -------------------------------------------------------------------------
    void createControls() {
        HFONT hFont = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
        
        // Row 1: Connection settings
        createStatic("Peer Host:", 0);
        m_hHost = createEdit("127.0.0.1", ui::IDC_HOST);
        
        createStatic("Listen:", 1);
        m_hLPort = createEdit("27015", ui::IDC_LPORT);
        
        createStatic("Connect:", 2);
        m_hCPort = createEdit("27015", ui::IDC_CPORT);
        
        m_hHmac = createCheckbox("HMAC", ui::IDC_HMAC);
        SendMessage(m_hHmac, BM_SETCHECK, BST_CHECKED, 0);
        
        m_hListenOnly = createCheckbox("Listen Only", ui::IDC_LISTENONLY);
        m_hConnectOnly = createCheckbox("Connect Only", ui::IDC_CONNECTONLY);
        m_hAutoMap = createCheckbox("Auto-map", ui::IDC_AUTOMAP);
        
        m_hStunBtn = createButton("STUN Query", ui::IDC_STUN);
        m_hStartBtn = createButton("Start", ui::IDC_START);
        m_hStopBtn = createButton("Stop", ui::IDC_STOP);
        
        // Row 2: UDP Hole Punch
        m_hLblMyEndpoint = createStatic("My Endpoint:", 3);
        m_hMyEndpoint = createEdit("", ui::IDC_MY_ENDPOINT);
        EnableWindow(m_hMyEndpoint, FALSE); // Read-only display
        
        m_hCopyEndpoint = createButton("Copy", ui::IDC_COPY_ENDPOINT);
        
        m_hLblPeerEndpoint = createStatic("Peer Host:", 4);
        m_hPeerEndpoint = createEdit("", ui::IDC_PEER_ENDPOINT);
        
        m_hHolePunchBtn = createButton("Hole Punch", ui::IDC_HOLEPUNCH);
        
        // Log area
        m_hLog = CreateWindowExA(
            WS_EX_CLIENTEDGE,
            "EDIT",
            "",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
            0, 0, 100, 100,
            m_hwnd,
            reinterpret_cast<HMENU>(ui::IDC_LOG),
            m_hInstance,
            nullptr);
        SendMessage(m_hLog, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);
        
        // Input row
        m_hInput = CreateWindowExA(
            WS_EX_CLIENTEDGE,
            "EDIT",
            "",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            0, 0, 100, ui::ROW_HEIGHT,
            m_hwnd,
            reinterpret_cast<HMENU>(ui::IDC_INPUT),
            m_hInstance,
            nullptr);
        SendMessage(m_hInput, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);
        
        // Subclass input for Enter key
        SetWindowSubclass(m_hInput, inputSubclassProc, 1, reinterpret_cast<DWORD_PTR>(this));
        
        m_hSendBtn = createButton("Send", ui::IDC_SEND);
        
        // Status bar
        m_hStatus = CreateWindowExA(
            0,
            "STATIC",
            "Idle",
            WS_CHILD | WS_VISIBLE,
            0, 0, 200, 20,
            m_hwnd,
            reinterpret_cast<HMENU>(ui::IDC_STATUS),
            m_hInstance,
            nullptr);
        SendMessage(m_hStatus, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);
        
        m_hPeerInfo = CreateWindowExA(
            0,
            "STATIC",
            "",
            WS_CHILD | WS_VISIBLE,
            0, 0, 400, 20,
            m_hwnd,
            reinterpret_cast<HMENU>(ui::IDC_PEERINFO),
            m_hInstance,
            nullptr);
        SendMessage(m_hPeerInfo, WM_SETFONT, reinterpret_cast<WPARAM>(hFont), TRUE);
        
        layoutControls();
    }
    
    HWND createStatic(const char* text, int) {
        HWND h = CreateWindowExA(
            0, "STATIC", text,
            WS_CHILD | WS_VISIBLE,
            0, 0, ui::LABEL_WIDTH, ui::ROW_HEIGHT,
            m_hwnd, nullptr, m_hInstance, nullptr);
        SendMessage(h, WM_SETFONT, 
            reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
        return h;
    }
    
    HWND createEdit(const char* text, int id) {
        HWND h = CreateWindowExA(
            WS_EX_CLIENTEDGE, "EDIT", text,
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            0, 0, 100, ui::ROW_HEIGHT,
            m_hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), m_hInstance, nullptr);
        SendMessage(h, WM_SETFONT, 
            reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
        return h;
    }
    
    HWND createButton(const char* text, int id) {
        HWND h = CreateWindowExA(
            0, "BUTTON", text,
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            0, 0, ui::BUTTON_WIDTH, ui::ROW_HEIGHT,
            m_hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), m_hInstance, nullptr);
        SendMessage(h, WM_SETFONT, 
            reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
        return h;
    }
    
    HWND createCheckbox(const char* text, int id) {
        HWND h = CreateWindowExA(
            0, "BUTTON", text,
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            0, 0, ui::CHECK_WIDTH, ui::ROW_HEIGHT,
            m_hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), m_hInstance, nullptr);
        SendMessage(h, WM_SETFONT, 
            reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
        return h;
    }
    
    // -------------------------------------------------------------------------
    // Layout
    // -------------------------------------------------------------------------
    void layoutControls() {
        RECT rc;
        GetClientRect(m_hwnd, &rc);
        
        int width = rc.right - rc.left;
        int height = rc.bottom - rc.top;
        
        int x = ui::MARGIN;
        int y = ui::MARGIN;
        
        // Row 1: Host
        SetWindowPos(GetDlgItem(m_hwnd, 0), nullptr, x, y + 3, ui::LABEL_WIDTH, 20, SWP_NOZORDER);
        x += ui::LABEL_WIDTH;
        SetWindowPos(m_hHost, nullptr, x, y, 180, ui::ROW_HEIGHT, SWP_NOZORDER);
        x += 185;
        
        // Listen port
        x += 10;
        SetWindowPos(GetDlgItem(m_hwnd, 0), nullptr, x, y + 3, 50, 20, SWP_NOZORDER);
        x += 55;
        SetWindowPos(m_hLPort, nullptr, x, y, ui::PORT_WIDTH, ui::ROW_HEIGHT, SWP_NOZORDER);
        x += ui::PORT_WIDTH + 10;
        
        // Connect port
        SetWindowPos(GetDlgItem(m_hwnd, 0), nullptr, x, y + 3, 55, 20, SWP_NOZORDER);
        x += 60;
        SetWindowPos(m_hCPort, nullptr, x, y, ui::PORT_WIDTH, ui::ROW_HEIGHT, SWP_NOZORDER);
        x += ui::PORT_WIDTH + 15;
        
        // Checkboxes
        SetWindowPos(m_hHmac, nullptr, x, y, 60, ui::ROW_HEIGHT, SWP_NOZORDER);
        x += 65;
        SetWindowPos(m_hListenOnly, nullptr, x, y, 85, ui::ROW_HEIGHT, SWP_NOZORDER);
        x += 90;
        SetWindowPos(m_hConnectOnly, nullptr, x, y, 95, ui::ROW_HEIGHT, SWP_NOZORDER);
        x += 100;
        SetWindowPos(m_hAutoMap, nullptr, x, y, 80, ui::ROW_HEIGHT, SWP_NOZORDER);
        x += 85;
        
        // Buttons
        SetWindowPos(m_hStunBtn, nullptr, x, y, 90, ui::ROW_HEIGHT, SWP_NOZORDER);
        x += 95;
        SetWindowPos(m_hStartBtn, nullptr, x, y, 55, ui::ROW_HEIGHT, SWP_NOZORDER);
        x += 60;
        SetWindowPos(m_hStopBtn, nullptr, x, y, 55, ui::ROW_HEIGHT, SWP_NOZORDER);
        
        // Row 2: UDP Hole Punch
        y += ui::ROW_HEIGHT + ui::MARGIN;
        x = ui::MARGIN;
        
        // My Endpoint label + field + Copy button
        SetWindowPos(m_hLblMyEndpoint, nullptr, x, y + 3, 85, 20, SWP_NOZORDER);
        x += 90;
        SetWindowPos(m_hMyEndpoint, nullptr, x, y, 160, ui::ROW_HEIGHT, SWP_NOZORDER);
        x += 165;
        SetWindowPos(m_hCopyEndpoint, nullptr, x, y, 50, ui::ROW_HEIGHT, SWP_NOZORDER);
        x += 60;
        
        // Peer Host label + field + Hole Punch button
        SetWindowPos(m_hLblPeerEndpoint, nullptr, x, y + 3, 70, 20, SWP_NOZORDER);
        x += 75;
        SetWindowPos(m_hPeerEndpoint, nullptr, x, y, 160, ui::ROW_HEIGHT, SWP_NOZORDER);
        x += 165;
        SetWindowPos(m_hHolePunchBtn, nullptr, x, y, 80, ui::ROW_HEIGHT, SWP_NOZORDER);
        
        // Log area
        y += ui::ROW_HEIGHT + ui::MARGIN;
        int logHeight = height - y - ui::ROW_HEIGHT - 30 - ui::MARGIN * 2;
        SetWindowPos(m_hLog, nullptr, ui::MARGIN, y, width - ui::MARGIN * 2, logHeight, SWP_NOZORDER);
        
        // Input row
        y += logHeight + ui::MARGIN;
        int inputWidth = width - ui::MARGIN * 3 - ui::BUTTON_WIDTH;
        SetWindowPos(m_hInput, nullptr, ui::MARGIN, y, inputWidth, ui::ROW_HEIGHT, SWP_NOZORDER);
        SetWindowPos(m_hSendBtn, nullptr, ui::MARGIN * 2 + inputWidth, y, 
                     ui::BUTTON_WIDTH, ui::ROW_HEIGHT, SWP_NOZORDER);
        
        // Status bar
        y += ui::ROW_HEIGHT + ui::MARGIN;
        SetWindowPos(m_hStatus, nullptr, ui::MARGIN, y, 200, 20, SWP_NOZORDER);
        SetWindowPos(m_hPeerInfo, nullptr, ui::MARGIN + 210, y, width - 230, 20, SWP_NOZORDER);
    }
    
    // -------------------------------------------------------------------------
    // Command Handling
    // -------------------------------------------------------------------------
    void handleCommand(int id, int notifyCode) {
        (void)notifyCode;
        
        switch (id) {
        case ui::IDC_LISTENONLY:
            if (SendMessage(m_hListenOnly, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                EnableWindow(m_hHost, FALSE);
                SetWindowTextA(m_hHost, "0.0.0.0");
            } else {
                EnableWindow(m_hHost, TRUE);
                SetWindowTextA(m_hHost, "127.0.0.1");
            }
            break;
            
        case ui::IDC_START:
            onStart();
            break;
            
        case ui::IDC_STOP:
            onStop();
            break;
            
        case ui::IDC_STUN:
            onStun();
            break;
            
        case ui::IDC_SEND:
            onSend();
            break;
            
        case ui::IDC_COPY_ENDPOINT:
            onCopyEndpoint();
            break;
            
        case ui::IDC_HOLEPUNCH:
            onHolePunch();
            break;
        }
    }
    
    void onStart() {
        ConnectionConfig config;
        
        char buf[256];
        GetWindowTextA(m_hHost, buf, sizeof(buf));
        config.remoteHost = buf;
        
        GetWindowTextA(m_hLPort, buf, sizeof(buf));
        config.listenPort = static_cast<uint16_t>(atoi(buf));
        
        GetWindowTextA(m_hCPort, buf, sizeof(buf));
        config.remotePort = static_cast<uint16_t>(atoi(buf));
        
        config.useHmac = SendMessage(m_hHmac, BM_GETCHECK, 0, 0) == BST_CHECKED;
        config.listenOnly = SendMessage(m_hListenOnly, BM_GETCHECK, 0, 0) == BST_CHECKED;
        config.connectOnly = SendMessage(m_hConnectOnly, BM_GETCHECK, 0, 0) == BST_CHECKED;
        config.autoMap = SendMessage(m_hAutoMap, BM_GETCHECK, 0, 0) == BST_CHECKED;
        
        // Validate
        if (config.listenOnly && config.connectOnly) {
            config.listenOnly = false;
            config.connectOnly = false;
        }
        
        if (config.listenOnly) {
            config.remoteHost = "0.0.0.0";
        }
        
        Application::instance().start(config);
    }
    
    void onStop() {
        Application::instance().stop();
        LOG_INFO("Stopped");
    }
    
    void onStun() {
        // Prevent multiple concurrent STUN queries
        if (m_stunPending.load()) {
            LOG_WARNING("STUN query already in progress");
            return;
        }

        // Get local port for STUN discovery
        char lportBuf[32];
        GetWindowTextA(m_hLPort, lportBuf, sizeof(lportBuf));
        uint16_t localPort = static_cast<uint16_t>(atoi(lportBuf));

        // Clean up previous thread if any
        if (m_stunThread.joinable()) {
            m_stunThread.join();
        }

        m_stunPending.store(true);
        LOG_INFO("Starting STUN query...");

        // Run STUN query in background thread
        HWND hwnd = m_hwnd;
        m_stunThread = std::thread([this, localPort, hwnd] {
            UdpHolePuncher puncher;
            auto result = puncher.discoverOnly(localPort);

            if (result) {
                m_stunResult = result.value().ip + ":" + std::to_string(result.value().port);
            } else {
                m_stunResult = "ERROR:" + result.error();
            }

            // Notify UI thread
            PostMessage(hwnd, ui::WM_STUN_COMPLETE, 0, 0);
        });
    }

    void onStunComplete() {
        m_stunPending.store(false);

        if (m_stunResult.rfind("ERROR:", 0) == 0) {
            LOG_ERROR("STUN query failed: " + m_stunResult.substr(6));
        } else {
            LOG_INFO("Your public endpoint: " + m_stunResult);
            SetWindowTextA(m_hMyEndpoint, m_stunResult.c_str());
        }
    }
    
    void onSend() {
        char buf[1024];
        GetWindowTextA(m_hInput, buf, sizeof(buf));
        
        if (buf[0]) {
            if (Application::instance().send(buf)) {
                SetWindowTextA(m_hInput, "");
            } else {
                LOG_WARNING("Send failed - not connected");
            }
        }
    }
    
    void onCopyEndpoint() {
        char buf[256];
        GetWindowTextA(m_hMyEndpoint, buf, sizeof(buf));
        
        if (buf[0] && OpenClipboard(m_hwnd)) {
            EmptyClipboard();
            size_t len = strlen(buf) + 1;
            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
            if (hMem) {
                memcpy(GlobalLock(hMem), buf, len);
                GlobalUnlock(hMem);
                SetClipboardData(CF_TEXT, hMem);
            }
            CloseClipboard();
            LOG_INFO("Endpoint copied to clipboard");
        }
    }
    
    void onHolePunch() {
        // Get peer endpoint from input
        char buf[256];
        GetWindowTextA(m_hPeerEndpoint, buf, sizeof(buf));
        
        std::string peerStr = buf;
        if (peerStr.empty()) {
            LOG_ERROR("Enter peer endpoint (ip:port)");
            return;
        }
        
        // Parse ip:port
        auto colonPos = peerStr.rfind(':');
        if (colonPos == std::string::npos) {
            LOG_ERROR("Invalid endpoint format. Use ip:port");
            return;
        }
        
        std::string peerIp = peerStr.substr(0, colonPos);
        uint16_t peerPort = static_cast<uint16_t>(std::stoi(peerStr.substr(colonPos + 1)));
        
        // Get local port from listen port field
        char lportBuf[32];
        GetWindowTextA(m_hLPort, lportBuf, sizeof(lportBuf));
        uint16_t localPort = static_cast<uint16_t>(atoi(lportBuf));
        
        LOG_INFO("Starting UDP hole punch to " + peerIp + ":" + std::to_string(peerPort));
        
        // Create and start hole puncher
        stun::Endpoint peerEndpoint{peerIp, peerPort};
        m_holePuncher = std::make_unique<UdpHolePuncher>();
        
        // Set success callback - receives socket and confirmed peer endpoint
        m_holePuncher->onSuccess([this, peerIp, peerPort](SOCKET, const stun::Endpoint&) {
            LOG_INFO("Hole punch succeeded. Peer: " + peerIp + ":" + std::to_string(peerPort));
            LOG_INFO("NAT traversal complete - you can now start TCP connection");
            
            // Auto-fill host and port for convenience
            SetWindowTextA(m_hHost, peerIp.c_str());
            SetWindowTextA(m_hCPort, std::to_string(peerPort).c_str());
        });
        
        m_holePuncher->onFailure([](const std::string& error) {
            LOG_ERROR("Hole punch failed: " + error);
        });
        
        auto result = m_holePuncher->start(localPort, peerEndpoint);
        if (!result) {
            LOG_ERROR("Failed to start hole punch: " + result.error());
        }
    }
    
    // -------------------------------------------------------------------------
    // UI Refresh
    // -------------------------------------------------------------------------
    void refreshUI() {
        // Update log
        auto newLines = Logger::instance().getNewEntries(m_logIndex);
        for (const auto& line : newLines) {
            appendLogLine(line);
        }
        
        // Update status
        auto state = Application::instance().connectionState();
        SetWindowTextA(m_hStatus, ConnectionStateName(state));
        
        // Update peer info
        auto fingerprint = Application::instance().peerFingerprint();
        if (!fingerprint.empty()) {
            std::string info = "Peer: " + fingerprint.substr(0, 16) + "...";
            SetWindowTextA(m_hPeerInfo, info.c_str());
        } else {
            SetWindowTextA(m_hPeerInfo, "");
        }
    }
    
    void appendLogLine(const std::string& line) {
        int len = GetWindowTextLengthA(m_hLog);
        SendMessage(m_hLog, EM_SETSEL, len, len);
        std::string s = line + "\r\n";
        SendMessageA(m_hLog, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(s.c_str()));
    }
    
    // -------------------------------------------------------------------------
    // Input Subclass (Enter to send)
    // -------------------------------------------------------------------------
    static LRESULT CALLBACK inputSubclassProc(
        HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam,
        UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
        
        auto* self = reinterpret_cast<MainWindow*>(dwRefData);
        (void)uIdSubclass;
        
        if (msg == WM_KEYDOWN && wParam == VK_RETURN) {
            if (GetWindowTextLengthA(hWnd) > 0) {
                self->onSend();
            }
            return 0;
        }
        
        if (msg == WM_CHAR && (wParam == '\r' || wParam == '\n')) {
            return 0;
        }
        
        if (msg == WM_NCDESTROY) {
            RemoveWindowSubclass(hWnd, inputSubclassProc, uIdSubclass);
        }
        
        return DefSubclassProc(hWnd, msg, wParam, lParam);
    }
    
    // -------------------------------------------------------------------------
    // Members
    // -------------------------------------------------------------------------
    HINSTANCE   m_hInstance = nullptr;
    HWND        m_hwnd      = nullptr;
    
    // Controls
    HWND m_hHost        = nullptr;
    HWND m_hLPort       = nullptr;
    HWND m_hCPort       = nullptr;
    HWND m_hHmac        = nullptr;
    HWND m_hListenOnly  = nullptr;
    HWND m_hConnectOnly = nullptr;
    HWND m_hAutoMap     = nullptr;
    HWND m_hStunBtn     = nullptr;
    HWND m_hStartBtn    = nullptr;
    HWND m_hStopBtn     = nullptr;
    HWND m_hLog         = nullptr;
    HWND m_hInput       = nullptr;
    HWND m_hSendBtn     = nullptr;
    HWND m_hStatus      = nullptr;
    HWND m_hPeerInfo    = nullptr;
    // UDP Hole Punch controls
    HWND m_hMyEndpoint    = nullptr;
    HWND m_hPeerEndpoint  = nullptr;
    HWND m_hHolePunchBtn  = nullptr;
    HWND m_hCopyEndpoint  = nullptr;
    HWND m_hLblMyEndpoint   = nullptr;
    HWND m_hLblPeerEndpoint = nullptr;
    
    size_t m_logIndex = 0;
    std::unique_ptr<UdpHolePuncher> m_holePuncher;

    // Async STUN query
    std::thread m_stunThread;
    std::string m_stunResult;
    std::atomic<bool> m_stunPending{false};
};

// =============================================================================
// Entry Point
// =============================================================================
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    // Set app user model ID (for taskbar grouping)
    SetCurrentProcessExplicitAppUserModelID(L"Tumblechat.App");
    
    // Initialize common controls
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icc);
    
    // Initialize application
    if (!Application::instance().initialize()) {
        return 1;
    }
    
    // Create and show window
    MainWindow mainWindow;
    if (!mainWindow.create(hInstance)) {
        MessageBoxA(nullptr, "Failed to create window", "Error", MB_ICONERROR);
        return 1;
    }
    
    mainWindow.show(nCmdShow);
    
    // Message loop
    int result = mainWindow.messageLoop();
    
    // Cleanup
    Application::instance().shutdown();
    
    return result;
}
