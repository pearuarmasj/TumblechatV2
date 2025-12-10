#pragma once
// =============================================================================
// logger.h - Thread-safe logging system
// =============================================================================

#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <functional>
#include "types.h"

namespace p2p {

class Logger {
public:
    static Logger& instance() {
        static Logger s_instance;
        return s_instance;
    }
    
    // Set minimum log level
    void setLevel(LogLevel level) { m_level = level; }
    LogLevel level() const { return m_level; }
    
    // Register external log handler
    void setCallback(LogCallback cb) { 
        std::lock_guard<std::mutex> lock(m_mutex);
        m_callback = std::move(cb); 
    }
    
    // Log methods
    void debug(const std::string& msg)   { log(LogLevel::Debug, msg); }
    void info(const std::string& msg)    { log(LogLevel::Info, msg); }
    void warning(const std::string& msg) { log(LogLevel::Warning, msg); }
    void error(const std::string& msg)   { log(LogLevel::Error, msg); }
    
    void log(LogLevel level, const std::string& msg) {
        if (level < m_level) return;
        
        std::string formatted = formatMessage(level, msg);
        
        std::lock_guard<std::mutex> lock(m_mutex);
        m_entries.push_back({level, formatted});
        
        // Trim to max size
        if (m_entries.size() > MAX_ENTRIES) {
            m_entries.erase(m_entries.begin(), m_entries.begin() + TRIM_COUNT);
        }
        
        // Notify callback
        if (m_callback) {
            m_callback(level, formatted);
        }
    }
    
    // Get recent entries since last check
    std::vector<std::string> getNewEntries(size_t& lastIndex) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<std::string> result;
        
        while (lastIndex < m_entries.size()) {
            result.push_back(m_entries[lastIndex].message);
            ++lastIndex;
        }
        return result;
    }
    
    // Clear all entries
    void clear() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_entries.clear();
    }
    
    // Format timestamp
    static std::string timestamp() {
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        auto time = std::chrono::system_clock::to_time_t(now);
        
        tm localTime{};
        localtime_s(&localTime, &time);
        
        std::ostringstream oss;
        oss << std::put_time(&localTime, "%H:%M:%S")
            << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return oss.str();
    }

private:
    Logger() = default;
    
    std::string formatMessage(LogLevel level, const std::string& msg) {
        std::ostringstream oss;
        oss << timestamp() << " " << LogLevelPrefix(level) << " " << msg;
        return oss.str();
    }
    
    struct LogEntry {
        LogLevel    level;
        std::string message;
    };
    
    static constexpr size_t MAX_ENTRIES = 10000;
    static constexpr size_t TRIM_COUNT  = 1000;
    
    std::mutex              m_mutex;
    std::vector<LogEntry>   m_entries;
    LogCallback             m_callback;
    LogLevel                m_level = LogLevel::Info;
};

// Convenience macros
#define LOG_DEBUG(msg)   p2p::Logger::instance().debug(msg)
#define LOG_INFO(msg)    p2p::Logger::instance().info(msg)
#define LOG_WARNING(msg) p2p::Logger::instance().warning(msg)
#define LOG_ERROR(msg)   p2p::Logger::instance().error(msg)

} // namespace p2p
