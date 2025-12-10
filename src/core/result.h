#pragma once
// =============================================================================
// result.h - Error handling types
// =============================================================================

#include <string>
#include <optional>

namespace p2p {

// -----------------------------------------------------------------------------
// Result<T, E> - Either a value or an error
// Uses tagged union approach to handle same-type cases
// -----------------------------------------------------------------------------
template<typename T, typename E = std::string>
class Result {
public:
    // Success constructors
    static Result Ok(T value) { 
        Result r; 
        r.m_value = std::move(value);
        r.m_isOk = true;
        return r; 
    }
    
    // Error constructors
    static Result Err(E error) { 
        Result r; 
        r.m_error = std::move(error);
        r.m_isOk = false;
        return r; 
    }
    
    // Check state
    bool isOk() const { return m_isOk; }
    bool isErr() const { return !m_isOk; }
    explicit operator bool() const { return isOk(); }
    
    // Access value (undefined if error)
    T& value() { return *m_value; }
    const T& value() const { return *m_value; }
    
    // Access error (undefined if ok)
    E& error() { return *m_error; }
    const E& error() const { return *m_error; }
    
    // Safe access with default
    T valueOr(T defaultVal) const { 
        return isOk() ? *m_value : defaultVal; 
    }
    
private:
    std::optional<T> m_value;
    std::optional<E> m_error;
    bool m_isOk = false;
};

// -----------------------------------------------------------------------------
// Void result specialization
// -----------------------------------------------------------------------------
template<typename E>
class Result<void, E> {
public:
    static Result Ok() { 
        Result r; 
        r.m_error = std::nullopt; 
        return r; 
    }
    
    static Result Err(E error) { 
        Result r; 
        r.m_error = std::move(error); 
        return r; 
    }
    
    bool isOk() const { return !m_error.has_value(); }
    bool isErr() const { return m_error.has_value(); }
    explicit operator bool() const { return isOk(); }
    
    const E& error() const { return *m_error; }
    
private:
    std::optional<E> m_error;
};

// Convenience aliases
using VoidResult = Result<void, std::string>;

} // namespace p2p
