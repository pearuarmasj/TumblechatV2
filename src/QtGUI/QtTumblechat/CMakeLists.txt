cmake_minimum_required(VERSION 3.16)

project(QtTumblechat VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# MSVC requires /Zc:__cplusplus to report correct __cplusplus value for Qt
if(MSVC)
    add_compile_options(/Zc:__cplusplus)
endif()

find_package(Qt6 REQUIRED COMPONENTS Widgets)

qt_standard_project_setup()

# Project root (TumblechatV2 folder)
set(PROJECT_ROOT "${CMAKE_SOURCE_DIR}/../../..")

qt_add_executable(QtTumblechat
    main.cpp

    mainwindow.cpp
    mainwindow.h
    mainwindow.ui

    chatwidget.cpp
    chatwidget.h

    connectiondialog.cpp
    connectiondialog.h

    sessionbridge.cpp
    sessionbridge.h

    stunworker.cpp
    stunworker.h

    # Core p2p library sources (network transport layer)
    "${PROJECT_ROOT}/src/network/udp_transport.cpp"
)

# Include directories for p2p library and dependencies
target_include_directories(QtTumblechat PRIVATE
    "${PROJECT_ROOT}"
    "${PROJECT_ROOT}/src"
    "${PROJECT_ROOT}/cryptopp"
    "${PROJECT_ROOT}/deps/include"
)

# Library directories
target_link_directories(QtTumblechat PRIVATE
    "${PROJECT_ROOT}/cryptopp/x64/Output/$<IF:$<CONFIG:Debug>,Debug,Release>"
    "${PROJECT_ROOT}/deps/lib"
)

# Link libraries
target_link_libraries(QtTumblechat PRIVATE
    Qt6::Widgets
    cryptlib
    oqs
    ws2_32
    iphlpapi
    wininet
)

set_target_properties(QtTumblechat PROPERTIES
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS QtTumblechat
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
