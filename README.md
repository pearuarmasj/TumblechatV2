# TumblechatV2

Native Win32 GUI client for peer-to-peer encrypted messaging.

## What it does

- Direct P2P connection between two machines
- End-to-end encryption with ChaCha20-Poly1305 + optional HMAC
- Post-quantum key exchange (ML-KEM / Kyber via liboqs)
- STUN client for discovering your public IP:port
- UDP hole punching for NAT traversal
- Win32 GUI (no framework dependencies)

## vs. HybridHost/HybridClient (the original)

The original iteration was split into two console apps:

| HybridHost/Client | TumblechatV2 |
|-------------------|--------------|
| Separate host + client binaries | Single unified binary |
| Console-only | Native Win32 GUI |
| RSA-3072 key exchange | ML-KEM (Kyber) post-quantum |
| AES-256-GCM | ChaCha20-Poly1305 |
| Hardcoded localhost testing | STUN discovery + UDP hole punch |
| Blocking I/O, single-threaded receive | Async session management |
| Manual counter tracking | Integrated replay protection |
| ~300 lines each, all-in-one | Modular headers in src/ |

The old code was a proof-of-concept: generate RSA keypair, exchange pubkeys, wrap AES session key, send encrypted blobs back and forth. Worked, but only on localhost or pre-configured IPs.

TumblechatV2 addresses the real-world problem: connecting two peers behind NAT without a relay server. STUN discovers external endpoints, UDP hole punching opens the path, then TCP takes over for reliable message delivery.

## Building

**Requirements:**
- Visual Studio 2026 (toolset v145)
- Windows 10 SDK
- C++17

```
MSBuild TumblechatV2.vcxproj /p:Configuration=Release /p:Platform=x64
```

Or open `TumblechatV2.slnx` and hit build.

Output: `bin\Release\TumblechatV2.exe`

## Usage

1. Click "STUN Query" to get your public endpoint
2. Share that endpoint with your peer (copy button included)
3. Paste their endpoint and click "Hole Punch"
4. Once NAT traversal succeeds, click "Start" to establish encrypted session
5. Type messages in the input box

## Dependencies (bundled)

All dependencies are included locally - no vcpkg or external package manager needed.

- `cryptopp/` - Crypto++ 8.x (static library, /MT)
- `deps/` - liboqs with ML-KEM/Kyber

## Layout

```
TumblechatV2/
├── gui_client_v2.cpp        # WinMain, Application, MainWindow
├── src/
│   ├── core/                # types.h, result.h, logger.h
│   ├── crypto/              # crypto_engine.h (ChaCha20-Poly1305, Kyber)
│   ├── network/             # socket_wrapper.h, frame_io.h, udp_hole_punch.h
│   └── session/             # session.h, connection_manager.h
├── cryptopp/                # Crypto++ source + prebuilt lib
└── deps/                    # liboqs (oqs.lib, oqs.dll, headers)
```

## License

Do whatever you want with it.
