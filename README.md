# TumblechatV2

Native Win32 GUI client for peer-to-peer encrypted messaging.

## What it does

- Direct P2P connection between two machines
- Hybrid post-quantum key exchange: X25519 (classical) + ML-KEM-768 (Kyber, PQ-resistant)
- Symmetric encryption: AES-256-GCM + HMAC-SHA256
- Session keys derived via HKDF-SHA256 from both shared secrets
- STUN client for discovering your public IP:port
- UDP hole punching for NAT traversal
- Win32 GUI (no framework dependencies)

## vs. HybridHost/HybridClient (the original)

The original iteration was split into two console apps:

| Aspect | HybridHost/Client | TumblechatV2 |
|--------|-------------------|--------------|
| Architecture | Separate host + client binaries | Single unified binary |
| UI | Console-only | Native Win32 GUI |
| Key Exchange | RSA-3072 (classical only) | X25519 + ML-KEM-768 (hybrid PQ) |
| Symmetric Cipher | AES-256-GCM | AES-256-GCM |
| Key Derivation | RSA encrypts AES key directly | HKDF combines X25519 + ML-KEM shared secrets |
| Networking | Hardcoded localhost testing | STUN discovery + UDP hole punch |
| Threading | Blocking I/O, single-threaded receive | Async session management |
| Replay Protection | Manual counter tracking | Integrated counter + timestamp validation |
| Code Structure | ~300 lines each, all-in-one | Modular headers in src/ |

The old code was a proof-of-concept: generate RSA keypair, exchange pubkeys, RSA-encrypt an AES session key, send encrypted blobs back and forth. Worked, but only on localhost or pre-configured IPs, and RSA is increasingly seen as a ticking clock for quantum computing threats.

TumblechatV2 addresses both problems:
1. **Post-quantum security**: The hybrid X25519 + ML-KEM scheme means even if Shor's algorithm breaks X25519, ML-KEM still protects the session (and vice versa).
2. **Real-world connectivity**: STUN discovers external endpoints, UDP hole punching opens the path through NAT, then TCP handles reliable message delivery.

## Building

**Requirements:**
- Visual Studio 2026 (toolset v145)
- Windows 10 SDK
- C++17

```powershell
# Find and run MSBuild (works regardless of VS install location)
$msbuild = Get-ChildItem -Path 'C:\Program Files*\Microsoft Visual Studio' -Recurse -Filter 'MSBuild.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match 'amd64' } | Select-Object -First 1 -ExpandProperty FullName
& $msbuild TumblechatV2.vcxproj /p:Configuration=Release /p:Platform=x64
```

Or open `TumblechatV2.slnx` in Visual Studio and build (F7).

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
│   ├── crypto/              # crypto_engine.h (X25519, ML-KEM, AES-GCM, HKDF)
│   ├── network/             # socket_wrapper.h, frame_io.h, udp_hole_punch.h
│   └── session/             # session.h, connection_manager.h
├── cryptopp/                # Crypto++ source + prebuilt lib
└── deps/                    # liboqs (oqs.lib, oqs.dll, headers)
```

## License

Do whatever you want with it.
