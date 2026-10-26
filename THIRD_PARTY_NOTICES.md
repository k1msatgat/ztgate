# Third-party notices

ztgate ships with or links to the components below. Each keeps its own license.

## Linux server and client

| Component | How it is used | License |
|---|---|---|
| OpenSSL 3 (libcrypto) | Dynamically linked for the session crypto (`lib/common/src/crypt_openssl.c`). Installed from the operating system's package, not shipped in ztgate packages | Apache License 2.0 |
| GNU C Library | Dynamically linked from the operating system | LGPL 2.1 or later |

## Windows client

| Component | How it is used | License |
|---|---|---|
| Wintun 0.14.1 (`wintun.dll`) | Shipped unmodified next to the executables and loaded through its public API (`wintun.h`). Its license text is installed as `wintun-LICENSE.txt` | WireGuard LLC Prebuilt Binaries License |
| Microsoft Visual C++ runtime and MFC | Statically linked into `vpn_service.exe`, `vpn_client.exe` and `vpn_gui.exe` | Microsoft Visual Studio license terms (redistributable code) |
| Windows SDK libraries (CNG, WinHTTP, WFP, Winsock and others) | Called from the operating system | Part of Windows |

## MCP server (optional, `mcp/`)

Installed separately with `npm ci` by `mcp/install.sh`; not part of the DEB / RPM / MSI.

| Package | License |
|---|---|
| `@modelcontextprotocol/sdk` | MIT |
| `zod` | MIT |
| 93 transitive packages (`mcp/package-lock.json`) | MIT (85), ISC (7), BSD-3-Clause (2), BSD-2-Clause (1) |

## Apache License 2.0 (OpenSSL)

OpenSSL is licensed under the Apache License, Version 2.0. You may obtain a copy
of the License at https://www.apache.org/licenses/LICENSE-2.0. The OpenSSL
project's notices are available at https://www.openssl.org/source/license.html.
