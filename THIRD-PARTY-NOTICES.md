<!-- Copyright (C) 2026 Sergey (PsyGioX) <https://github.com/PsyGioX> - SPDX-License-Identifier: GPL-3.0-only -->
# Third-party notices

NetFreedom itself is licensed under the **GNU General Public License v3.0** (see `LICENSE`).
It is built on the work of others, whose licenses are kept intact:

| Component | Author | License |
|---|---|---|
| zapret (`nfqws` on Linux; the fake payload files; the built-in default fake ClientHello and HTTP request; the protocol detection and strategy behaviour that the Rust engine reimplements, written after reading zapret v72.9) | bol-van, https://github.com/bol-van/zapret | MIT |
| Strategy ideas, host/address lists, launcher scripts of the original set | Flowseal, https://github.com/Flowseal/zapret-discord-youtube | MIT |
| WinDivert (`WinDivert.dll`, `WinDivert64.sys`) | basil00, https://github.com/basil00/WinDivert | LGPL-3.0 or GPL-2.0 (your choice), shipped unmodified |

MIT-licensed code may be included in a GPL-3.0 work, provided the MIT copyright and permission
notice stays with it. That notice is reproduced below exactly as it came with the original set.
Cloudflare WARP is **not** part of this package; it is Cloudflare's own software with its own terms.

## Original license text (preserved verbatim)

```text
MIT License

Copyright (c) 2016-2026 bol-van
Copyright (c) 2024-2026 Flowseal

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

This repository contains binary files originating from the project by bol-van,  
available at: https://github.com/bol-van/zapret/ (licensed under the MIT License).

This repository also includes and depends on WinDivert  
(https://github.com/basil00/WinDivert), which is licensed under your choice of:

1. The GNU Lesser General Public License (LGPL) Version 3, or  
2. The GNU General Public License (GPL) Version 2.

Binary distributions of WinDivert are included in this project as-is, without modification.  
The corresponding source code and license terms for WinDivert are available at  
https://github.com/basil00/WinDivert.

---

To comply with the licenses of these projects:

1. The original copyright notices and licenses (above) are retained.  
2. The use of WinDivert in this project is governed by its licensing terms (LGPLv3/GPLv2).  
3. This repository provides only binary files and does not include the source code of  
   the project by bol-van or modifications to WinDivert.
```
