#!/usr/bin/env python3
# NetFreedom - open, local, reversible access to the open Internet.
# Copyright (C) 2026 Sergey (PsyGioX) <https://github.com/PsyGioX>
# Project home: https://github.com/PsyGioX/NetFreedom
#
# SPDX-License-Identifier: GPL-3.0-only
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.

"""Generate src/profiles_data.rs: the NetFreedom strategy table.

The 23 BAT profiles of the original set were 12 distinct UDP rule sets and ~20 near-duplicate
TCP rule sets (ALT2/6/7/8/9/10 were byte-for-byte the same LEAN profile, for example). Here the
strategies are written once, as a few small blocks, and composed:

  * WARP strategies   - "lean": only the QUIC/UDP handshake towards Cloudflare is diverted
                        (selected by an IP-range raw filter, so they never depend on list files).
  * bypass strategies - "classic": port based capture for TLS / HTTP / QUIC / Discord voice /
                        game traffic, each built from one TLS technique + shared blocks.

Design rules (they are the reason the output differs from the old tables):
  1. A strategy changes ONE thing, the TLS technique; everything else is shared and tested once.
  2. Game segments never rewrite real game data: they only add fake packets, only to the first
     packets of a flow (`cutoff`). Splitting or overlapping unknown payloads can break logins.
  3. WARP strategies do not read ipset/hostlist files at all: with `ipset-all.txt` switched to
     "none" the old LEAN variants silently stopped protecting the handshake.
  4. TLS tricks are applied to TLS ports only, never to port 80: plain HTTP to CDN ranges carries the
     certificate revocation checks (OCSP/CRL) that Windows and curl make, and splitting those broke
     "working" connections. Port 80 gets its own small HTTP rule for listed hosts only.
  5. No `badseq` with a past sequence number (TSPU started to cut connections that carry it, see
     youtubeUnblock#356); sequence tricks use a future number, timestamps (`ts`) or a low TTL.

Usage: python3 tools/gen_strategies.py > src/profiles_data.rs
"""
import sys

GOOGLE_TLS = "{BIN}tls_clienthello_www_google_com.bin"
GOOGLE_QUIC = "{BIN}quic_initial_www_google_com.bin"
ACTIVE_UDP = "{BIN}ACTIVE_GAME_UDP.bin"
ACTIVE_DISCORD = "{BIN}ACTIVE_DISCORD_UDP.bin"

# Cloudflare WARP (MASQUE) endpoint ranges + UDP ports, selected by WinDivert itself.
WFRAW = (
    "not impostor and not loopback and outbound and udp and udp.PayloadLength>=1 and "
    "udp.Payload[0]>=0xC0 and ((ip.DstAddr>=162.159.0.0 and ip.DstAddr<=162.159.255.255) or "
    "(ip.DstAddr>=188.114.96.0 and ip.DstAddr<=188.114.99.255) or "
    "(ipv6.DstAddr>=2606:4700:: and ipv6.DstAddr<=2606:4700:ffff:ffff:ffff:ffff:ffff:ffff)) and "
    "(udp.DstPort==443 or udp.DstPort==500 or udp.DstPort==1701 or udp.DstPort==4443 or "
    "udp.DstPort==4500 or udp.DstPort==8095 or udp.DstPort==8443)"
)

# list-social.txt (Instagram/Meta, X/Twitter, Telegram, WhatsApp) and list-dev.txt (Vercel, Netlify:
# blocked by Roskomnadzor in 2026) are ours: they ship with the package
HOSTS_GENERAL = [
    "--hostlist={LISTS}list-general.txt", "--hostlist={LISTS}list-general-user.txt",
    "--hostlist={LISTS}list-social.txt", "--hostlist={LISTS}list-dev.txt",
]
EXCLUDES = [
    "--hostlist-exclude={LISTS}list-exclude.txt",
    "--hostlist-exclude={LISTS}list-exclude-user.txt",
    "--ipset-exclude={LISTS}ipset-exclude.txt",
    "--ipset-exclude={LISTS}ipset-exclude-user.txt",
]
IPSET_ALL = ["--ipset={LISTS}ipset-all.txt"]
# Telegram data-centre ranges (the desktop/mobile clients connect to IPs, there is no host name to match)
IPSET_SOCIAL = ["--ipset={LISTS}ipset-social.txt"]

# ------------------------------------------------------------------------ TLS techniques
# Every technique is a list of winws arguments applied to a TLS-bearing TCP flow.
MOD = lambda sni: f"--dpi-desync-fake-tls-mod=rnd,dupsid,sni={sni}"
TECH = {
    # fake + overlapping split: the fake ClientHello carries a harmless SNI, the real one is
    # split at byte 1 with 681 bytes of overlap (the size of the Google ClientHello pattern).
    "fakesplit": [
        "--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=681", "--dpi-desync-split-pos=1",
        "--dpi-desync-fooling=ts", "--dpi-desync-repeats=8",
        f"--dpi-desync-split-seqovl-pattern={GOOGLE_TLS}", MOD("www.google.com"),
    ],
    # no fake packets at all: nothing for a "fake ban" to react to
    "split": [
        "--dpi-desync=multisplit", "--dpi-desync-split-seqovl=681", "--dpi-desync-split-pos=1",
        f"--dpi-desync-split-seqovl-pattern={GOOGLE_TLS}",
    ],
    "sni-split": [
        "--dpi-desync=multisplit", "--dpi-desync-split-pos=2,sniext+1",
        "--dpi-desync-split-seqovl=679", f"--dpi-desync-split-seqovl-pattern={GOOGLE_TLS}",
    ],
    # a Russian host name in the fake: TSPU does not throttle what it believes is domestic traffic
    "hostfake": [
        "--dpi-desync=fake,hostfakesplit", "--dpi-desync-hostfakesplit-mod=host=ya.ru,altorder=1",
        "--dpi-desync-fooling=ts", "--dpi-desync-repeats=5", MOD("ya.ru"),
    ],
    "disorder": [
        "--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld",
        "--dpi-desync-fooling=ts", "--dpi-desync-repeats=6", MOD("www.google.com"),
    ],
    "syndata": ["--dpi-desync=syndata,multidisorder"],
    # fakes that expire before the server: the target never sees the junk
    "ttl": [
        "--dpi-desync=fake,fakedsplit", "--dpi-desync-autottl=2", "--dpi-desync-repeats=6",
        "--dpi-desync-fakedsplit-pattern=0x00", MOD("www.google.com"),
    ],
    # sequence number in the FUTURE (never in the past, see rule 4)
    "seqfake": [
        "--dpi-desync=fake,multisplit", "--dpi-desync-split-seqovl=681", "--dpi-desync-split-pos=1",
        "--dpi-desync-fooling=badseq", "--dpi-desync-badseq-increment=10000000",
        "--dpi-desync-repeats=8", f"--dpi-desync-split-seqovl-pattern={GOOGLE_TLS}", MOD("www.google.com"),
    ],
    # what Flowseal's own YouTube rule uses in 2026: no fake ClientHello, only a fake host name sent
    # in front of the real one (ts fooling), the host is a google.com name
    "hostfake-g": [
        "--dpi-desync=hostfakesplit", "--dpi-desync-fooling=ts",
        "--dpi-desync-hostfakesplit-mod=host=www.google.com",
    ],
    "max": [
        "--dpi-desync=fake,fakedsplit", "--dpi-desync-fakedsplit-pattern=0x00",
        "--dpi-desync-fooling=ts", "--dpi-desync-repeats=11", f"--dpi-desync-fake-tls={GOOGLE_TLS}",
        MOD("www.google.com"),
    ],
}


# Proven techniques of the original 23-profile set, kept verbatim (names follow Flowseal's ALT
# numbering). Their quirks are deliberate: Russian-domain ClientHellos and a STUN payload as the
# first fake are what made them work on many providers.
LEGACY = {
    "general": [
        "--dpi-desync=multisplit",
        "--dpi-desync-split-seqovl=568",
        "--dpi-desync-split-pos=1",
        "--dpi-desync-split-seqovl-pattern={BIN}tls_clienthello_4pda_to.bin"
    ],
    "alt": [
        "--dpi-desync=fake,fakedsplit",
        "--dpi-desync-repeats=6",
        "--dpi-desync-fooling=ts",
        "--dpi-desync-fakedsplit-pattern=0x00",
        "--dpi-desync-fake-tls={BIN}stun.bin",
        "--dpi-desync-fake-tls={BIN}tls_clienthello_www_google_com.bin"
    ],
    "alt10": [
        "--dpi-desync=fake",
        "--dpi-desync-repeats=6",
        "--dpi-desync-fooling=ts",
        "--dpi-desync-fake-tls={BIN}stun.bin",
        "--dpi-desync-fake-tls={BIN}tls_clienthello_4pda_to.bin"
    ],
    "alt11": [
        "--dpi-desync=fake,multisplit",
        "--dpi-desync-split-seqovl=664",
        "--dpi-desync-split-pos=1",
        "--dpi-desync-fooling=ts",
        "--dpi-desync-repeats=8",
        "--dpi-desync-split-seqovl-pattern={BIN}tls_clienthello_www_sferum_ru.bin",
        "--dpi-desync-fake-tls={BIN}stun2.bin",
        "--dpi-desync-fake-tls={BIN}tls_clienthello_www_sferum_ru.bin"
    ],
    "alt12": [
        "--dpi-desync=fake,multisplit",
        "--dpi-desync-split-seqovl=664",
        "--dpi-desync-split-pos=1",
        "--dpi-desync-fooling=ts",
        "--dpi-desync-repeats=8",
        "--dpi-desync-split-seqovl-pattern={BIN}tls_clienthello_www_sferum_ru.bin",
        "--dpi-desync-fake-tls={BIN}stun.bin",
        "--dpi-desync-fake-tls={BIN}tls_clienthello_www_sferum_ru.bin"
    ],
    "alt13": [
        "--dpi-desync=fake,hostfakesplit",
        "--dpi-desync-fooling=ts",
        "--dpi-desync-hostfakesplit-mod=host=mail.ru,altorder=1",
        "--dpi-desync-repeats=5",
        "--dpi-desync-fake-tls={BIN}tls_clienthello_sochi_park.bin",
        "--dpi-desync-fake-tls={BIN}stun2.bin"
    ],
    "alt2": [
        "--dpi-desync=multisplit",
        "--dpi-desync-split-seqovl=652",
        "--dpi-desync-split-pos=2",
        "--dpi-desync-split-seqovl-pattern={BIN}tls_clienthello_www_google_com.bin"
    ],
    "alt3": [
        "--dpi-desync=fake,hostfakesplit",
        "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=ya.ru",
        "--dpi-desync-hostfakesplit-mod=host=ya.ru,altorder=1",
        "--dpi-desync-fooling=ts"
    ],
    "alt4": [
        "--dpi-desync=fake,multisplit",
        "--dpi-desync-repeats=6",
        "--dpi-desync-fooling=badseq",
        "--dpi-desync-badseq-increment=1000",
        "--dpi-desync-fake-tls={BIN}stun.bin",
        "--dpi-desync-fake-tls={BIN}tls_clienthello_www_google_com.bin"
    ],
    "alt8": [
        "--dpi-desync=fake",
        "--dpi-desync-fake-tls-mod=none",
        "--dpi-desync-repeats=6",
        "--dpi-desync-fooling=badseq",
        "--dpi-desync-badseq-increment=2"
    ],
    "alt9": [
        "--dpi-desync=hostfakesplit",
        "--dpi-desync-repeats=4",
        "--dpi-desync-fooling=ts,md5sig",
        "--dpi-desync-hostfakesplit-mod=host=ozon.ru"
    ],
    "exp": [
        "--dpi-desync=fake,multisplit",
        "--dpi-desync-split-seqovl=480",
        "--dpi-desync-split-pos=1",
        "--dpi-desync-fooling=ts",
        "--dpi-desync-repeats=4",
        "--dpi-desync-split-seqovl-pattern={BIN}stun2.bin",
        "--dpi-desync-fake-tls={BIN}tls_clienthello_www_sferum_ru.bin"
    ],
    "fta-alt": [
        "--dpi-desync=fake,fakedsplit",
        "--dpi-desync-split-pos=1",
        "--dpi-desync-fooling=badseq",
        "--dpi-desync-badseq-increment=2",
        "--dpi-desync-repeats=8",
        "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com"
    ],
    "simple-fake-alt": [
        "--dpi-desync=fake",
        "--dpi-desync-repeats=6",
        "--dpi-desync-fooling=badseq",
        "--dpi-desync-badseq-increment=2",
        "--dpi-desync-fake-tls={BIN}stun2.bin",
        "--dpi-desync-fake-tls={BIN}tls_clienthello_www_google_com.bin"
    ],
    "simple-fake-alt2": [
        "--dpi-desync=fake",
        "--dpi-desync-repeats=6",
        "--dpi-desync-fooling=ts",
        "--dpi-desync-fake-tls={BIN}stun2.bin",
        "--dpi-desync-fake-tls={BIN}tls_clienthello_www_sferum_ru.bin"
    ],
    "simple-fake": [
        "--dpi-desync=fake",
        "--dpi-desync-repeats=6",
        "--dpi-desync-fooling=ts",
        "--dpi-desync-fake-tls={BIN}tls_clienthello_www_google_com.bin"
    ]
}
TECH.update(LEGACY)
TECH.update({
    # variations around the family that worked in a real tune report (fake + disorder/dsplit + ts)
    "disorder-sni": [
        "--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,sniext+1",
        "--dpi-desync-fooling=ts", "--dpi-desync-repeats=6", MOD("www.google.com"),
    ],
    "disorder-ya": [
        "--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld",
        "--dpi-desync-fooling=ts", "--dpi-desync-repeats=6", MOD("ya.ru"),
    ],
    "fdisorder": [
        "--dpi-desync=fake,fakeddisorder", "--dpi-desync-split-pos=1,midsld",
        "--dpi-desync-fooling=ts", "--dpi-desync-repeats=6", MOD("www.google.com"),
    ],
})


def quic(repeats):
    return ["--dpi-desync=fake", f"--dpi-desync-repeats={repeats}", f"--dpi-desync-fake-quic={GOOGLE_QUIC}"]


HTTP_RULE = ["--dpi-desync=fake,multisplit", "--dpi-desync-split-pos=method+2", "--dpi-desync-fooling=ts", "--dpi-desync-repeats=4"]


# Our own techniques that send fake packets. Only these get the extra googlevideo rule below: the
# proven original strategies are kept verbatim, and the split-only ones must stay free of fakes.
GV_TECHS = {"fakesplit", "disorder", "max", "disorder-sni", "disorder-ya", "fdisorder", "ttl", "seqfake"}

# YouTube video comes from googlevideo.com. On some providers (MGTS, Rostelecom in autumn 2026) the
# page opens while TLS to googlevideo.com never completes with ANY of the general techniques; a
# separate rule with hostfakesplit (a google.com host in front of the real one) fixes exactly that
# (Flowseal/zapret-discord-youtube#17781).
GOOGLEVIDEO_RULE = [
    "--filter-tcp=443", "--hostlist-domains=googlevideo.com", "--ip-id=zero",
    "--dpi-desync=hostfakesplit", "--dpi-desync-fooling=ts",
    "--dpi-desync-hostfakesplit-mod=host=www.google.com",
]


def classic(tech, r_quic):
    """Port based capture: the strategy for sites, Discord, YouTube, Instagram, X and games."""
    t = TECH[tech]
    segs = [
        # QUIC (HTTP/3) to listed hosts
        ["--filter-udp=443", *HOSTS_GENERAL, *EXCLUDES, *quic(r_quic)],
        # QUIC to YouTube: Chrome prefers it, and it was in no rule (list-google.txt is TCP only)
        ["--filter-udp=443", "--hostlist={LISTS}list-google.txt", *quic(r_quic)],
        # Discord voice + STUN
        ["--filter-udp=19294-19344,50000-50100", "--filter-l7=discord,stun", "--dpi-desync=fake",
         "--dpi-desync-repeats=6", f"--dpi-desync-fake-discord={ACTIVE_DISCORD}",
         f"--dpi-desync-fake-stun={ACTIVE_DISCORD}"],
        # Discord media over TCP
        ["--filter-tcp=2053,2083,2087,2096,8443", "--hostlist-domains=discord.media", *t],
        # YouTube video (googlevideo.com), see GOOGLEVIDEO_RULE
        *([GOOGLEVIDEO_RULE] if tech in GV_TECHS else []),
        # YouTube / Google
        ["--filter-tcp=443", "--hostlist={LISTS}list-google.txt", "--ip-id=zero", *t],
        # everything else on the lists (sites, Instagram, X, ...)
        ["--filter-tcp=443", *HOSTS_GENERAL, *EXCLUDES, *t],
        # plain HTTP: listed hosts only, with an HTTP-shaped rule (rule 4)
        ["--filter-tcp=80", "--filter-l7=http", *HOSTS_GENERAL, *EXCLUDES, *HTTP_RULE],
        # QUIC to blocked ranges
        ["--filter-udp=443", *IPSET_ALL, *EXCLUDES, *quic(r_quic)],
        # TLS to blocked ranges (Cloudflare, Hetzner, OVH, ... the 16 KB cut-off targets)
        ["--filter-tcp=443,8443", *IPSET_ALL, *EXCLUDES, *t],
        # Telegram clients: by address, TLS port only (rule 4)
        ["--filter-tcp=443", *IPSET_SOCIAL, *t],
        # game TCP: fakes only, first packets only, real data untouched (rule 2)
        ["--filter-tcp={GF_TCP}", *IPSET_ALL, "--dpi-desync=fake", "--dpi-desync-fooling=ts",
         "--dpi-desync-repeats=4", "--dpi-desync-any-protocol=1", "--dpi-desync-cutoff=n2",
         "--dpi-desync-fake-unknown=" + "{BIN}stun.bin"],
        # game UDP: a few fakes on the first two packets of a flow, nothing more
        ["--filter-udp={GF_UDP}", *IPSET_ALL, "--dpi-desync=fake", "--dpi-desync-repeats=6",
         "--dpi-desync-any-protocol=1", "--dpi-desync-cutoff=n2",
         f"--dpi-desync-fake-unknown-udp={ACTIVE_UDP}"],
    ]
    head = ["--wf-tcp=80,443,2053,2083,2087,2096,8443,{GF_TCP}", "--wf-udp=443,19294-19344,50000-50100,{GF_UDP}"]
    return flatten(segs, head)


def lean(quic_args, port_repeats, port_cutoff, extra=(), port_fake=ACTIVE_UDP):
    """WARP handshake only: IP-range raw filter, no list files, nothing else is touched."""
    segs = [
        ["--filter-udp=443", *quic_args, *extra],
        ["--filter-udp=500,1701,4443,4500,8095,8443", "--dpi-desync=fake", f"--dpi-desync-repeats={port_repeats}",
         "--dpi-desync-any-protocol=1", f"--dpi-desync-cutoff=n{port_cutoff}",
         f"--dpi-desync-fake-unknown-udp={port_fake}", *extra],
    ]
    return flatten(segs, ["--wf-raw={WFRAW}"])


def flatten(segs, head):
    out = list(head)
    for i, s in enumerate(segs):
        if i:
            out.append("--new")
        out.extend(s)
    return out


# ------------------------------------------------------------------------------ the table
# (name, description, classic args or None, lean args or None)
STRATEGIES = [
    ("warp", "WARP handshake only, 6 fake QUIC Initials (default; least overhead)",
     None, lean(quic(6), 12, 2)),
    ("warp-heavy", "WARP handshake only, 11 fake Initials: for providers that need more noise",
     None, lean(quic(11), 10, 4)),
    ("warp-ttl", "WARP handshake only, fakes expire before Cloudflare (TTL 6)",
     None, lean(quic(6), 8, 2, extra=["--dpi-desync-ttl=6"])),
    ("warp-mix", "WARP handshake only, two different fake Initials per attempt",
     None, lean(["--dpi-desync=fake", "--dpi-desync-repeats=8", f"--dpi-desync-fake-quic={GOOGLE_QUIC}",
                 "--dpi-desync-fake-quic={BIN}quic_initial_rutube_ru.bin"], 12, 3)),
    # Competitive games. The strategy only runs while a connection is being set up (and when WARP
    # re-handshakes), never on game packets, so what it can change is the size of the burst that
    # leaves your uplink at that moment: a burst of N x 1.2 KB fakes occupies a slow uplink for
    # N x 2 ms (at 5 Mbit/s) and shows up as a jitter spike. These three trade fakes for burst.
    ("warp-esports", "WARP handshake only, 3 fake Initials: about a third of the burst of the default",
     None, lean(quic(3), 4, 2)),
    ("warp-esports-ttl", "WARP handshake only, 3 fakes that expire after 5 hops (TTL 5)",
     None, lean(quic(3), 4, 2, extra=["--dpi-desync-ttl=5"])),
    ("warp-lowburst", "WARP handshake only, 4 fake Initials; port rules use a 100-byte fake instead of 1250 bytes",
     None, lean(quic(4), 6, 2, port_fake="{BIN}stun.bin")),
]
BYPASS = [
    ("balanced", "fake + overlapping split with a harmless SNI (good first try)", "fakesplit", 6),
    ("disorder", "fake + out-of-order segments (worked in field tests)", "disorder", 11),
    ("max", "fake + fakedsplit, 11 repeats (worked in field tests)", "max", 11),
    ("disorder-sni", "fake + out-of-order, split at the SNI extension", "disorder-sni", 6),
    ("disorder-ya", "fake + out-of-order with a domestic SNI (ya.ru)", "disorder-ya", 6),
    ("fdisorder", "fake + fake-disorder split (ts)", "fdisorder", 6),
    ("split", "overlapping split only, no fake packets (light, immune to fake bans)", "split", 6),
    ("sni-split", "split at the SNI extension", "sni-split", 6),
    ("hostfake", "fake ClientHello with a domestic host name (ya.ru)", "hostfake", 6),
    ("hostfake-g", "hostfakesplit with a google.com host, ts (what Flowseal uses for YouTube in 2026)", "hostfake-g", 6),
    ("syndata", "payload inside SYN + out-of-order segments (IPv4)", "syndata", 6),
    ("ttl", "fakes that expire before the server (auto TTL)", "ttl", 6),
    ("seqfake", "fake with a future sequence number", "seqfake", 11),
    # the proven strategies of the original set, kept verbatim (Flowseal's ALT numbering)
    ("general", "original: overlapping split, 4pda pattern", "general", 6),
    ("alt", "original ALT: fake + fakedsplit, STUN + Google fakes", "alt", 6),
    ("alt2", "original ALT2: overlapping split at position 2", "alt2", 6),
    ("alt3", "original ALT3: hostfakesplit ya.ru", "alt3", 6),
    ("alt4", "original ALT4: fake + multisplit, future seq 1000", "alt4", 6),
    ("alt8", "original ALT8: plain fake, future seq 2", "alt8", 6),
    ("alt9", "original ALT9: hostfakesplit ozon.ru, ts+md5sig", "alt9", 6),
    ("alt10", "original ALT10: fake with STUN + 4pda ClientHello", "alt10", 6),
    ("alt11", "original ALT11: fake + multisplit 664, sferum.ru", "alt11", 6),
    ("alt12", "original ALT12: like ALT11 with a different STUN fake", "alt12", 6),
    ("alt13", "original ALT13: hostfakesplit mail.ru", "alt13", 6),
    ("exp", "original EXP: fake + multisplit 480", "exp", 6),
    ("simple-fake", "original SIMPLE FAKE: plain fake, ts", "simple-fake", 6),
    ("simple-fake-alt", "original SIMPLE FAKE ALT: plain fake, future seq 2", "simple-fake-alt", 6),
    ("simple-fake-alt2", "original SIMPLE FAKE ALT2: STUN + sferum.ru fakes", "simple-fake-alt2", 6),
    ("fta-alt", "original FAKE TLS AUTO ALT: fakedsplit, future seq 2", "fta-alt", 6),
]
for name, desc, tech, r in BYPASS:
    STRATEGIES.append((name, desc, classic(tech, r), None))

# ------------------------------------------------------------------------------- emission


RUST_HEADER = "\n".join(("// " + l).rstrip() for l in """NetFreedom - open, local, reversible access to the open Internet.
Copyright (C) 2026 Sergey (PsyGioX) <https://github.com/PsyGioX>
Project home: https://github.com/PsyGioX/NetFreedom

SPDX-License-Identifier: GPL-3.0-only

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.""".splitlines()) + "\n\n"


def rust_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    pool, idx = [], {}

    def intern(args):
        if args is None:
            return None
        key = tuple(args)
        if key not in idx:
            idx[key] = len(pool)
            pool.append(args)
        return idx[key]

    rows = [(n, d, intern(c), intern(l)) for n, d, c, l in STRATEGIES]
    out = [RUST_HEADER + "// @generated by tools/gen_strategies.py - do not edit by hand.\n"]
    out.append(f"pub const WFRAW: &str = {rust_str(WFRAW)};\n")
    for i, args in enumerate(pool):
        out.append(f"static S{i}: &[&str] = &[")
        out.extend(f"    {rust_str(a)}," for a in args)
        out.append("];\n")
    out.append("pub static PROFILES: &[crate::profiles::Profile] = &[")
    for n, d, c, l in rows:
        cs = f"Some(S{c})" if c is not None else "None"
        ls = f"Some(S{l})" if l is not None else "None"
        out.append(f"    crate::profiles::Profile {{ name: {rust_str(n)}, desc: {rust_str(d)}, classic: {cs}, lean: {ls} }},")
    out.append("];")
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
