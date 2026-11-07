#!/usr/bin/env python3
"""Compares assets/ipset-social.txt with Telegram's official list of address ranges.

    python3 tools/check_social_ranges.py                 # downloads core.telegram.org/resources/cidr.txt
    python3 tools/check_social_ranges.py --file cidr.txt # offline (core.telegram.org may be blocked for you)

Exit code 0 = every official range is covered by our file, 1 = something is missing.
Ranges are compared as networks, not as text: a /22 covered by a wider /20 is not "missing".
"""
import ipaddress
import pathlib
import sys
import urllib.request

OFFICIAL_URL = "https://core.telegram.org/resources/cidr.txt"
OURS = pathlib.Path(__file__).resolve().parent.parent / "assets" / "ipset-social.txt"


def parse(text):
    nets = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if line:
            nets.append(ipaddress.ip_network(line, strict=False))
    return nets


def covered(net, pool):
    return any(net.version == p.version and net.subnet_of(p) for p in pool)


def main(argv):
    if "--file" in argv:
        official = parse(pathlib.Path(argv[argv.index("--file") + 1]).read_text())
    else:
        try:
            official = parse(urllib.request.urlopen(OFFICIAL_URL, timeout=15).read().decode())
        except Exception as e:  # blocked, offline, ...
            print(f"cannot download {OFFICIAL_URL}: {e}\nsave it from a VPN/browser and pass --file cidr.txt")
            return 2
    ours = parse(OURS.read_text())
    missing = [n for n in official if not covered(n, ours)]
    extra = [n for n in ours if not covered(n, official)]
    print(f"official: {len(official)} ranges, ours: {len(ours)}")
    for n in missing:
        print(f"MISSING in ipset-social.txt: {n}")
    for n in extra:
        print(f"not in the official list (old or third-party range, harmless but check): {n}")
    if not missing:
        print("OK: every official range is covered")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
