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

"""Feed every strategy to the real nfqws (`--dry-run`): catches typos, unknown options and missing
fake/list files. It checks syntax only - whether a strategy WORKS on a provider is what `tune` is for.

  cargo build --example dump_args
  python3 tools/validate_strategies.py [dist/linux]
"""
import os, subprocess, sys

root = sys.argv[1] if len(sys.argv) > 1 else "dist/linux"
nfqws = os.path.abspath(os.path.join(root, "bin", "linux-x86_64", "nfqws"))
bin_dir, lists = os.path.abspath(os.path.join(root, "bin")) + "/", os.path.abspath(os.path.join(root, "lists")) + "/"
dump = subprocess.run(["target/debug/examples/dump_args", bin_dir, lists], capture_output=True, text=True, check=True).stdout
bad = 0
for line in dump.splitlines():
    name, kind, rest = line.split("|", 2)
    r = subprocess.run([nfqws, "--dry-run", "--qnum=200", "--dpi-desync-fwmark=0x40000000", *rest.split("\x1f")], capture_output=True, text=True, cwd=bin_dir)
    print(("OK   " if r.returncode == 0 else "FAIL ") + f"{name} ({kind})" + ("" if r.returncode == 0 else "\n     " + (r.stdout + r.stderr).strip()[-300:]))
    bad += r.returncode != 0
sys.exit(1 if bad else 0)
