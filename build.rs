// NetFreedom - open, local, reversible access to the open Internet.
// Copyright (C) 2026 Sergey (PsyGioX) <https://github.com/PsyGioX>
// Project home: https://github.com/PsyGioX/NetFreedom
//
// SPDX-License-Identifier: GPL-3.0-only
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

//! Embeds the NetFreedom icon and version information into the Windows executable.
//! Uses `windres` (GNU toolchain) or `rc.exe` (MSVC) if present; without them the build still
//! succeeds, the program just has the default icon. Nothing happens on other platforms.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/netfreedom.ico");
    println!("cargo:rerun-if-changed=build.rs");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let icon = manifest.join("assets").join("netfreedom.ico");
    let ver = env::var("CARGO_PKG_VERSION").unwrap();
    let nums: Vec<String> = ver.split('.').map(|p| p.to_string()).chain(std::iter::repeat("0".into())).take(4).collect();
    let comma = nums.join(",");
    let rc = out.join("netfreedom.rc");
    let icon_path = icon.to_string_lossy().replace('\\', "/");
    let text = format!(
        "1 ICON \"{icon_path}\"\n\
         1 VERSIONINFO\nFILEVERSION {comma}\nPRODUCTVERSION {comma}\nBEGIN\n BLOCK \"StringFileInfo\"\n BEGIN\n  BLOCK \"040904B0\"\n  BEGIN\n\
         \x20  VALUE \"ProductName\", \"NetFreedom\"\n   VALUE \"LegalCopyright\", \"Copyright (C) 2026 Sergey (PsyGioX). GNU GPL v3.0\"\n   VALUE \"Comments\", \"https://github.com/PsyGioX/NetFreedom\"\n   VALUE \"FileDescription\", \"NetFreedom - open, local, reversible access to the open Internet\"\n\
         \x20  VALUE \"FileVersion\", \"{ver}\"\n   VALUE \"ProductVersion\", \"{ver}\"\n   VALUE \"OriginalFilename\", \"netfreedom.exe\"\n  END\n END\n\
         \x20BLOCK \"VarFileInfo\"\n BEGIN\n  VALUE \"Translation\", 0x0409, 0x04B0\n END\nEND\n"
    );
    std::fs::write(&rc, text).expect("write .rc");

    let gnu = env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu");
    let ok = if gnu {
        let obj = out.join("netfreedom_res.o");
        ["x86_64-w64-mingw32-windres", "windres"].iter().any(|tool| {
            Command::new(tool).arg("-i").arg(&rc).arg("-o").arg(&obj).arg("--target=pe-x86-64").status().is_ok_and(|s| s.success())
        }) && {
            println!("cargo:rustc-link-arg-bins={}", obj.display());
            true
        }
    } else {
        let res = out.join("netfreedom.res");
        Command::new("rc.exe").arg("/nologo").arg(format!("/fo{}", res.display())).arg(&rc).status().is_ok_and(|s| s.success()) && {
            println!("cargo:rustc-link-arg-bins={}", res.display());
            true
        }
    };
    if !ok {
        println!("cargo:warning=windres/rc not found: building without the embedded icon");
    }
}
