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

//! netfreedom: games through Cloudflare WARP with zapret handling the handshake.
//!
//! Windows: winws + WinDivert. Linux: nfqws + nftables (NFQUEUE). The platform-independent logic
//! (profiles, capture settings, config, statistics, the native engine model, nft rule generation)
//! is unit-tested on any OS; everything that touches the OS sits behind `cfg`.

pub mod backend;
pub mod capture;
pub mod config;
pub mod dash;
pub mod dns;
pub mod engine;
pub mod health;
pub mod monitor;
pub mod netdiag;
pub mod session;
pub mod nftrules;
pub mod paths;
pub mod probe;
pub mod profiles;
mod profiles_data;
pub mod quic;
pub mod run;
pub mod safety;
pub mod stats;
pub mod tune;
pub mod ui;
pub mod util;
pub mod warp;

#[cfg(windows)]
pub mod native;
#[cfg(windows)]
pub mod sys;
#[cfg(windows)]
pub mod uninstall;
#[cfg(windows)]
pub mod winws;

#[cfg(unix)]
pub mod nfqws;
#[cfg(unix)]
#[path = "sys_unix.rs"]
pub mod sys;
#[cfg(unix)]
#[path = "uninstall_unix.rs"]
pub mod uninstall;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub mod crash;
pub mod maint;
pub mod web;
pub mod verify;
