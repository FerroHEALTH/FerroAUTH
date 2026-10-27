// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Sets the `resource_server` cfg on every target but the browser's.
//!
//! The browser (`wasm32-unknown-unknown`) builds only the SMART on openEHR
//! scope grammar; the manifest leaves the resource server's dependencies out
//! there, and this cfg leaves out the modules that use them (no specification
//! governs this: our own design).

fn main() {
    println!("cargo::rustc-check-cfg=cfg(resource_server)");
    let browser = matches!(
        (
            std::env::var("CARGO_CFG_TARGET_ARCH").as_deref(),
            std::env::var("CARGO_CFG_TARGET_OS").as_deref(),
        ),
        (Ok("wasm32"), Ok("unknown"))
    );
    if !browser {
        println!("cargo::rustc-cfg=resource_server");
    }
}
