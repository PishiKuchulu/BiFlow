use std::process::Command;

fn main() {
    // Rebuild inputs: the hook source and every MinHook source it compiles.
    println!("cargo:rerun-if-changed=cpp/biflow_hook.c");
    println!("cargo:rerun-if-changed=cpp/minhook/include/MinHook.h");
    println!("cargo:rerun-if-changed=cpp/minhook/src/buffer.c");
    println!("cargo:rerun-if-changed=cpp/minhook/src/buffer.h");
    println!("cargo:rerun-if-changed=cpp/minhook/src/hook.c");
    println!("cargo:rerun-if-changed=cpp/minhook/src/trampoline.c");
    println!("cargo:rerun-if-changed=cpp/minhook/src/trampoline.h");
    println!("cargo:rerun-if-changed=cpp/minhook/src/hde/hde64.c");
    println!("cargo:rerun-if-changed=cpp/minhook/src/hde/hde64.h");
    println!("cargo:rerun-if-changed=cpp/minhook/src/hde/pstdint.h");
    println!("cargo:rerun-if-changed=cpp/minhook/src/hde/table64.h");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=assets/biflow.ico");
    println!("cargo:rerun-if-changed=assets/biflow_res.obj");

    // NOTE: build scripts run on the HOST, so `cfg!(target_os)` here would
    // describe the host, not the crate being built. CARGO_CFG_TARGET_OS is
    // the target of the crate, which is what decides everything below.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR is always set for build scripts");
    let out_dll = std::path::Path::new(&out_dir).join("biflow_hook64.dll");

    if target_os != "windows" {
        // The embedded-bytes include in the binary crate must still resolve
        // on non-Windows hosts (e.g. `cargo check` on Linux); the hook is
        // never used there.
        if !out_dll.exists() {
            let _ = std::fs::write(&out_dll, b"");
        }
        return;
    }

    println!("cargo:rustc-link-lib=iphlpapi");
    println!("cargo:rustc-link-lib=ws2_32");
    println!("cargo:rustc-link-lib=advapi32");
    println!("cargo:rustc-link-lib=ole32");
    println!("cargo:rustc-link-lib=shell32");
    println!("cargo:rustc-link-lib=user32");
    // Manifest (requireAdministrator) only on the real binary, not on test
    // harnesses: `cargo test` must also work from a non-elevated shell.
    println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:level='requireAdministrator' uiAccess='false'");

    let res_obj = std::path::Path::new("assets/biflow_res.obj");
    if res_obj.exists() {
        let abs_obj = std::fs::canonicalize(res_obj).unwrap_or_else(|_| res_obj.to_path_buf());
        println!("cargo:rustc-link-arg-bins={}", abs_obj.display());
    }

    // Always compile the hook DLL from source into OUT_DIR (never into the
    // source tree, never a committed prebuilt binary). Cargo's
    // rerun-if-changed fingerprinting above decides when this is stale.
    println!("cargo:warning=Building biflow_hook64.dll from cpp/biflow_hook.c...");
    let tool = cc::Build::new().get_compiler();
    let mut cmd = Command::new(tool.path());
    // Propagate the cc crate's environment (INCLUDE/LIB/VSLANG from the
    // MSVC developer prompt) so cl.exe can find the Windows SDK.
    for (k, v) in tool.env() {
        cmd.env(k, v);
    }
    let out_dll_str = out_dll.to_string_lossy().to_string();
    let obj_dir = format!("{}\\", out_dir.trim_end_matches(['\\', '/']));
    cmd.args([
        "/LD",
        "/O2",
        // Static CRT: the DLL is injected into arbitrary processes and must
        // not depend on a vcruntime140.dll being loadable in their context.
        "/MT",
        &format!("/Fe:{}", out_dll_str),
        // Keep .obj intermediates inside OUT_DIR instead of polluting the
        // repository root / cpp folder.
        &format!("/Fo:{}", obj_dir),
        "cpp/biflow_hook.c",
        "cpp/minhook/src/buffer.c",
        "cpp/minhook/src/hook.c",
        "cpp/minhook/src/trampoline.c",
        "cpp/minhook/src/hde/hde64.c",
        "/Icpp/minhook/include",
        "/Icpp/minhook/src",
        "ws2_32.lib",
        "user32.lib",
    ]);
    match cmd.output() {
        Ok(out) if out.status.success() => {
            println!("cargo:warning=biflow_hook64.dll built successfully")
        }
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            panic!(
                "Failed to build biflow_hook64.dll with {} (a working MSVC C++ toolchain with Windows SDK is required):\n--- stdout ---\n{}\n--- stderr ---\n{}",
                tool.path().display(),
                stdout,
                stderr
            );
        }
        Err(e) => panic!(
            "Failed to invoke C compiler {}: {}. A working MSVC C++ toolchain is required to build the hook DLL.",
            tool.path().display(),
            e
        ),
    }
}
