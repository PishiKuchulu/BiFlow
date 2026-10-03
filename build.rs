use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=cpp/biflow_hook.c");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=assets/biflow.ico");
    println!("cargo:rerun-if-changed=assets/biflow_res.obj");

    if cfg!(target_os = "windows") {
        println!("cargo:rustc-link-lib=iphlpapi");
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=ole32");
        println!("cargo:rustc-link-lib=shell32");
        println!("cargo:rustc-link-lib=user32");
        println!("cargo:rustc-link-arg=/MANIFESTUAC:level='requireAdministrator' uiAccess='false'");

        let res_obj = std::path::Path::new("assets/biflow_res.obj");
        if res_obj.exists() {
            let abs_obj = std::fs::canonicalize(res_obj).unwrap_or_else(|_| res_obj.to_path_buf());
            println!("cargo:rustc-link-arg={}", abs_obj.display());
        }

        // Compile biflow_hook64.dll if needed or if source is newer
        let dll_path = std::path::Path::new("cpp/biflow_hook64.dll");
        let src_path = std::path::Path::new("cpp/biflow_hook.c");

        let needs_rebuild = if !dll_path.exists() {
            true
        } else if let (Ok(src_meta), Ok(dll_meta)) = (src_path.metadata(), dll_path.metadata()) {
            match (src_meta.modified(), dll_meta.modified()) {
                (Ok(src_time), Ok(dll_time)) => src_time > dll_time,
                _ => false,
            }
        } else {
            false
        };

        if needs_rebuild {
            println!("cargo:warning=Building biflow_hook64.dll from cpp/biflow_hook.c...");
            let tool = cc::Build::new().get_compiler();
            let mut cmd = Command::new(tool.path());
            cmd.args([
                "/LD", "/O2", "/MD",
                "/Fe:cpp/biflow_hook64.dll",
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
            let status = cmd.status();
            match status {
                Ok(s) if s.success() => println!("cargo:warning=biflow_hook64.dll built successfully"),
                _ => println!("cargo:warning=Failed to invoke cl.exe directly, precompiled dll will be used if present"),
            }
        }
    }
}
