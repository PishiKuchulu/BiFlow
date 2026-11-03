use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};

const EMBEDDED_HOOK_DLL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/biflow_hook64.dll"));

/// Versioned hook DLL file name, so an updated BiFlow never fights over a
/// DLL file that is still loaded (and therefore locked) in target processes.
pub(crate) fn hook_dll_file_name() -> String {
    format!(
        "biflow_hook64_v{}.dll",
        env!("CARGO_PKG_VERSION").replace('.', "_")
    )
}

/// Root-ACL latch: 0 = not applied yet, 1 = applied, 2 = failed (and the
/// failure already logged once). A plain `Once` would consume the single
/// attempt even on failure and leave the root folder unprotected for the
/// process lifetime with no retry; latching only success keeps the retry
/// while the state-2 latch keeps a persistent failure from spamming the
/// log on every call.
static ACL_ROOT_STATE: std::sync::Mutex<u8> = std::sync::Mutex::new(0);

/// %ProgramData%\BiFlow — the protected home of the hook DLL and the policy
/// files. On first use its DACL is replaced (best effort) with a protected
/// one: SYSTEM and Administrators get full control, ordinary users only
/// read/execute. That is what stops a same-user, non-elevated process from
/// swapping the DLL or the policy files that the elevated BiFlow later loads
/// into other processes (local privilege-escalation via %TEMP%).
/// The ACEs carry OI/CI inheritance, so children created later (bin/, the
/// DLL, the policy files) inherit them; the security-critical objects also
/// get the same DACL applied explicitly and checked (see
/// apply_protected_acl), because a directory DACL alone never proves what
/// its children ended up with.
pub fn biflow_programdata_dir() -> Option<PathBuf> {
    let prog = std::env::var("ProgramData").ok()?;
    let dir = PathBuf::from(prog).join("BiFlow");
    let _ = fs::create_dir_all(&dir);
    // Best-effort root ACL on first use, retried on later calls until it
    // succeeds once (security-critical consumers additionally re-apply it
    // with checked calls). A failure is logged once per latch state
    // instead of being swallowed forever.
    if let Ok(mut state) = ACL_ROOT_STATE.lock() {
        if *state != 1 {
            match apply_protected_acl(&dir) {
                Ok(()) => *state = 1,
                Err(e) => {
                    if *state == 0 {
                        crate::config::append_log(&format!("ROOT_ACL_APPLY_FAILED {}", e));
                    }
                    *state = 2;
                }
            }
        }
    }
    Some(dir)
}

/// SDDL for the policy/DLL objects: owner Administrators, protected DACL,
/// full control for SYSTEM + Administrators, read/execute for Users.
const POLICY_ACL_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)";

/// SDDL for the hook-status directory: like the policy ACL, but Users get
/// GENERIC_WRITE so a target process running with the user's normal token
/// can create its `hook_status_<pid>.txt` report. Under the policy ACL the
/// hook could never write that report and every injection timed out.
const STATUS_ACL_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GW;;;BU)";

/// Applies the protected admin-only DACL to one path and verifies the
/// result: unlike the old best-effort directory call, a failure here is
/// reported so injection/policy publication never proceeds on assumed
/// protection. Uses SetNamedSecurityInfoW (the documented replacement for
/// the superseded SetFileSecurityW).
pub fn apply_protected_acl(path: &Path) -> Result<(), String> {
    // Users ACE mask for the policy ACL: GRGX = GENERIC_READ | GENERIC_EXECUTE.
    apply_acl_sddl(path, POLICY_ACL_SDDL, 0x8000_0000 | 0x2000_0000)
}

/// Applies the status-directory ACL (owner Administrators + protected
/// DACL + user write access for hook reports). See STATUS_ACL_SDDL.
pub(crate) fn apply_status_acl(path: &Path) -> Result<(), String> {
    // Users ACE mask for the status ACL: GW = GENERIC_WRITE.
    apply_acl_sddl(path, STATUS_ACL_SDDL, 0x4000_0000)
}

fn apply_acl_sddl(path: &Path, sddl_str: &str, users_mask: u32) -> Result<(), String> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    // O:BA = owner Administrators. Setting the owner matters as much as the
    // DACL: an object's owner implicitly holds WRITE_DAC, so a DACL-only
    // fix would still let the creating user (e.g. whoever pre-created the
    // folder) rewrite the ACL and retake the directory.
    // D:P  = protected DACL (no inheritance from the parent folder)
    // OICI = object + container inherit (children inherit these ACEs)
    // FA   = full access for SYSTEM (SY) and Administrators (BA)
    // GRGX = generic read/execute for Users (BU) in the policy ACL
    // GW   = generic write for Users (BU) in the status ACL
    let sddl: Vec<u16> = sddl_str.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let mut psd: PSECURITY_DESCRIPTOR = null_mut();
        let ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut psd,
            null_mut(),
        );
        if ok == 0 || psd.is_null() {
            return Err(format!(
                "Could not build security descriptor for {}",
                path.display()
            ));
        }
        // BOOL is i32 in windows-sys (windows_sys::core::BOOL).
        let mut present: i32 = 0;
        let mut dacl: *mut ACL = null_mut();
        let mut defaulted: i32 = 0;
        let got = GetSecurityDescriptorDacl(psd, &mut present, &mut dacl, &mut defaulted);
        if got == 0 || present == 0 || dacl.is_null() {
            LocalFree(psd as HLOCAL);
            return Err(format!("Could not extract DACL for {}", path.display()));
        }
        let mut owner: PSID = null_mut();
        let mut owner_defaulted: i32 = 0;
        let got_owner = GetSecurityDescriptorOwner(psd, &mut owner, &mut owner_defaulted);
        if got_owner == 0 || owner.is_null() {
            LocalFree(psd as HLOCAL);
            return Err(format!("Could not extract owner for {}", path.display()));
        }
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let err = SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            null_mut(),
            dacl as *const ACL,
            null_mut(),
        );
        LocalFree(psd as HLOCAL);
        if err != 0 {
            return Err(format!(
                "Could not set ACL on {} (Win32 error {})",
                path.display(),
                err
            ));
        }
        // Verify the result by reading the security descriptor back: the
        // owner must really be Administrators (a silent no-op here would
        // leave the WRITE_DAC loophole in place) AND the DACL must be
        // exactly the expected ACE set. Verifying only the owner used to
        // let a DACL that SetNamedSecurityInfoW applied differently (or
        // not at all) pass while the code claimed the object protected.
        let mut actual_owner: PSID = null_mut();
        let mut actual_dacl: *mut ACL = null_mut();
        let mut read_sd: PSECURITY_DESCRIPTOR = null_mut();
        let rerr = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut actual_owner,
            null_mut(),
            &mut actual_dacl,
            null_mut(),
            &mut read_sd,
        );
        if rerr != 0 || actual_owner.is_null() || actual_dacl.is_null() {
            if !read_sd.is_null() {
                LocalFree(read_sd as HLOCAL);
            }
            return Err(format!(
                "Could not verify ACL for {} (Win32 error {})",
                path.display(),
                rerr
            ));
        }
        let owner_ok = sid_to_string(actual_owner).as_deref() == Some("S-1-5-32-544");
        let dacl_ok = verify_expected_dacl(actual_dacl, users_mask);
        LocalFree(read_sd as HLOCAL);
        if !owner_ok {
            return Err(format!(
                "ACL owner verification failed for {} (owner is not Administrators)",
                path.display()
            ));
        }
        if !dacl_ok {
            return Err(format!(
                "ACL DACL verification failed for {} (read-back ACEs differ from the expected set)",
                path.display()
            ));
        }
    }
    Ok(())
}

/// Returns Some(true) when the DACL of `path` grants write-like rights
/// (write data / append / delete / write DAC / generic write or all) to
/// any untrusted principal: Users, Authenticated Users, Everyone,
/// CREATOR OWNER, or the current user personally. None when the DACL
/// cannot be read (callers must fail closed). Used by the autostart gate,
/// where a lexical path-prefix test is NOT enough: a user-created
/// subfolder of %ProgramData% passes a prefix test while being fully
/// writable by its creator.
pub(crate) fn path_grants_untrusted_write(path: &Path, current_user_sid: &str) -> Option<bool> {
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    const DANGEROUS_MASK: u32 = 0x4000_0000  // GENERIC_WRITE
        | 0x1000_0000  // GENERIC_ALL
        | 0x0200_0000  // MAXIMUM_ALLOWED
        | 0x0000_0002  // FILE_WRITE_DATA
        | 0x0000_0004  // FILE_APPEND_DATA
        | 0x0000_0040  // FILE_DELETE_CHILD
        | 0x0001_0000  // DELETE
        | 0x0004_0000  // WRITE_DAC
        | 0x0008_0000; // WRITE_OWNER
    let untrusted = [
        "S-1-5-32-545", // Users
        "S-1-5-11",     // Authenticated Users
        "S-1-1-0",      // Everyone
        "S-1-3-0",      // CREATOR OWNER
        current_user_sid,
    ];
    unsafe {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut dacl: *mut ACL = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let err = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        );
        if err != 0 || dacl.is_null() {
            if !sd.is_null() {
                LocalFree(sd as HLOCAL);
            }
            return None;
        }
        use windows_sys::Win32::Security::{
            AclSizeInformation, GetAce, GetAclInformation, ACL_SIZE_INFORMATION,
        };
        let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
        let ok = GetAclInformation(
            dacl,
            &mut info as *mut ACL_SIZE_INFORMATION as *mut core::ffi::c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        );
        if ok == 0 {
            LocalFree(sd as HLOCAL);
            return None;
        }
        let mut grants = false;
        for i in 0..info.AceCount {
            let mut ace_ptr: *mut core::ffi::c_void = null_mut();
            if GetAce(dacl, i, &mut ace_ptr) == 0 || ace_ptr.is_null() {
                LocalFree(sd as HLOCAL);
                return None;
            }
            let ace_bytes = ace_ptr as *const u8;
            if *ace_bytes != 0 {
                continue; // not an access-allowed ACE
            }
            let mask = std::ptr::read_unaligned(ace_bytes.add(4) as *const u32);
            if mask & DANGEROUS_MASK == 0 {
                continue;
            }
            let sid = ace_bytes.add(8) as PSID;
            if let Some(s) = sid_to_string(sid) {
                if untrusted.contains(&s.as_str()) {
                    grants = true;
                    break;
                }
            }
        }
        LocalFree(sd as HLOCAL);
        Some(grants)
    }
}

/// Converts a SID to its string form ("S-1-5-32-544") for comparison.
unsafe fn sid_to_string(sid: PSID) -> Option<String> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    if sid.is_null() {
        return None;
    }
    let mut sid_str: windows_sys::core::PWSTR = null_mut();
    let cok = ConvertSidToStringSidW(sid, &mut sid_str);
    if cok == 0 || sid_str.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *sid_str.add(len) != 0 {
        len += 1;
    }
    let s = String::from_utf16_lossy(std::slice::from_raw_parts(sid_str, len));
    LocalFree(sid_str as HLOCAL);
    Some(s)
}

/// Verifies a read-back DACL contains EXACTLY the expected ACEs: SYSTEM
/// and Administrators with FILE_ALL_ACCESS (0x001F01FF), Users with
/// `users_mask`, every ACE an access-allowed ACE carrying OI|CI
/// inheritance, and nothing else (no extra allow ACEs, no deny ACEs).
unsafe fn verify_expected_dacl(dacl: *mut ACL, users_mask: u32) -> bool {
    use windows_sys::Win32::Security::{
        AclSizeInformation, GetAce, GetAclInformation, ACL_SIZE_INFORMATION,
    };
    const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
    const ACE_TYPE_ACCESS_ALLOWED: u8 = 0;
    const ACE_FLAGS_OI_CI: u8 = 0x03;
    if dacl.is_null() {
        return false;
    }
    let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
    let ok = GetAclInformation(
        dacl,
        &mut info as *mut ACL_SIZE_INFORMATION as *mut core::ffi::c_void,
        std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
        AclSizeInformation,
    );
    if ok == 0 || info.AceCount != 3 {
        return false;
    }
    let expected: [(&str, u32); 3] = [
        ("S-1-5-18", FILE_ALL_ACCESS),     // SYSTEM
        ("S-1-5-32-544", FILE_ALL_ACCESS), // Administrators
        ("S-1-5-32-545", users_mask),      // Users
    ];
    let mut seen = [false; 3];
    for i in 0..info.AceCount {
        let mut ace_ptr: *mut core::ffi::c_void = null_mut();
        if GetAce(dacl, i, &mut ace_ptr) == 0 || ace_ptr.is_null() {
            return false;
        }
        // ACCESS_ALLOWED_ACE layout: ACE_HEADER {AceType u8, AceFlags u8,
        // AceSize u16}, Mask u32 at offset 4, SID at offset 8.
        let ace_bytes = ace_ptr as *const u8;
        let ace_type = *ace_bytes;
        let ace_flags = *ace_bytes.add(1);
        let mask = std::ptr::read_unaligned(ace_bytes.add(4) as *const u32);
        if ace_type != ACE_TYPE_ACCESS_ALLOWED || (ace_flags & ACE_FLAGS_OI_CI) != ACE_FLAGS_OI_CI {
            return false;
        }
        let sid = ace_bytes.add(8) as PSID;
        let Some(sid_string) = sid_to_string(sid) else {
            return false;
        };
        let mut matched = false;
        for (idx, (want_sid, want_mask)) in expected.iter().enumerate() {
            if !seen[idx] && sid_string == *want_sid && mask == *want_mask {
                seen[idx] = true;
                matched = true;
                break;
            }
        }
        if !matched {
            return false;
        }
    }
    seen.iter().all(|s| *s)
}

pub fn ensure_dll_extracted() -> Result<PathBuf, String> {
    let base = biflow_programdata_dir()
        .ok_or_else(|| "ProgramData environment variable is unavailable".to_string())?
        .join("bin");
    fs::create_dir_all(&base).map_err(|e| format!("Cannot create {}: {}", base.display(), e))?;
    // The root folder itself is part of the trust boundary (the policy
    // files and the autostart task XML live directly in it): prove its
    // owner + DACL instead of assuming the best-effort startup call in
    // biflow_programdata_dir succeeded.
    if let Some(root) = base.parent() {
        apply_protected_acl(root)?;
    }
    // The DLL is loaded into other processes: its directory and the file
    // itself get the checked protected ACL, and a failure here fails the
    // extraction instead of injecting a DLL whose protection is assumed.
    apply_protected_acl(&base)?;
    let dll_path = base.join(hook_dll_file_name());

    // Verify the FULL content, not just the size: a same-size impostor DLL
    // must never be injected. (The ACL above is the primary defense; this
    // catches corruption and stale builds.)
    let current = fs::read(&dll_path).ok();
    if current.as_deref() != Some(EMBEDDED_HOOK_DLL) {
        fs::write(&dll_path, EMBEDDED_HOOK_DLL).map_err(|e| {
            format!(
                "Cannot write hook DLL {} (is an old copy still loaded in a target process?): {}",
                dll_path.display(),
                e
            )
        })?;
        let back = fs::read(&dll_path)
            .map_err(|e| format!("Cannot re-read hook DLL {}: {}", dll_path.display(), e))?;
        if back != EMBEDDED_HOOK_DLL {
            return Err("Hook DLL content verification failed after writing it".into());
        }
    }
    // Also protect a pre-existing DLL (e.g. from an older BiFlow) that did
    // not need rewriting: its ACL must be proven, not inherited by luck.
    apply_protected_acl(&dll_path)?;

    // Best-effort cleanup of DLLs from older BiFlow versions.
    if let Ok(entries) = fs::read_dir(&base) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("biflow_hook64_v") && entry.path() != dll_path {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    Ok(dll_path)
}

/// Writes a policy file into %ProgramData%\BiFlow atomically: temp file in
/// the same directory + flush + rename-replace, then the checked protected
/// ACL. ProgramData is the ONLY policy location now: the %TEMP% fallbacks
/// were removed because a stale TEMP copy could resurrect a deleted policy
/// and because TEMP was never protected by the admin-only DACL.
fn write_pd_policy_file(leaf: &str, content: &str) -> Result<(), String> {
    let dir = biflow_programdata_dir()
        .ok_or_else(|| "ProgramData environment variable is unavailable".to_string())?;
    fs::create_dir_all(&dir).map_err(|e| format!("Cannot create {}: {}", dir.display(), e))?;
    // The containing folder's owner + DACL are part of the policy's
    // protection: prove them on every publish, not just the file's.
    apply_protected_acl(&dir)?;
    let final_path = dir.join(leaf);
    // The temp name must be unique per CALL, not per process: the UI
    // thread and the watchdog thread both publish policy, and with a
    // pid-only name two concurrent publishes of the same leaf shared one
    // temp path and could rename each other's content.
    static PUBLISH_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = PUBLISH_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp_path = dir.join(format!(".{}-{}-{}.tmp", leaf, std::process::id(), seq));
    fs::write(&tmp_path, content)
        .map_err(|e| format!("Cannot write {}: {}", tmp_path.display(), e))?;
    // Flush to disk before the rename so a crash cannot leave a torn file.
    // A flush that cannot even start is a publish failure, not a detail to
    // skip past while claiming crash-safety.
    match fs::File::open(&tmp_path) {
        Ok(f) => {
            if let Err(e) = f.sync_all() {
                let _ = fs::remove_file(&tmp_path);
                return Err(format!("Cannot flush {}: {}", tmp_path.display(), e));
            }
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!(
                "Cannot reopen {} for flush: {}",
                tmp_path.display(),
                e
            ));
        }
    }
    fs::rename(&tmp_path, &final_path)
        .map_err(|e| format!("Cannot publish {}: {}", final_path.display(), e))?;
    apply_protected_acl(&final_path)?;
    Ok(())
}

pub fn update_target_ip(ip: &str) -> Result<(), String> {
    write_pd_policy_file("target_ip.txt", ip.trim())
}

/// Writes the allow-list of bypassed executables (one full path per line,
/// UTF-8). The injected hook only binds sockets for processes on this list,
/// so removing one app stops its bypass without affecting the others.
pub fn update_bypass_app_list(exe_paths: &[String]) -> Result<(), String> {
    write_pd_policy_file("bypass_apps.txt", &exe_paths.join("\n"))
}

/// Deletes the policy files: the disable signal, since the injected hook
/// re-validates them on every intercepted call and stops binding new
/// sockets once they are gone. Also removes any legacy %TEMP% copies left
/// by older BiFlow versions. Attempts every deletion and reports the first
/// failure instead of silently pretending cleanup succeeded.
pub fn clear_target_ip() -> Result<(), String> {
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Ok(prog) = std::env::var("ProgramData") {
        let base = PathBuf::from(prog).join("BiFlow");
        paths.push(base.join("target_ip.txt"));
        paths.push(base.join("bypass_apps.txt"));
    }
    paths.push(std::env::temp_dir().join("biflow_target_ip.txt"));
    paths.push(std::env::temp_dir().join("BiFlow").join("bypass_apps.txt"));
    paths.push(std::env::temp_dir().join("BiFlow").join("target_ip.txt"));
    let mut first_err: Option<String> = None;
    for p in paths {
        if let Err(e) = fs::remove_file(&p) {
            if e.kind() != std::io::ErrorKind::NotFound && first_err.is_none() {
                first_err = Some(format!("Cannot delete {}: {}", p.display(), e));
            }
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// The dedicated hook-status directory: `%ProgramData%\BiFlow\status`.
/// It carries its own ACL (see STATUS_ACL_SDDL) that lets a target process
/// running with the user's normal token create its status report — under
/// the policy folder's read-only-for-users ACL the report could never be
/// written and every injection timed out as "not live".
pub(crate) fn hook_status_dir() -> Option<PathBuf> {
    biflow_programdata_dir().map(|d| d.join("status"))
}

/// Creates the status directory and applies its ACL, best effort: if it
/// cannot be prepared, the hook falls back to writing its report under
/// %TEMP%\BiFlow and the reader checks there too, so injection still works.
fn ensure_status_dir() {
    if let Some(dir) = hook_status_dir() {
        let _ = fs::create_dir_all(&dir);
        if let Err(e) = apply_status_acl(&dir) {
            // The fallback to %TEMP% keeps injection working, but the
            // degradation is recorded instead of passing silently.
            crate::config::append_log(&format!("STATUS_DIR_ACL_FAILED {}", e));
        }
    }
}

/// Removes hook status files left behind by processes that have exited.
/// Called once at startup, before any new injection happens.
pub fn clear_stale_hook_status() {
    for dir in hook_status_dirs() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("hook_status_") && name.ends_with(".txt") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}

fn hook_status_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(prog) = std::env::var("ProgramData") {
        let base = PathBuf::from(prog).join("BiFlow");
        dirs.push(base.join("status"));
        dirs.push(base);
    }
    dirs.push(std::env::temp_dir().join("BiFlow"));
    dirs
}

/// Waits for the injected DLL to report how many hooks it actually
/// installed. This is what makes the UI's "Live" state honest: a successful
/// LoadLibraryW alone does not prove the Winsock hooks are active.
fn wait_for_hook_status(pid: u32) -> Result<u32, String> {
    let deadline = Instant::now() + Duration::from_millis(2500);
    loop {
        for dir in hook_status_dirs() {
            let path = dir.join(format!("hook_status_{}.txt", pid));
            if let Ok(content) = fs::read_to_string(&path) {
                let content = content.trim().to_string();
                if let Some(rest) = content.strip_prefix("OK ") {
                    let Ok(n) = rest.trim().parse::<u32>() else {
                        return Err(format!(
                            "Hook DLL in PID {} sent an unparseable hook report: {}",
                            pid, content
                        ));
                    };
                    if n >= 5 {
                        return Ok(n);
                    }
                    return Err(format!(
                        "Hook DLL in PID {} installed only {}/5 hooks",
                        pid, n
                    ));
                }
                if content.starts_with("ERR") {
                    return Err(format!("Hook DLL in PID {} reported: {}", pid, content));
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "Hook DLL in PID {} did not report its hook status (hooks may not be active)",
                pid
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Checks (by module enumeration) that our DLL is really loaded in the
/// target process. Returns None when enumeration is not possible, in which
/// case the caller falls back to the LoadLibraryW exit code.
fn process_has_our_module(pid: u32) -> Option<bool> {
    let target = hook_dll_file_name().to_ascii_lowercase();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: MODULEENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        let mut found = false;
        if Module32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szModule[..entry
                        .szModule
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szModule.len())],
                );
                if name.to_ascii_lowercase() == target {
                    found = true;
                    break;
                }
                if Module32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        Some(found)
    }
}

/// Creation timestamp (FILETIME ticks) of a process. Used to tell a live
/// process apart from a new process that reused its PID.
pub fn process_creation_time(pid: u32) -> Option<u64> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return None;
        }
        let mut creation: FILETIME = std::mem::zeroed();
        let mut exit_t: FILETIME = std::mem::zeroed();
        let mut kernel: FILETIME = std::mem::zeroed();
        let mut user: FILETIME = std::mem::zeroed();
        let ok = GetProcessTimes(process, &mut creation, &mut exit_t, &mut kernel, &mut user);
        CloseHandle(process);
        if ok == 0 {
            None
        } else {
            Some(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
        }
    }
}

pub fn inject_dll_into_pid(pid: u32, dll_path: &Path) -> Result<(), String> {
    // Prepare the status-report directory and drop any stale report for
    // this PID, so the wait at the end can only be satisfied by a report
    // written for THIS injection (a leftover or planted file must not be
    // able to fake a "live" result).
    ensure_status_dir();
    for dir in hook_status_dirs() {
        let _ = fs::remove_file(dir.join(format!("hook_status_{}.txt", pid)));
    }

    let wide_path: Vec<u16> = dll_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let bytes_len = wide_path.len() * std::mem::size_of::<u16>();

    unsafe {
        let process: HANDLE = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ,
            0,
            pid,
        );

        if process.is_null() {
            return Err(format!(
                "Could not open process {} (error {})",
                pid,
                GetLastError()
            ));
        }

        // Architecture check: 64-bit DLL cannot be injected into 32-bit (WOW64) process
        let mut is_wow64: i32 = 0;
        if IsWow64Process(process, &mut is_wow64) != 0 && is_wow64 != 0 {
            CloseHandle(process);
            return Err(format!(
                "Skipping 32-bit (WOW64) process (PID {}) - incompatible with 64-bit DLL",
                pid
            ));
        }

        let remote_mem = VirtualAllocEx(
            process,
            null_mut(),
            bytes_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            CloseHandle(process);
            return Err(format!(
                "VirtualAllocEx failed in target process (error {})",
                GetLastError()
            ));
        }

        let mut written: usize = 0;
        let ok_write = WriteProcessMemory(
            process,
            remote_mem,
            wide_path.as_ptr() as *const _,
            bytes_len,
            &mut written,
        );

        if ok_write == 0 {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err(format!(
                "WriteProcessMemory failed (error {})",
                GetLastError()
            ));
        }

        let kernel32_name: Vec<u16> = OsStr::new("kernel32.dll")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let kernel32 = GetModuleHandleW(kernel32_name.as_ptr());
        let load_library_w = GetProcAddress(kernel32, c"LoadLibraryW".as_ptr() as *const u8);

        if load_library_w.is_none() {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err("LoadLibraryW address not found in kernel32.dll".into());
        }

        let thread: HANDLE = CreateRemoteThread(
            process,
            null_mut(),
            0,
            Some(std::mem::transmute::<
                Option<unsafe extern "system" fn() -> isize>,
                unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
            >(load_library_w)),
            remote_mem,
            0,
            null_mut(),
        );

        if thread.is_null() {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err(format!(
                "CreateRemoteThread failed (error {})",
                GetLastError()
            ));
        }

        let wait_res = WaitForSingleObject(thread, 3000);
        let mut exit_code: u32 = 0;
        GetExitCodeThread(thread, &mut exit_code);
        CloseHandle(thread);

        if wait_res == WAIT_TIMEOUT {
            // Do not free remote_mem if thread is still executing to prevent target crash
            CloseHandle(process);
            return Err(format!("Injection thread timed out for PID {}", pid));
        }

        VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(process);

        // GetExitCodeThread truncates the HMODULE to 32 bits; a module whose
        // base address has zero low bits would look like a failure. Verify
        // by module enumeration first and only then trust the exit code.
        match process_has_our_module(pid) {
            Some(true) => {}
            Some(false) => {
                return Err(format!(
                    "LoadLibraryW completed in PID {} but the hook DLL is not in its module list",
                    pid
                ));
            }
            None => {
                if exit_code == 0 {
                    return Err(format!(
                        "LoadLibraryW returned NULL in PID {} (injection failed)",
                        pid
                    ));
                }
            }
        }
    }

    // The DLL is loaded; now require proof that its hooks were installed
    // before calling this injection "live".
    wait_for_hook_status(pid).map(|_| ())
}

/// Duplicates the shell (explorer.exe) primary token so a child process can
/// be created WITHOUT inheriting BiFlow's administrator token.
unsafe fn shell_primary_token() -> Option<HANDLE> {
    let hwnd = GetShellWindow();
    if hwnd.is_null() {
        return None;
    }
    let mut shell_pid = 0u32;
    GetWindowThreadProcessId(hwnd, &mut shell_pid);
    if shell_pid == 0 {
        return None;
    }
    let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, shell_pid);
    if proc.is_null() {
        return None;
    }
    let mut token: HANDLE = null_mut();
    let ok = OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &mut token);
    CloseHandle(proc);
    if ok == 0 {
        return None;
    }
    let mut primary: HANDLE = null_mut();
    // Least privilege for the duplicated primary token: only the rights
    // CreateProcessWithTokenW and the logon plumbing actually need,
    // instead of TOKEN_ALL_ACCESS on a token that becomes another
    // process's identity.
    let ok = DuplicateTokenEx(
        token,
        TOKEN_ASSIGN_PRIMARY
            | TOKEN_DUPLICATE
            | TOKEN_QUERY
            | TOKEN_ADJUST_DEFAULT
            | TOKEN_ADJUST_SESSIONID,
        null_mut(),
        SecurityImpersonation,
        TokenPrimary,
        &mut primary,
    );
    CloseHandle(token);
    if ok == 0 {
        None
    } else {
        Some(primary)
    }
}

pub struct LaunchOutcome {
    pub pid: u32,
    /// True when the process was started with the shell's medium-integrity
    /// token (the normal, safe case); false when it had to inherit BiFlow's
    /// elevated token as a fallback.
    pub unelevated: bool,
}

pub fn launch_with_bypass(exe: &Path, target_ip: &str) -> Result<LaunchOutcome, String> {
    let dll_path = ensure_dll_extracted()?;
    update_target_ip(target_ip)?;

    let exe_name = exe
        .file_name()
        .map(|f| f.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let wide_exe: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let parent_dir = exe.parent().unwrap_or(Path::new("."));
    let wide_dir: Vec<u16> = parent_dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // For Chromium browsers (exact file names only), add flags to allow DLL
    // injection and bypass the system proxy directly. This weakens the
    // browser sandbox and is disclosed in the UI status after launch.
    let is_chromium = matches!(exe_name.as_str(), "chrome.exe" | "msedge.exe" | "brave.exe");
    let make_cmd_line = || -> Vec<u16> {
        let cmd_str = if is_chromium {
            format!(
                "\"{}\" --disable-features=RendererCodeIntegrity --no-proxy-server",
                exe.display()
            )
        } else {
            format!("\"{}\"", exe.display())
        };
        cmd_str.encode_utf16().chain(std::iter::once(0)).collect()
    };

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // Start the app at the user's normal integrity level whenever possible:
    // a browser or game must not run as Administrator just because BiFlow
    // itself is elevated.
    let mut unelevated = false;
    let mut cmd_line = make_cmd_line();
    let success = unsafe {
        let mut created = 0;
        if let Some(token) = shell_primary_token() {
            created = CreateProcessWithTokenW(
                token,
                LOGON_WITH_PROFILE,
                wide_exe.as_ptr(),
                cmd_line.as_mut_ptr(),
                CREATE_SUSPENDED,
                null_mut(),
                wide_dir.as_ptr(),
                &si,
                &mut pi,
            );
            CloseHandle(token);
            if created != 0 {
                unelevated = true;
            }
        }
        if created == 0 {
            // Fallback: inherit BiFlow's token (elevated). The caller is told
            // via LaunchOutcome.unelevated == false so the UI can warn.
            cmd_line = make_cmd_line();
            CreateProcessW(
                wide_exe.as_ptr(),
                cmd_line.as_mut_ptr(),
                null_mut(),
                null_mut(),
                0,
                CREATE_SUSPENDED,
                null_mut(),
                wide_dir.as_ptr(),
                &si,
                &mut pi,
            )
        } else {
            created
        }
    };

    if success == 0 {
        return Err(format!(
            "Failed to start application (Win32 error {})",
            unsafe { GetLastError() }
        ));
    }

    let pid = pi.dwProcessId;

    // Inject our hook DLL into the still-suspended process.
    let inject_res = inject_dll_into_pid(pid, &dll_path);

    match inject_res {
        Ok(()) => {
            unsafe {
                ResumeThread(pi.hThread);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
            Ok(LaunchOutcome { pid, unelevated })
        }
        Err(e) => {
            // Never leave a silently un-bypassed copy running: the user asked
            // for this app to start WITH the bypass, so a failed injection
            // terminates the suspended process and reports honestly.
            unsafe {
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
            Err(format!(
                "Injection failed; the launched process was terminated so it does not run without the bypass: {}",
                e
            ))
        }
    }
}

/// Find PIDs whose full executable path matches `exe` (case-insensitive).
/// Matching is by full path only: same-name binaries in other folders
/// are never matched, so injection and connection teardown target the
/// right app. (A basename-matching finder used to exist here and was
/// removed deliberately: basename ambiguity is what the rest of the
/// codebase is designed to avoid.)
pub fn find_pids_by_exe_path(exe: &Path) -> Vec<u32> {
    let target = exe.to_string_lossy().to_ascii_lowercase();
    let mut pids = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return pids;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let pid = entry.th32ProcessID;
                if pid > 4 {
                    if let Some(path) = get_process_full_path(pid) {
                        if path.to_ascii_lowercase() == target {
                            pids.push(pid);
                        }
                    }
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }

    pids
}

pub(crate) fn resolve_executable_path(name: &str) -> Option<String> {
    if Path::new(name).is_absolute() && Path::new(name).exists() {
        return Some(name.to_string());
    }

    // 1. Check Windows App Paths in HKLM and HKCU
    for hive in [
        winreg::enums::HKEY_LOCAL_MACHINE,
        winreg::enums::HKEY_CURRENT_USER,
    ] {
        let key_path = format!(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{}",
            name
        );
        if let Ok(key) = winreg::RegKey::predef(hive).open_subkey(&key_path) {
            if let Ok(val) = key.get_value::<String, _>("") {
                let clean = val.trim().trim_matches('"');
                if Path::new(clean).exists() {
                    return Some(clean.to_string());
                }
            }
        }
    }

    // 2. Check System directories
    if let Ok(sys_root) = std::env::var("SystemRoot") {
        let p32 = Path::new(&sys_root).join("System32").join(name);
        if p32.exists() {
            return Some(p32.to_string_lossy().to_string());
        }
        let p_root = Path::new(&sys_root).join(name);
        if p_root.exists() {
            return Some(p_root.to_string_lossy().to_string());
        }
    }

    // 3. In-memory check against PATH environment variable (zero subprocesses, zero console windows)
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }

    None
}

pub(crate) fn get_process_full_path(pid: u32) -> Option<String> {
    // Long-path aware: the buffer covers the full Win32 long path limit.
    // It is allocated once per thread and reused: this runs once per PID
    // per process-map pass, and a fresh 64 KiB vector per call meant
    // ~19 MB of transient allocation for a 300-process pass.
    thread_local! {
        static PATH_BUF: std::cell::RefCell<Vec<u16>> =
            std::cell::RefCell::new(vec![0u16; 32767]);
    }
    PATH_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        for access in [PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_QUERY_INFORMATION] {
            unsafe {
                let process = OpenProcess(access, 0, pid);
                if process.is_null() {
                    continue;
                }
                let mut len = buf.len() as u32;
                let success = QueryFullProcessImageNameW(process, 0, buf.as_mut_ptr(), &mut len);
                CloseHandle(process);
                if success != 0 && len > 0 {
                    return Some(String::from_utf16_lossy(&buf[..len as usize]));
                }
            }
        }
        None
    })
}

/// (PID -> parent PID, PID -> full executable path). There is
/// deliberately no basename map: status decisions must use full paths,
/// and the basename map an earlier version built here was discarded by
/// every caller while still costing a pass over all processes.
pub type ProcessMaps = (
    std::collections::HashMap<u32, u32>,
    std::collections::HashMap<u32, String>,
);

pub fn get_process_maps() -> ProcessMaps {
    let mut parents: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    let mut paths: std::collections::HashMap<u32, String> = std::collections::HashMap::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return (parents, paths);
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );
                let pid = entry.th32ProcessID;
                let parent_pid = entry.th32ParentProcessID;

                if pid > 4 {
                    parents.insert(pid, parent_pid);

                    if let Some(path) = get_process_full_path(pid) {
                        paths.insert(pid, path);
                    } else if let Some(path) = resolve_executable_path(&name) {
                        paths.insert(pid, path);
                    }
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }

    (parents, paths)
}

pub fn get_running_gui_processes() -> Vec<(u32, String, String)> {
    let mut procs = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return procs;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );
                let pid = entry.th32ProcessID;

                // Filter out system internal OS processes
                let lower = name.to_ascii_lowercase();
                let skip = [
                    "smss.exe",
                    "csrss.exe",
                    "wininit.exe",
                    "services.exe",
                    "lsass.exe",
                    "fontdrvhost.exe",
                    "winlogon.exe",
                    "dwm.exe",
                    "sihost.exe",
                    "taskhostw.exe",
                    "biflow.exe",
                ];

                if !skip.contains(&lower.as_str()) && lower.ends_with(".exe") && pid > 4 {
                    let full_path =
                        get_process_full_path(pid).or_else(|| resolve_executable_path(&name));

                    if let Some(path) = full_path {
                        if Path::new(&path).is_absolute() {
                            procs.push((pid, name.clone(), path));
                        }
                    }
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }

    // De-duplicate by full path (not by file name): the same exe name in two
    // different folders is two different applications.
    procs.sort_by_key(|a| a.2.to_ascii_lowercase());
    procs.dedup_by(|a, b| a.2.eq_ignore_ascii_case(&b.2));
    procs
}
