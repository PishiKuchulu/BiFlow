use crate::models::Store;
use std::{
    fs, io,
    path::PathBuf,
    sync::OnceLock,
};

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn data_dir() -> PathBuf {
    DATA_DIR
        .get_or_init(|| {
            // Check if local portable "data" directory exists next to exe
            if let Ok(exe) = std::env::current_exe() {
                if let Some(parent) = exe.parent() {
                    let portable_data = parent.join("data");
                    if portable_data.is_dir() {
                        return portable_data;
                    }
                }
            }

            // Default to %LOCALAPPDATA%\BiFlow
            if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
                let p = PathBuf::from(local_appdata).join("BiFlow");
                let _ = fs::create_dir_all(&p);
                return p;
            }

            // Fallback
            PathBuf::from("data")
        })
        .clone()
}

pub fn store_path() -> PathBuf {
    data_dir().join("biflow_config.json")
}

pub fn log_path() -> PathBuf {
    data_dir().join("biflow.log")
}

pub fn load() -> io::Result<Store> {
    let path = store_path();
    if !path.exists() {
        return Ok(Store::default());
    }
    // Read errors (locked file, antivirus, permissions) propagate as Err so
    // the caller can tell "no config yet" apart from "config unreadable"
    // and avoid overwriting the real config with defaults on the next save.
    let raw = fs::read_to_string(&path)?;
    match serde_json::from_str(&raw) {
        Ok(v) => Ok(v),
        Err(_) => {
            // Never silently discard the user's config: back the corrupt
            // file up before falling back to defaults.
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let backup = path.with_extension(format!("json.corrupt.{}", ts));
            let _ = fs::rename(&path, &backup);
            Ok(Store::default())
        }
    }
}

pub fn save(store: &Store) -> io::Result<()> {
    let dir = data_dir();
    fs::create_dir_all(&dir)?;
    let path = store_path();
    let tmp = path.with_extension("tmp");
    // Propagate serialization errors instead of writing an empty file that
    // would destroy the user's configuration.
    let text = serde_json::to_string_pretty(store)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    {
        use std::io::Write;
        let mut f = fs::File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        // Flush to disk before the rename so a crash/power loss cannot leave
        // a torn config behind.
        f.sync_all()?;
    }
    // std::fs::rename replaces the destination atomically on Windows
    // (MoveFileEx with REPLACE_EXISTING). The previous remove-then-rename
    // sequence had a window in which NO config file existed at all.
    fs::rename(tmp, path)?;
    Ok(())
}

/// Maximum diagnostic log size before rotation (2 MiB).
const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

/// Formats Unix seconds as "YYYY-MM-DD HH:MM:SS UTC" (civil-date conversion,
/// no external crates) so log lines are human-readable.
fn format_timestamp_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
    let (hh, mm, ss) = (secs_of_day / 3600, (secs_of_day % 3600) / 60, secs_of_day % 60);
    // Howard Hinnant's civil-from-days algorithm.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, m, d, hh, mm, ss
    )
}

pub fn append_log(line: &str) {
    let _ = fs::create_dir_all(data_dir());
    let path = log_path();
    // Rotate the log instead of growing it without bound.
    if let Ok(meta) = fs::metadata(&path) {
        if meta.len() > MAX_LOG_BYTES {
            let _ = fs::rename(&path, path.with_extension("log.old"));
        }
    }
    let _ = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| {
            use std::io::Write;
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            writeln!(f, "[{}] {}", format_timestamp_utc(secs), line)
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_format_is_human_readable() {
        assert_eq!(format_timestamp_utc(0), "1970-01-01 00:00:00 UTC");
        // 2026-10-23 11:45:00 UTC
        assert_eq!(format_timestamp_utc(1_792_755_900), "2026-10-23 11:45:00 UTC");
    }
}
