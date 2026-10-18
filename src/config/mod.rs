use crate::models::Store;
use std::{
    fs, io,
    path::PathBuf,
};

pub fn data_dir() -> PathBuf {
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
    fs::write(&tmp, text)?;
    if path.exists() {
        let _ = fs::remove_file(&path);
    }
    fs::rename(tmp, path)?;
    Ok(())
}

/// Maximum diagnostic log size before rotation (2 MiB).
const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

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
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            writeln!(f, "[{}] {}", timestamp, line)
        });
}
