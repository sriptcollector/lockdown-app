// Starts the Lockdown engine next to the app, reads the port and one-time token it prints, and
// hands them to the window. The engine only listens on 127.0.0.1 and rejects requests without
// the token. It is stopped when the app quits.
use serde::Serialize;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use tauri::{Manager, RunEvent, State};

#[derive(Clone, Serialize, serde::Deserialize)]
struct EngineInfo {
    port: u16,
    token: String,
}

#[derive(Default)]
struct Engine {
    info: Mutex<Option<EngineInfo>>,
    child: Mutex<Option<Child>>,
}

#[tauri::command]
fn engine_info(engine: State<'_, Engine>) -> Option<EngineInfo> {
    engine.info.lock().unwrap().clone()
}

fn engine_path() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("exe path");
    let dir = exe.parent().expect("exe dir").to_path_buf();
    let name = if cfg!(windows) { "lockdown-engine.exe" } else { "lockdown-engine" };
    dir.join(name)
}

fn start_engine(app: &tauri::AppHandle) {
    let engine = app.state::<Engine>();
    let mut cmd = Command::new(engine_path());
    cmd.arg("serve").stdout(Stdio::piped()).stderr(Stdio::null()).stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let Ok(mut child) = cmd.spawn() else { return };
    let stdout = child.stdout.take();
    *engine.child.lock().unwrap() = Some(child);
    let handle = app.clone();
    std::thread::spawn(move || {
        let Some(out) = stdout else { return };
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if let Ok(info) = serde_json::from_str::<EngineInfo>(&line) {
                *handle.state::<Engine>().info.lock().unwrap() = Some(info);
            }
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(Engine::default())
        .invoke_handler(tauri::generate_handler![engine_info])
        .setup(|app| {
            start_engine(app.handle());
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Lockdown");
    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            if let Some(mut c) = handle.state::<Engine>().child.lock().unwrap().take() {
                let _ = c.kill();
            }
        }
    });
}
