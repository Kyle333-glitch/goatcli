#![deny(unsafe_op_in_unsafe_fn)]

use napi::{
    bindgen_prelude::{FnArgs, Result, Utf16String},
    threadsafe_function::ThreadsafeFunction,
    Env, Status,
};
use napi_derive::napi;

#[cfg(not(windows))]
use napi::Error;

mod command_line;

#[napi(js_name = "WINDOWS_PRIVACY_SPAWN_ABI_VERSION")]
pub const WINDOWS_PRIVACY_SPAWN_ABI_VERSION: u32 = 1;

#[napi(object, object_to_js = false)]
pub struct SpawnWindowsPrivacyEnvironmentEntry {
    pub name: Utf16String,
    pub value: Utf16String,
}

#[napi(object, object_to_js = false)]
pub struct SpawnWindowsPrivacyRequest {
    pub command: Utf16String,
    pub args: Vec<Utf16String>,
    pub cwd: Option<Utf16String>,
    pub env: Vec<SpawnWindowsPrivacyEnvironmentEntry>,
    pub windows_hide: bool,
    pub detached: bool,
}

type ExitCallback = ThreadsafeFunction<
    FnArgs<(Option<u32>, Option<String>)>,
    (),
    FnArgs<(Option<u32>, Option<String>)>,
    Status,
    false,
>;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::SpawnedWindowsPrivacyProcess;

#[cfg(windows)]
#[napi(js_name = "spawnWindowsPrivacyProcess")]
pub fn spawn_windows_privacy_process(
    env: Env,
    request: SpawnWindowsPrivacyRequest,
    on_exit: ExitCallback,
) -> Result<SpawnedWindowsPrivacyProcess> {
    windows::spawn(&env, request, on_exit)
}

#[cfg(not(windows))]
#[napi]
pub struct SpawnedWindowsPrivacyProcess;

#[cfg(not(windows))]
#[napi]
impl SpawnedWindowsPrivacyProcess {
    #[napi(getter)]
    pub fn pid(&self) -> u32 {
        0
    }

    #[napi]
    pub fn take_launcher_write_fd(&self) -> i32 {
        -1
    }

    #[napi]
    pub fn take_launcher_read_fd(&self) -> i32 {
        -1
    }

    #[napi]
    pub fn terminate(&self) -> bool {
        false
    }

    #[napi]
    pub fn close(&self) {}
}

#[cfg(not(windows))]
#[napi(js_name = "spawnWindowsPrivacyProcess")]
pub fn spawn_windows_privacy_process(
    env: Env,
    _request: SpawnWindowsPrivacyRequest,
    _on_exit: ExitCallback,
) -> Result<SpawnedWindowsPrivacyProcess> {
    env.throw_error(
        "Native Windows process creation failed.",
        Some("GOAT_NATIVE_PROCESS_CREATE_FAILED"),
    )?;
    Err(Error::new(
        Status::PendingException,
        "Native Windows process creation failed.",
    ))
}
