use std::{
    cmp::Ordering,
    ffi::c_void,
    mem::size_of,
    ptr::{null, null_mut},
    sync::{mpsc, Arc, Mutex, OnceLock},
    thread,
};

use napi::{
    bindgen_prelude::{FnArgs, Result},
    threadsafe_function::ThreadsafeFunctionCallMode,
    Env, Error, Status,
};
use napi_derive::napi;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, DuplicateHandle, GetHandleInformation, SetHandleInformation,
        DUPLICATE_SAME_ACCESS, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    },
    Globalization::{CompareStringOrdinal, CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{GetFileType, FILE_TYPE_CHAR, FILE_TYPE_PIPE},
    System::{
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        Pipes::CreatePipe,
        Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
            InitializeProcThreadAttributeList, RegisterWaitForSingleObject, ResumeThread,
            TerminateProcess, UnregisterWaitEx, UpdateProcThreadAttribute,
            CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
            DETACHED_PROCESS, EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST,
            PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESHOWWINDOW,
            STARTF_USESTDHANDLES, STARTUPINFOEXW, WT_EXECUTEONLYONCE,
        },
    },
};

use crate::{
    command_line::{build_command_line, ensure_no_nul, validate_environment_entry, InputError},
    ExitCallback, SpawnWindowsPrivacyEnvironmentEntry, SpawnWindowsPrivacyRequest,
};

const CRT_FOPEN: u8 = 0x01;
const CRT_FPIPE: u8 = 0x08;
const CRT_FDEV: u8 = 0x40;
const PRIVACY_FD_COUNT: usize = 5;
const TERMINATED_EXIT_CODE: u32 = 1;

#[cfg(test)]
#[link(name = "ucrt")]
unsafe extern "C" {
    fn _close(fd: i32) -> i32;
    fn _get_osfhandle(fd: i32) -> isize;
    fn _open_osfhandle(handle: isize, flags: i32) -> i32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    Process,
    PrivacyPipe,
}

type InternalResult<T> = std::result::Result<T, FailureKind>;

type UvOpenOsfhandle = unsafe extern "C" fn(HANDLE) -> i32;
type UvGetOsfhandle = unsafe extern "C" fn(i32) -> HANDLE;

struct NodeUvFunctions {
    open_osfhandle: UvOpenOsfhandle,
    get_osfhandle: UvGetOsfhandle,
}

static NODE_UV_FUNCTIONS: OnceLock<Option<NodeUvFunctions>> = OnceLock::new();

fn node_uv_functions() -> Option<&'static NodeUvFunctions> {
    NODE_UV_FUNCTIONS
        .get_or_init(resolve_node_uv_functions)
        .as_ref()
}

fn resolve_node_uv_functions() -> Option<NodeUvFunctions> {
    // Node statically links libuv and exports these public APIs from the main executable. Loading
    // them dynamically avoids a build-time dependency on a version-specific `node.lib` while
    // ensuring returned descriptors belong to Node's CRT table rather than this addon module's.
    // SAFETY: a null module name selects the current process executable.
    let module = unsafe { GetModuleHandleW(null()) };
    if module.is_null() {
        return local_uv_functions_for_tests();
    }

    // SAFETY: both names are NUL-terminated ASCII and the module remains loaded for process life.
    let open = unsafe { GetProcAddress(module, c"uv_open_osfhandle".as_ptr().cast::<u8>()) };
    // SAFETY: same reasoning as above.
    let get = unsafe { GetProcAddress(module, c"uv_get_osfhandle".as_ptr().cast::<u8>()) };
    let (Some(open), Some(get)) = (open, get) else {
        return local_uv_functions_for_tests();
    };

    // SAFETY: these are the documented libuv C exports with the exact signatures declared above.
    let open_osfhandle = unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, UvOpenOsfhandle>(open)
    };
    // SAFETY: as above, for `uv_get_osfhandle`.
    let get_osfhandle =
        unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, UvGetOsfhandle>(get) };
    Some(NodeUvFunctions {
        open_osfhandle,
        get_osfhandle,
    })
}

#[cfg(not(test))]
fn local_uv_functions_for_tests() -> Option<NodeUvFunctions> {
    None
}

#[cfg(test)]
fn local_uv_functions_for_tests() -> Option<NodeUvFunctions> {
    unsafe extern "C" fn open_osfhandle(handle: HANDLE) -> i32 {
        // SAFETY: the test process owns `handle` and transfers it to its local CRT table.
        unsafe { _open_osfhandle(handle as isize, 0) }
    }

    unsafe extern "C" fn get_osfhandle(fd: i32) -> HANDLE {
        // SAFETY: the descriptor remains borrowed from the test process's local CRT table.
        unsafe { _get_osfhandle(fd) as HANDLE }
    }

    Some(NodeUvFunctions {
        open_osfhandle,
        get_osfhandle,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostCreateStage {
    Created,
    LauncherWriteFdCreated,
    LauncherReadFdCreated,
    WaitHandleCreated,
    WaiterReady,
    BeforeResume,
    AfterResume,
}

trait SpawnHooks {
    fn process_created(&self, _pid: u32, _process: HANDLE) -> InternalResult<()> {
        Ok(())
    }

    fn checkpoint(&self, _stage: PostCreateStage) -> InternalResult<()> {
        Ok(())
    }
}

struct NoSpawnHooks;

impl SpawnHooks for NoSpawnHooks {}

trait ExitNotifier: Send + 'static {
    fn notify(self: Box<Self>, exit_code: Option<u32>);
}

struct JsExitNotifier(ExitCallback);

impl ExitNotifier for JsExitNotifier {
    fn notify(self: Box<Self>, exit_code: Option<u32>) {
        self.0.call(
            FnArgs::from((exit_code, None)),
            ThreadsafeFunctionCallMode::NonBlocking,
        );
    }
}

impl From<InputError> for FailureKind {
    fn from(_: InputError) -> Self {
        Self::Process
    }
}

impl FailureKind {
    fn code(self) -> &'static str {
        match self {
            Self::Process => "GOAT_NATIVE_PROCESS_CREATE_FAILED",
            Self::PrivacyPipe => "GOAT_NATIVE_PRIVACY_PIPE_FAILED",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Process => "Native Windows process creation failed.",
            Self::PrivacyPipe => "Native Windows privacy pipe creation failed.",
        }
    }

    fn throw<T>(self, env: &Env) -> Result<T> {
        env.throw_error(self.message(), Some(self.code()))?;
        Err(Error::new(Status::PendingException, self.message()))
    }
}

struct OwnedHandle(Option<HANDLE>);

// Windows kernel handles can be used and closed from a different thread.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    fn new(handle: HANDLE) -> InternalResult<Self> {
        if is_invalid_handle(handle) {
            return Err(FailureKind::Process);
        }
        Ok(Self(Some(handle)))
    }

    fn raw(&self) -> HANDLE {
        self.0.expect("owned handle must be present")
    }

    fn take(&mut self) -> HANDLE {
        self.0.take().expect("owned handle must be present")
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            // SAFETY: `OwnedHandle` has unique ownership and closes the handle once.
            unsafe {
                CloseHandle(handle);
            }
        }
    }
}

struct AttributeList {
    storage: Box<[usize]>,
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl AttributeList {
    fn new(handles: &mut [HANDLE]) -> InternalResult<Self> {
        let mut bytes = 0usize;
        // SAFETY: the documented sizing call uses a null list and writes only `bytes`.
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(FailureKind::Process);
        }

        let words = bytes.div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; words].into_boxed_slice();
        let pointer = storage.as_mut_ptr().cast();
        // SAFETY: storage is aligned, writable, and at least the requested byte length.
        if unsafe { InitializeProcThreadAttributeList(pointer, 1, 0, &mut bytes) } == 0 {
            return Err(FailureKind::Process);
        }

        let list = Self { storage, pointer };
        // SAFETY: all listed handles are valid inheritable handles and remain alive through
        // `CreateProcessW`; the attribute list storage remains allocated in `list`.
        let updated = unsafe {
            UpdateProcThreadAttribute(
                list.pointer,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_mut_ptr().cast::<c_void>(),
                std::mem::size_of_val(handles),
                null_mut(),
                null_mut(),
            )
        };
        if updated == 0 {
            // Keep the initialized list alive so its `Drop` performs the matching delete.
            return Err(FailureKind::Process);
        }
        Ok(list)
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // Read the field to make the storage lifetime relationship explicit to the compiler and
        // reviewers; `DeleteProcThreadAttributeList` must run before storage is freed.
        let _ = self.storage.len();
        // SAFETY: `pointer` was successfully initialized exactly once.
        unsafe {
            DeleteProcThreadAttributeList(self.pointer);
        }
    }
}

struct WaitCallbackContext {
    signal_sender: mpsc::SyncSender<()>,
}

struct RegisteredProcessWait {
    registration: Option<HANDLE>,
    context: Option<Box<WaitCallbackContext>>,
    signal_receiver: mpsc::Receiver<()>,
}

// The registration handle is valid across threads, and the boxed callback context remains pinned
// until `UnregisterWaitEx` has synchronously drained any callback.
unsafe impl Send for RegisteredProcessWait {}

impl RegisteredProcessWait {
    fn new(process: HANDLE) -> InternalResult<Self> {
        let (signal_sender, signal_receiver) = mpsc::sync_channel(1);
        let context = Box::new(WaitCallbackContext { signal_sender });
        let context_pointer = std::ptr::from_ref(context.as_ref()).cast::<c_void>();
        let mut registration = INVALID_HANDLE_VALUE;
        // SAFETY: the process handle and callback remain valid; `context` is pinned in its Box
        // until a synchronous unregister has completed.
        let registered = unsafe {
            RegisterWaitForSingleObject(
                &mut registration,
                process,
                Some(process_wait_callback),
                context_pointer,
                INFINITE,
                WT_EXECUTEONLYONCE,
            )
        };
        if registered == 0 || is_invalid_handle(registration) {
            return Err(FailureKind::Process);
        }
        Ok(Self {
            registration: Some(registration),
            context: Some(context),
            signal_receiver,
        })
    }

    fn wait_for_signal(&mut self) -> bool {
        let signaled = self.signal_receiver.recv().is_ok();
        self.unregister();
        signaled
    }

    fn unregister(&mut self) {
        let Some(registration) = self.registration.take() else {
            return;
        };
        let context = self
            .context
            .take()
            .expect("registered wait must retain its callback context");
        // SAFETY: this registration is uniquely owned. `INVALID_HANDLE_VALUE` requests that any
        // in-flight callback finish before this call returns.
        let unregistered = unsafe { UnregisterWaitEx(registration, INVALID_HANDLE_VALUE) };
        if unregistered == 0 {
            // We cannot prove that Windows has stopped using the callback pointer. Leaking the
            // context is the only memory-safe fallback; the bounded leak occurs only on an
            // unexpected kernel API failure.
            let _ = Box::leak(context);
        }
    }
}

impl Drop for RegisteredProcessWait {
    fn drop(&mut self) {
        self.unregister();
    }
}

unsafe extern "system" fn process_wait_callback(context: *mut c_void, _timed_out: bool) {
    // SAFETY: `RegisteredProcessWait` keeps this boxed context alive until synchronous unregister.
    let context = unsafe { &*context.cast::<WaitCallbackContext>() };
    let _ = context.signal_sender.send(());
}

struct ChildStandardHandle {
    handle: OwnedHandle,
    crt_flags: u8,
}

struct ProcessState {
    control_handle: Mutex<Option<OwnedHandle>>,
}

impl ProcessState {
    fn new(control_handle: OwnedHandle) -> Self {
        Self {
            control_handle: Mutex::new(Some(control_handle)),
        }
    }

    fn close(&self) {
        self.control_handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }

    fn raw(&self) -> Option<HANDLE> {
        self.control_handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(OwnedHandle::raw)
    }

    fn terminate(&self) -> bool {
        let guard = self
            .control_handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(handle) = guard.as_ref() else {
            return false;
        };

        let mut exit_code = 0u32;
        // SAFETY: the process handle stays alive while the mutex guard is held.
        if unsafe { GetExitCodeProcess(handle.raw(), &mut exit_code) } == 0 || exit_code != 259 {
            return false;
        }
        // SAFETY: the process handle stays alive while the mutex guard is held.
        unsafe { TerminateProcess(handle.raw(), TERMINATED_EXIT_CODE) != 0 }
    }
}

struct SuspendedChildGuard {
    state: Arc<ProcessState>,
    primary_thread: OwnedHandle,
    armed: bool,
}

impl SuspendedChildGuard {
    fn new(process_info: PROCESS_INFORMATION) -> Self {
        let process_handle = OwnedHandle(Some(process_info.hProcess));
        let primary_thread = OwnedHandle(Some(process_info.hThread));
        Self {
            state: Arc::new(ProcessState::new(process_handle)),
            primary_thread,
            armed: true,
        }
    }

    fn process_handle(&self) -> HANDLE {
        self.state
            .raw()
            .expect("suspended child must retain its process handle")
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SuspendedChildGuard {
    fn drop(&mut self) {
        if self.armed {
            self.state.terminate();
        }
    }
}

#[derive(Default)]
struct PipeFdState {
    launcher_write: Option<OwnedHandle>,
    launcher_read: Option<OwnedHandle>,
}

impl PipeFdState {
    fn take_write(&mut self) -> InternalResult<i32> {
        take_node_fd(&mut self.launcher_write)
    }

    fn take_read(&mut self) -> InternalResult<i32> {
        take_node_fd(&mut self.launcher_read)
    }

    fn close(&mut self) {
        self.launcher_write.take();
        self.launcher_read.take();
    }
}

fn take_node_fd(slot: &mut Option<OwnedHandle>) -> InternalResult<i32> {
    let functions = node_uv_functions().ok_or(FailureKind::PrivacyPipe)?;
    let mut handle = slot.take().ok_or(FailureKind::PrivacyPipe)?;
    let raw = handle.take();
    // SAFETY: this transfers the valid, non-inheritable launcher handle to Node's CRT table.
    let fd = unsafe { (functions.open_osfhandle)(raw) };
    if fd == -1 {
        // `_open_osfhandle` does not take ownership when descriptor allocation fails.
        // SAFETY: no descriptor was created and this function still owns `raw`.
        unsafe {
            CloseHandle(raw);
        }
        return Err(FailureKind::PrivacyPipe);
    }
    Ok(fd)
}

#[napi]
pub struct SpawnedWindowsPrivacyProcess {
    pid: u32,
    pipe_fds: Mutex<PipeFdState>,
    state: Arc<ProcessState>,
    #[cfg(feature = "test-hooks")]
    child_read_handle_for_test: f64,
    #[cfg(feature = "test-hooks")]
    child_write_handle_for_test: f64,
}

#[napi]
impl SpawnedWindowsPrivacyProcess {
    #[napi(getter)]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    #[napi]
    pub fn take_launcher_write_fd(&self, env: Env) -> Result<i32> {
        match self
            .pipe_fds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take_write()
        {
            Ok(fd) => Ok(fd),
            Err(failure) => failure.throw(&env),
        }
    }

    #[napi]
    pub fn take_launcher_read_fd(&self, env: Env) -> Result<i32> {
        match self
            .pipe_fds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take_read()
        {
            Ok(fd) => Ok(fd),
            Err(failure) => failure.throw(&env),
        }
    }

    #[napi]
    pub fn terminate(&self) -> bool {
        self.state.terminate()
    }

    #[napi]
    pub fn close(&self) {
        self.pipe_fds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .close();
        self.state.close();
    }
}

#[cfg(feature = "test-hooks")]
#[napi]
impl SpawnedWindowsPrivacyProcess {
    #[napi(getter)]
    pub fn child_read_handle_for_test(&self) -> f64 {
        self.child_read_handle_for_test
    }

    #[napi(getter)]
    pub fn child_write_handle_for_test(&self) -> f64 {
        self.child_write_handle_for_test
    }
}

impl Drop for SpawnedWindowsPrivacyProcess {
    fn drop(&mut self) {
        self.pipe_fds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .close();
        self.state.close();
    }
}

pub(crate) fn spawn(
    env: &Env,
    request: SpawnWindowsPrivacyRequest,
    on_exit: super::ExitCallback,
) -> Result<SpawnedWindowsPrivacyProcess> {
    match spawn_inner(request, Box::new(JsExitNotifier(on_exit)), &NoSpawnHooks) {
        Ok(process) => Ok(process),
        Err(failure) => failure.throw(env),
    }
}

fn spawn_inner(
    request: SpawnWindowsPrivacyRequest,
    on_exit: Box<dyn ExitNotifier>,
    hooks: &dyn SpawnHooks,
) -> InternalResult<SpawnedWindowsPrivacyProcess> {
    if !request.windows_hide || !request.detached {
        return Err(FailureKind::Process);
    }

    ensure_no_nul(&request.command)?;
    let raw_command_units = request.args.iter().try_fold(
        request.command.len().saturating_add(1),
        |length, argument| {
            length
                .checked_add(1)
                .and_then(|length| length.checked_add(argument.len()))
        },
    );
    if raw_command_units.is_none_or(|length| length > 32_767) {
        return Err(FailureKind::Process);
    }
    let mut application_name = request.command.to_vec();
    application_name.push(0);
    let args: Vec<Vec<u16>> = request
        .args
        .iter()
        .map(|argument| argument.to_vec())
        .collect();
    let mut command_line = build_command_line(&request.command, &args)?;
    let mut environment = build_environment_block(request.env)?;
    let current_directory = build_optional_wide(request.cwd.as_deref())?;

    let (child_request_read, parent_request_write) = create_anonymous_pipe(true)?;
    let (parent_response_read, child_response_write) = create_anonymous_pipe(false)?;

    let standard_handles = [0, 1, 2].map(duplicate_standard_handle);
    let standard_handles: [Option<ChildStandardHandle>; 3] = standard_handles
        .into_iter()
        .collect::<InternalResult<Vec<_>>>()?
        .try_into()
        .map_err(|_| FailureKind::Process)?;

    let invalid = INVALID_HANDLE_VALUE;
    let child_handles = [
        standard_handles[0]
            .as_ref()
            .map_or(invalid, |value| value.handle.raw()),
        standard_handles[1]
            .as_ref()
            .map_or(invalid, |value| value.handle.raw()),
        standard_handles[2]
            .as_ref()
            .map_or(invalid, |value| value.handle.raw()),
        child_request_read.raw(),
        child_response_write.raw(),
    ];
    let crt_flags = [
        standard_handles[0]
            .as_ref()
            .map_or(0, |value| value.crt_flags),
        standard_handles[1]
            .as_ref()
            .map_or(0, |value| value.crt_flags),
        standard_handles[2]
            .as_ref()
            .map_or(0, |value| value.crt_flags),
        CRT_FOPEN | CRT_FPIPE,
        CRT_FOPEN | CRT_FPIPE,
    ];
    let mut crt_table = build_crt_descriptor_table(child_handles, crt_flags);

    let mut inherited_handles = collect_inherited_handles(child_handles);
    let attribute_list = AttributeList::new(&mut inherited_handles)?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    startup.StartupInfo.wShowWindow = 0;
    startup.StartupInfo.cbReserved2 =
        u16::try_from(crt_table.len()).map_err(|_| FailureKind::Process)?;
    startup.StartupInfo.lpReserved2 = crt_table.as_mut_ptr();
    startup.StartupInfo.hStdInput = child_handles[0];
    startup.StartupInfo.hStdOutput = child_handles[1];
    startup.StartupInfo.hStdError = child_handles[2];
    startup.lpAttributeList = attribute_list.pointer;

    let mut process_info = PROCESS_INFORMATION::default();
    let cwd_pointer = current_directory
        .as_ref()
        .map_or(null(), |cwd| cwd.as_ptr());
    let creation_flags = CREATE_UNICODE_ENVIRONMENT
        | EXTENDED_STARTUPINFO_PRESENT
        | DETACHED_PROCESS
        | CREATE_NEW_PROCESS_GROUP
        | CREATE_SUSPENDED;
    // SAFETY: all pointers reference initialized, live buffers through the call. The attribute
    // list contains every valid handle referenced by the five-entry CRT table and no others.
    let created = unsafe {
        CreateProcessW(
            application_name.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            1,
            creation_flags,
            environment.as_mut_ptr().cast::<c_void>(),
            cwd_pointer,
            &startup.StartupInfo,
            &mut process_info,
        )
    };
    if created == 0 {
        return Err(FailureKind::Process);
    }

    let pid = process_info.dwProcessId;
    let mut suspended_child = SuspendedChildGuard::new(process_info);
    hooks.process_created(pid, suspended_child.process_handle())?;
    hooks.checkpoint(PostCreateStage::Created)?;

    #[cfg(feature = "test-hooks")]
    let child_read_handle_for_test = handle_to_number(child_request_read.raw());
    #[cfg(feature = "test-hooks")]
    let child_write_handle_for_test = handle_to_number(child_response_write.raw());

    // The launcher handles stay owned here until JavaScript explicitly takes them. Converting
    // them earlier would create descriptors in this addon's module-local CRT table, which Node's
    // `fs` APIs cannot use.
    hooks.checkpoint(PostCreateStage::LauncherWriteFdCreated)?;
    hooks.checkpoint(PostCreateStage::LauncherReadFdCreated)?;

    let waiter_handle = duplicate_handle(suspended_child.process_handle(), false)?;
    let registered_wait = RegisteredProcessWait::new(waiter_handle.raw())?;
    hooks.checkpoint(PostCreateStage::WaitHandleCreated)?;
    let state = Arc::clone(&suspended_child.state);
    let waiter_state = Arc::clone(&suspended_child.state);
    let (decision_sender, decision_receiver) = mpsc::sync_channel::<bool>(1);
    let (ready_sender, ready_receiver) = mpsc::sync_channel::<()>(0);
    let waiter = thread::Builder::new()
        .name("goat-windows-process-wait".to_owned())
        .spawn(move || {
            if ready_sender.send(()).is_err() {
                return;
            }
            let exit_code = wait_for_exit(registered_wait, waiter_handle);
            let should_notify = decision_receiver.recv().unwrap_or(false);
            waiter_state.close();
            if should_notify {
                on_exit.notify(exit_code);
            }
        })
        .map_err(|_| FailureKind::Process)?;
    drop(waiter);
    ready_receiver.recv().map_err(|_| FailureKind::Process)?;
    hooks.checkpoint(PostCreateStage::WaiterReady)?;

    // No child-only handle is needed in the launcher after `CreateProcessW`. Close them before
    // resuming the child, after all later launcher handles have been allocated, so the test-only
    // canaries can discriminate closed handles without ordinary handle reuse.
    drop(child_request_read);
    drop(child_response_write);
    drop(standard_handles);
    drop(attribute_list);

    hooks.checkpoint(PostCreateStage::BeforeResume)?;
    // SAFETY: the primary thread handle remains alive and refers to the suspended child.
    if unsafe { ResumeThread(suspended_child.primary_thread.raw()) } == u32::MAX {
        let _ = decision_sender.send(false);
        return Err(FailureKind::Process);
    }
    hooks.checkpoint(PostCreateStage::AfterResume)?;
    if decision_sender.send(true).is_err() {
        return Err(FailureKind::Process);
    }
    suspended_child.disarm();

    Ok(SpawnedWindowsPrivacyProcess {
        pid,
        pipe_fds: Mutex::new(PipeFdState {
            launcher_write: Some(parent_request_write),
            launcher_read: Some(parent_response_read),
        }),
        state,
        #[cfg(feature = "test-hooks")]
        child_read_handle_for_test,
        #[cfg(feature = "test-hooks")]
        child_write_handle_for_test,
    })
}

fn create_anonymous_pipe(child_reads: bool) -> InternalResult<(OwnedHandle, OwnedHandle)> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut read_handle = INVALID_HANDLE_VALUE;
    let mut write_handle = INVALID_HANDLE_VALUE;
    // SAFETY: both output pointers and the security attributes are valid for this call.
    if unsafe { CreatePipe(&mut read_handle, &mut write_handle, &attributes, 0) } == 0 {
        return Err(FailureKind::PrivacyPipe);
    }
    let read_handle = OwnedHandle(Some(read_handle));
    let write_handle = OwnedHandle(Some(write_handle));
    let parent_handle = if child_reads {
        write_handle.raw()
    } else {
        read_handle.raw()
    };
    // SAFETY: the selected parent handle is valid and owned by this function.
    if unsafe { SetHandleInformation(parent_handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(FailureKind::PrivacyPipe);
    }

    Ok((read_handle, write_handle))
}

fn duplicate_standard_handle(fd: i32) -> InternalResult<Option<ChildStandardHandle>> {
    let functions = node_uv_functions().ok_or(FailureKind::Process)?;
    // SAFETY: this borrows the handle for a descriptor in Node's CRT table.
    let source = unsafe { (functions.get_osfhandle)(fd) };
    if source as isize == -1 || source as isize == -2 || source.is_null() {
        return Ok(None);
    }
    let mut flags = 0u32;
    // SAFETY: this only validates the borrowed source handle.
    if unsafe { GetHandleInformation(source, &mut flags) } == 0 {
        return Ok(None);
    }

    // SAFETY: `source` is borrowed, valid, and remains owned by the UCRT.
    let file_type = unsafe { GetFileType(source) };
    let handle = duplicate_handle(source, true)?;
    let crt_flags = crt_flags_for_file_type(file_type);
    Ok(Some(ChildStandardHandle { handle, crt_flags }))
}

fn crt_flags_for_file_type(file_type: u32) -> u8 {
    CRT_FOPEN
        | match file_type {
            FILE_TYPE_CHAR => CRT_FDEV,
            FILE_TYPE_PIPE => CRT_FPIPE,
            _ => 0,
        }
}

fn duplicate_handle(source: HANDLE, inheritable: bool) -> InternalResult<OwnedHandle> {
    let mut duplicate = INVALID_HANDLE_VALUE;
    // SAFETY: the source handle is valid; both process pseudo-handles are valid for the current
    // process, and the output pointer is writable.
    let duplicated = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            GetCurrentProcess(),
            &mut duplicate,
            0,
            i32::from(inheritable),
            DUPLICATE_SAME_ACCESS,
        )
    };
    if duplicated == 0 {
        return Err(FailureKind::Process);
    }
    OwnedHandle::new(duplicate)
}

fn build_crt_descriptor_table(
    handles: [HANDLE; PRIVACY_FD_COUNT],
    flags: [u8; PRIVACY_FD_COUNT],
) -> Vec<u8> {
    let mut table =
        vec![0u8; size_of::<i32>() + PRIVACY_FD_COUNT + size_of::<HANDLE>() * PRIVACY_FD_COUNT];
    table[..size_of::<i32>()].copy_from_slice(&(PRIVACY_FD_COUNT as i32).to_ne_bytes());
    table[size_of::<i32>()..size_of::<i32>() + PRIVACY_FD_COUNT].copy_from_slice(&flags);

    let handles_offset = size_of::<i32>() + PRIVACY_FD_COUNT;
    for (index, handle) in handles.into_iter().enumerate() {
        let raw = handle as usize;
        let offset = handles_offset + index * size_of::<HANDLE>();
        table[offset..offset + size_of::<HANDLE>()].copy_from_slice(&raw.to_ne_bytes());
    }
    table
}

fn collect_inherited_handles(handles: [HANDLE; PRIVACY_FD_COUNT]) -> Vec<HANDLE> {
    handles
        .into_iter()
        .filter(|handle| !is_invalid_handle(*handle))
        .collect()
}

fn build_optional_wide(value: Option<&[u16]>) -> InternalResult<Option<Vec<u16>>> {
    value
        .map(|value| {
            ensure_no_nul(value)?;
            let mut wide = value.to_vec();
            wide.push(0);
            Ok::<Vec<u16>, InputError>(wide)
        })
        .transpose()
        .map_err(Into::into)
}

fn build_environment_block(
    environment: Vec<SpawnWindowsPrivacyEnvironmentEntry>,
) -> InternalResult<Vec<u16>> {
    let mut entries = environment;
    for entry in &entries {
        validate_environment_entry(&entry.name, &entry.value)?;
    }

    // Node sorts object keys by their raw UTF-16 code units, then keeps the first spelling of
    // each case-insensitive Windows name. Do that before libuv's case-insensitive block sort so
    // environments such as `process.env` cannot fail merely because they contain both `PATH`
    // and `Path`.
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    let mut unique_entries: Vec<SpawnWindowsPrivacyEnvironmentEntry> =
        Vec::with_capacity(entries.len());
    for entry in entries {
        if unique_entries.iter().any(|existing| {
            compare_environment_names(&existing.name, &entry.name) == Ordering::Equal
        }) {
            continue;
        }
        unique_entries.push(entry);
    }
    let mut entries = unique_entries;
    entries.sort_by(|left, right| compare_environment_names(&left.name, &right.name));

    let block_length = entries.iter().try_fold(1usize, |length, entry| {
        length
            .checked_add(entry.name.len())
            .and_then(|length| length.checked_add(1))
            .and_then(|length| length.checked_add(entry.value.len()))
            .and_then(|length| length.checked_add(1))
    });
    let Some(block_length) = block_length else {
        return Err(InputError::EnvironmentTooLarge.into());
    };
    if block_length > 32_767 {
        return Err(InputError::EnvironmentTooLarge.into());
    }

    let mut block = Vec::with_capacity(block_length.max(2));
    for entry in entries {
        block.extend_from_slice(&entry.name);
        block.push(u16::from(b'='));
        block.extend_from_slice(&entry.value);
        block.push(0);
    }
    block.push(0);
    if block.len() == 1 {
        block.push(0);
    }
    Ok(block)
}

fn compare_environment_names(left: &[u16], right: &[u16]) -> Ordering {
    // SAFETY: both UTF-16 slices are valid for their explicit lengths.
    match unsafe {
        CompareStringOrdinal(
            left.as_ptr(),
            i32::try_from(left.len()).unwrap_or(i32::MAX),
            right.as_ptr(),
            i32::try_from(right.len()).unwrap_or(i32::MAX),
            1,
        )
    } {
        CSTR_LESS_THAN => Ordering::Less,
        CSTR_EQUAL => Ordering::Equal,
        CSTR_GREATER_THAN => Ordering::Greater,
        _ => left.cmp(right),
    }
}

fn wait_for_exit(mut registered_wait: RegisteredProcessWait, process: OwnedHandle) -> Option<u32> {
    if !registered_wait.wait_for_signal() {
        return None;
    }
    let mut exit_code = 0u32;
    // SAFETY: the process handle remains valid until this function returns.
    if unsafe { GetExitCodeProcess(process.raw(), &mut exit_code) } == 0 {
        return None;
    }
    Some(exit_code)
}

fn is_invalid_handle(handle: HANDLE) -> bool {
    handle.is_null() || handle == INVALID_HANDLE_VALUE
}

#[cfg(feature = "test-hooks")]
fn handle_to_number(handle: HANDLE) -> f64 {
    handle as usize as f64
}

#[cfg(feature = "test-hooks")]
#[allow(dead_code)]
fn number_to_handle(value: f64) -> Option<HANDLE> {
    if !value.is_finite() || value <= 0.0 || value.fract() != 0.0 || value > usize::MAX as f64 {
        return None;
    }
    let raw = value as usize;
    if raw as f64 != value {
        return None;
    }
    Some(raw as HANDLE)
}

#[cfg(feature = "test-hooks")]
#[allow(dead_code)]
#[napi(js_name = "createInheritableEventForTest")]
pub fn create_inheritable_event_for_test(env: Env) -> Result<f64> {
    use windows_sys::Win32::System::Threading::CreateEventW;

    const HANDLE_PADDING: usize = 4_096;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };

    // Put the retained canary well above the range a freshly started Bun process ordinarily
    // allocates. A numeric handle that was correctly excluded from inheritance could otherwise
    // collide with an unrelated child handle and make `GetHandleInformation` produce a false
    // positive. All padding events are closed before this function returns.
    let mut events = Vec::with_capacity(HANDLE_PADDING);
    for _ in 0..HANDLE_PADDING {
        // SAFETY: attributes are initialized and the unnamed event needs no external pointer.
        let handle = unsafe { CreateEventW(&attributes, 1, 0, null()) };
        let event = match OwnedHandle::new(handle) {
            Ok(event) => event,
            Err(failure) => return failure.throw(&env),
        };
        events.push(event);
    }
    let mut canary = events.pop().expect("positive padding count");
    drop(events);
    Ok(handle_to_number(canary.take()))
}

#[cfg(feature = "test-hooks")]
#[allow(dead_code)]
#[napi(js_name = "isHandleValidForTest")]
pub fn is_handle_valid_for_test(handle: f64) -> bool {
    let Some(handle) = number_to_handle(handle) else {
        return false;
    };
    let mut flags = 0u32;
    // SAFETY: `GetHandleInformation` validates the untrusted numeric handle without dereferencing
    // caller-controlled memory.
    unsafe { GetHandleInformation(handle, &mut flags) != 0 }
}

#[cfg(feature = "test-hooks")]
#[allow(dead_code)]
#[napi(js_name = "isHandleInheritableForTest")]
pub fn is_handle_inheritable_for_test(handle: f64) -> bool {
    let Some(handle) = number_to_handle(handle) else {
        return false;
    };
    let mut flags = 0u32;
    // SAFETY: `GetHandleInformation` validates the untrusted numeric handle without dereferencing
    // caller-controlled memory.
    unsafe { GetHandleInformation(handle, &mut flags) != 0 && flags & HANDLE_FLAG_INHERIT != 0 }
}

#[cfg(feature = "test-hooks")]
#[allow(dead_code)]
#[napi(js_name = "isFdInheritableForTest")]
pub fn is_fd_inheritable_for_test(fd: i32) -> bool {
    let Some(functions) = node_uv_functions() else {
        return false;
    };
    // SAFETY: querying Node's descriptor table does not transfer ownership.
    let raw = unsafe { (functions.get_osfhandle)(fd) };
    if raw as isize == -1 || raw as isize == -2 || raw.is_null() {
        return false;
    }
    is_handle_inheritable_for_test(handle_to_number(raw))
}

#[cfg(feature = "test-hooks")]
#[allow(dead_code)]
#[napi(js_name = "closeHandleForTest")]
pub fn close_handle_for_test(handle: f64) -> bool {
    let Some(handle) = number_to_handle(handle) else {
        return false;
    };
    // SAFETY: this test-only hook takes ownership of the supplied test handle.
    unsafe { CloseHandle(handle) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use napi::bindgen_prelude::Utf16String;
    use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
    use windows_sys::Win32::{Foundation::WAIT_OBJECT_0, System::Threading::WaitForSingleObject};

    fn environment_entry(name: &str, value: &str) -> SpawnWindowsPrivacyEnvironmentEntry {
        SpawnWindowsPrivacyEnvironmentEntry {
            name: Utf16String::from(name.to_owned()),
            value: Utf16String::from(value.to_owned()),
        }
    }

    #[test]
    fn crt_descriptor_table_matches_the_libuv_layout() {
        let handles = [
            0x10usize as HANDLE,
            0x20usize as HANDLE,
            0x30usize as HANDLE,
            0x40usize as HANDLE,
            0x50usize as HANDLE,
        ];
        let flags = [
            CRT_FOPEN,
            CRT_FOPEN,
            CRT_FOPEN | CRT_FDEV,
            CRT_FOPEN | CRT_FPIPE,
            CRT_FOPEN | CRT_FPIPE,
        ];
        let table = build_crt_descriptor_table(handles, flags);

        assert_eq!(
            i32::from_ne_bytes(table[..size_of::<i32>()].try_into().unwrap()),
            PRIVACY_FD_COUNT as i32
        );
        assert_eq!(&table[size_of::<i32>()..size_of::<i32>() + 5], &flags);
        let handles_offset = size_of::<i32>() + PRIVACY_FD_COUNT;
        for (index, expected) in [0x10usize, 0x20, 0x30, 0x40, 0x50].into_iter().enumerate() {
            let offset = handles_offset + index * size_of::<HANDLE>();
            assert_eq!(
                usize::from_ne_bytes(
                    table[offset..offset + size_of::<HANDLE>()]
                        .try_into()
                        .unwrap()
                ),
                expected
            );
        }
    }

    #[test]
    fn environment_block_sorts_ordinally_and_keeps_first_lexical_case_alias() {
        let block = build_environment_block(vec![
            environment_entry("zebra", "3"),
            environment_entry("Alpha", "1"),
            environment_entry("middle", "2"),
        ])
        .unwrap();
        assert_eq!(
            String::from_utf16(&block[..block.len() - 2]).unwrap(),
            "Alpha=1\0middle=2\0zebra=3"
        );

        let block = build_environment_block(vec![
            environment_entry("Path", "one"),
            environment_entry("PATH", "two"),
        ])
        .unwrap();
        assert_eq!(
            String::from_utf16(&block[..block.len() - 2]).unwrap(),
            "PATH=two"
        );
    }

    #[test]
    fn environment_block_preserves_unpaired_utf16_units() {
        let block = build_environment_block(vec![SpawnWindowsPrivacyEnvironmentEntry {
            name: Utf16String::from("GOAT_TEST".to_owned()),
            value: Utf16String::from(vec![u16::from(b'a'), 0xD800, u16::from(b'b')]),
        }])
        .unwrap();
        assert!(block
            .windows(3)
            .any(|window| window == [u16::from(b'a'), 0xD800, u16::from(b'b')]));
    }

    #[test]
    fn handle_list_contains_only_valid_stdio_and_privacy_handles() {
        let handles = [
            0x10usize as HANDLE,
            null_mut(),
            INVALID_HANDLE_VALUE,
            0x40usize as HANDLE,
            0x50usize as HANDLE,
        ];
        assert_eq!(
            collect_inherited_handles(handles),
            vec![
                0x10usize as HANDLE,
                0x40usize as HANDLE,
                0x50usize as HANDLE
            ]
        );
    }

    #[test]
    fn crt_flags_distinguish_console_pipe_and_file_stdio() {
        assert_eq!(
            crt_flags_for_file_type(FILE_TYPE_CHAR),
            CRT_FOPEN | CRT_FDEV
        );
        assert_eq!(
            crt_flags_for_file_type(FILE_TYPE_PIPE),
            CRT_FOPEN | CRT_FPIPE
        );
        assert_eq!(crt_flags_for_file_type(1), CRT_FOPEN);
    }

    #[test]
    fn owned_handle_closes_exactly_once_and_transfer_prevents_early_close() {
        use windows_sys::Win32::System::Threading::CreateEventW;

        // SAFETY: creating an unnamed manual-reset event requires no external pointer lifetime.
        let raw = unsafe { CreateEventW(null(), 1, 0, null()) };
        let mut handle = OwnedHandle::new(raw).unwrap();
        assert!(handle_is_valid(raw));
        let transferred = handle.take();
        drop(handle);
        assert!(handle_is_valid(transferred));
        // SAFETY: the test now owns the transferred handle exactly once.
        unsafe {
            CloseHandle(transferred);
        }
        assert!(!handle_is_valid(transferred));

        // SAFETY: creating an unnamed manual-reset event requires no external pointer lifetime.
        let raw = unsafe { CreateEventW(null(), 1, 0, null()) };
        drop(OwnedHandle::new(raw).unwrap());
        assert!(!handle_is_valid(raw));
    }

    #[test]
    fn registered_wait_buffers_a_signal_before_the_receiver_runs() {
        use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent};

        // SAFETY: creating an unnamed manual-reset event requires no external pointer lifetime.
        let event = OwnedHandle::new(unsafe { CreateEventW(null(), 1, 0, null()) }).unwrap();
        let mut registered_wait = RegisteredProcessWait::new(event.raw()).unwrap();
        // SAFETY: `event` remains valid and uniquely owned for the duration of this call.
        assert_ne!(unsafe { SetEvent(event.raw()) }, 0);
        assert!(registered_wait.wait_for_signal());
    }

    #[test]
    fn pipe_descriptor_transfer_is_one_shot_and_close_reclaims_untransferred_fds() {
        let (child_read, parent_write) = create_anonymous_pipe(true).unwrap();
        drop(child_read);
        let mut state = PipeFdState {
            launcher_write: Some(parent_write),
            launcher_read: None,
        };
        let transferred = state.take_write().unwrap();
        assert!(state.take_write().is_err());
        state.close();
        // SAFETY: querying and closing the transferred descriptor is owned by this test.
        unsafe {
            assert_ne!(_get_osfhandle(transferred), -1);
            assert_eq!(_close(transferred), 0);
        }

        let (child_read, parent_write) = create_anonymous_pipe(true).unwrap();
        drop(child_read);
        let raw_handle = parent_write.raw();
        assert!(handle_is_valid(raw_handle));
        let mut state = PipeFdState {
            launcher_write: Some(parent_write),
            launcher_read: None,
        };
        state.close();
        assert!(!handle_is_valid(raw_handle));
    }

    struct IgnoreExit;

    impl ExitNotifier for IgnoreExit {
        fn notify(self: Box<Self>, _exit_code: Option<u32>) {}
    }

    struct FailingHooks {
        fail_at: PostCreateStage,
        pid: AtomicU32,
        observer: Mutex<Option<OwnedHandle>>,
    }

    impl FailingHooks {
        fn new(fail_at: PostCreateStage) -> Self {
            Self {
                fail_at,
                pid: AtomicU32::new(0),
                observer: Mutex::new(None),
            }
        }

        fn take_observer(&self) -> OwnedHandle {
            self.observer.lock().unwrap().take().unwrap()
        }
    }

    impl SpawnHooks for FailingHooks {
        fn process_created(&self, pid: u32, process: HANDLE) -> InternalResult<()> {
            self.pid.store(pid, AtomicOrdering::SeqCst);
            self.observer
                .lock()
                .unwrap()
                .replace(duplicate_handle(process, false)?);
            Ok(())
        }

        fn checkpoint(&self, stage: PostCreateStage) -> InternalResult<()> {
            if stage == self.fail_at {
                Err(FailureKind::Process)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn every_post_create_failure_terminates_the_suspended_or_resumed_child() {
        let stages = [
            PostCreateStage::Created,
            PostCreateStage::LauncherWriteFdCreated,
            PostCreateStage::LauncherReadFdCreated,
            PostCreateStage::WaitHandleCreated,
            PostCreateStage::WaiterReady,
            PostCreateStage::BeforeResume,
            PostCreateStage::AfterResume,
        ];

        for stage in stages {
            let hooks = FailingHooks::new(stage);
            let request = test_spawn_request();
            let result = spawn_inner(request, Box::new(IgnoreExit), &hooks);
            assert!(
                matches!(result, Err(FailureKind::Process)),
                "stage {stage:?}"
            );
            assert_ne!(hooks.pid.load(AtomicOrdering::SeqCst), 0);
            let observer = hooks.take_observer();
            // SAFETY: the observer is a valid process handle retained only for this assertion.
            assert_eq!(
                unsafe { WaitForSingleObject(observer.raw(), 5_000) },
                WAIT_OBJECT_0
            );
            let mut exit_code = 259u32;
            // SAFETY: the observer handle remains valid through this call.
            assert_ne!(
                unsafe { GetExitCodeProcess(observer.raw(), &mut exit_code) },
                0
            );
            assert_ne!(exit_code, 259, "stage {stage:?} left a live child");
        }
    }

    fn test_spawn_request() -> SpawnWindowsPrivacyRequest {
        let command = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let env = ["SystemRoot", "SystemDrive", "TEMP", "PATH"]
            .into_iter()
            .filter_map(|name| {
                std::env::var(name)
                    .ok()
                    .map(|value| environment_entry(name, &value))
            })
            .collect();
        SpawnWindowsPrivacyRequest {
            command: Utf16String::from(command),
            args: Vec::new(),
            cwd: None,
            env,
            windows_hide: true,
            detached: true,
        }
    }

    fn handle_is_valid(handle: HANDLE) -> bool {
        let mut flags = 0u32;
        // SAFETY: this API validates the numeric handle without dereferencing test memory.
        unsafe { GetHandleInformation(handle, &mut flags) != 0 }
    }
}
