#![deny(unsafe_code)]

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

const DEFAULT_LAUNCHER_VERSION: &str = "0.4.0";
const LAUNCHER_VERSION: &str = match option_env!("GOAT_LAUNCHER_VERSION") {
    Some(version) => version,
    None => DEFAULT_LAUNCHER_VERSION,
};
const DEFAULT_ENGINE_VERSION: &str = "1.17.11";
const ENGINE_VERSION: &str = match option_env!("GOAT_ENGINE_VERSION") {
    Some(version) => version,
    None => DEFAULT_ENGINE_VERSION,
};
const REGISTRY_ORIGIN: &str = "https://registry.npmjs.org";
const MAX_TOOL_OUTPUT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ENGINE_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const ENGINE_MANIFEST_PUBLIC_KEY_BASE64: Option<&str> =
    option_env!("GOAT_ENGINE_SIGNING_PUBLIC_KEY_BASE64");
const RELEASE_POLICY_DIGEST: Option<&str> = option_env!("GOAT_RELEASE_POLICY_SOURCE_SHA256");

#[cfg(target_os = "windows")]
const PLATFORM: &str = "win32";
#[cfg(target_os = "macos")]
const PLATFORM: &str = "darwin";
#[cfg(target_arch = "x86_64")]
const ARCHITECTURE: &str = "x64";
#[cfg(target_arch = "aarch64")]
const ARCHITECTURE: &str = "arm64";

#[cfg(target_os = "windows")]
const POWERSHELL_PATH: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
#[cfg(target_os = "windows")]
const TAR_PATH: &str = r"C:\Windows\System32\tar.exe";
#[cfg(target_os = "macos")]
const CURL_PATH: &str = "/usr/bin/curl";
#[cfg(target_os = "macos")]
const TAR_PATH: &str = "/usr/bin/tar";

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
compile_error!("GOAT native installer supports Windows and macOS only");
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("GOAT native installer supports x64 and arm64 only");

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("GOAT native installer error: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<u8, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_usage();
        return Ok(0);
    }
    if args.iter().any(|arg| arg == "--version" || arg == "-v") {
        println!("{LAUNCHER_VERSION}");
        return Ok(0);
    }

    let paths = InstallPaths::resolve()?;
    let installed_launcher = is_installed_launcher(&paths.launcher)?;
    let command = args.first().map(String::as_str);

    if !installed_launcher || command == Some("install") {
        install_launcher(&paths)?;
        ensure_engine(&paths, false)?;
        if let Err(error) =
            add_to_user_path(paths.launcher.parent().expect("launcher has a parent"))
        {
            eprintln!("GOAT installed, but PATH was not updated: {error}");
        }
        print_installed(&paths);
        return Ok(0);
    }

    if command == Some("update") {
        if args.len() != 1 {
            return Err("`goat update` does not accept arguments".to_owned());
        }
        ensure_engine(&paths, true)?;
        println!("GOAT engine {ENGINE_VERSION} is installed.");
        return Ok(0);
    }

    ensure_engine(&paths, false)?;
    launch_engine(&paths, &args)
}

fn print_usage() {
    println!(
        "GOAT native installer {LAUNCHER_VERSION}\n\n\
         One-download installer and standalone launcher; Node.js and npm are not required.\n\n\
         Usage:\n  goat-installer       Install GOAT\n  goat                 Launch GOAT\n  goat update          Install the current engine release\n  goat --version       Print the native launcher version"
    );
}

struct InstallPaths {
    app_data: PathBuf,
    launcher: PathBuf,
    engine_root: PathBuf,
}

impl InstallPaths {
    fn resolve() -> Result<Self, String> {
        let app_data = app_data_dir()?;
        let launcher_dir = app_data.join("bin");
        let launcher = launcher_dir.join(executable_name());
        let engine_root = app_data
            .join("engines")
            .join("stable")
            .join(format!("{PLATFORM}-{ARCHITECTURE}"));
        Ok(Self {
            app_data,
            launcher,
            engine_root,
        })
    }
}

fn app_data_dir() -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    {
        let path = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| "LOCALAPPDATA is not set".to_owned())?;
        validate_user_path(&path, "LOCALAPPDATA")?;
        Ok(path.join("goat"))
    }

    #[cfg(target_os = "macos")]
    {
        let path = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| "HOME is not set".to_owned())?;
        validate_user_path(&path, "HOME")?;
        Ok(path
            .join("Library")
            .join("Application Support")
            .join("goat"))
    }
}

fn validate_user_path(path: &Path, name: &str) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .to_string_lossy()
            .chars()
            .any(|character| character.is_control())
        || (cfg!(target_os = "windows")
            && (path.to_string_lossy().starts_with("\\\\") || path.to_string_lossy().contains(';')))
    {
        return Err(format!("{name} is not a safe absolute directory"));
    }
    Ok(())
}

fn executable_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "goat.exe"
    }
    #[cfg(target_os = "macos")]
    {
        "goat"
    }
}

fn is_installed_launcher(path: &Path) -> Result<bool, String> {
    let current =
        env::current_exe().map_err(|error| format!("cannot locate installer: {error}"))?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("cannot inspect launcher: {error}")),
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Ok(false);
    }
    let current =
        fs::canonicalize(current).map_err(|error| format!("cannot resolve installer: {error}"))?;
    let installed =
        fs::canonicalize(path).map_err(|error| format!("cannot resolve launcher: {error}"))?;
    Ok(current == installed)
}

fn install_launcher(paths: &InstallPaths) -> Result<(), String> {
    let current =
        env::current_exe().map_err(|error| format!("cannot locate installer: {error}"))?;
    fs::create_dir_all(&paths.app_data)
        .map_err(|error| format!("cannot create GOAT application directory: {error}"))?;
    validate_regular_directory(&paths.app_data)?;
    let launcher_directory = paths.launcher.parent().expect("launcher has a parent");
    fs::create_dir_all(launcher_directory)
        .map_err(|error| format!("cannot create the GOAT launcher directory: {error}"))?;
    validate_regular_directory(launcher_directory)?;
    if is_installed_launcher(&paths.launcher)? {
        return Ok(());
    }

    let temporary = launcher_temporary_path(launcher_directory)?;
    copy_to_new_file(&current, &temporary)?;
    #[cfg(target_os = "macos")]
    set_executable(&temporary)?;
    if fs::symlink_metadata(&paths.launcher).is_ok() {
        fs::remove_file(&paths.launcher)
            .map_err(|error| format!("cannot replace existing native launcher: {error}"))?;
    }
    if let Err(error) = fs::rename(&temporary, &paths.launcher) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("cannot activate native launcher: {error}"));
    }
    Ok(())
}

fn launcher_temporary_path(directory: &Path) -> Result<PathBuf, String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is invalid: {error}"))?
        .as_nanos();
    Ok(directory.join(format!("goat-{}-{timestamp}.tmp", process_id())))
}

fn copy_to_new_file(source: &Path, target: &Path) -> Result<(), String> {
    let bytes =
        fs::read(source).map_err(|error| format!("cannot read native launcher: {error}"))?;
    write_new_file(target, &bytes).map_err(|error| format!("cannot copy native launcher: {error}"))
}

fn write_new_file(target: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    file.write_all(bytes)
}

fn add_to_user_path(directory: &Path) -> Result<(), String> {
    let directory = directory.to_string_lossy();
    #[cfg(target_os = "windows")]
    {
        let escaped = directory.replace('\'', "''");
        let script = format!(
            "$ErrorActionPreference='Stop'; $name='Path'; $dir='{escaped}'; $path=[Environment]::GetEnvironmentVariable($name,'User'); $parts=@(); if ($path) {{ $parts=$path -split ';' }}; if ($parts -notcontains $dir) {{ [Environment]::SetEnvironmentVariable($name, (($parts + $dir) -join ';'), 'User') }}"
        );
        run_command(
            POWERSHELL_PATH,
            &["-NoProfile", "-NonInteractive", "-Command", &script],
        )?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let home = env::var_os("HOME").ok_or_else(|| "HOME is not set".to_owned())?;
        let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_owned());
        let home = PathBuf::from(home);
        let config = if shell.ends_with("/bash") {
            let profile = home.join(".bash_profile");
            if profile.exists() {
                profile
            } else {
                home.join(".bashrc")
            }
        } else {
            home.join(".zshrc")
        };
        let existing_permissions = match fs::symlink_metadata(&config) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                    return Err(format!("cannot update {} safely", config.display()));
                }
                Some(metadata.permissions())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("cannot inspect {}: {error}", config.display())),
        };
        let existing = match fs::read_to_string(&config) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(format!("cannot read {}: {error}", config.display())),
        };
        let marker = "# GOAT native installer";
        let escaped = directory.replace('\'', "'\\''");
        let line = format!("export PATH='{escaped}':$PATH");
        if existing.lines().any(|value| value == line) {
            return Ok(());
        }
        let suffix = if existing.is_empty() || existing.ends_with('\n') {
            ""
        } else {
            "\n"
        };
        let addition = format!("{suffix}{marker}\n{line}\n");
        let contents = format!("{existing}{addition}");
        let temporary = config.with_extension(format!("goat-{}.tmp", process_id()));
        write_new_file(&temporary, contents.as_bytes())
            .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
        if let Some(permissions) = existing_permissions {
            if let Err(error) = fs::set_permissions(&temporary, permissions) {
                let _ = fs::remove_file(&temporary);
                return Err(format!(
                    "cannot preserve {} permissions: {error}",
                    config.display()
                ));
            }
        }
        if let Err(error) = fs::rename(&temporary, &config) {
            let _ = fs::remove_file(&temporary);
            return Err(format!("cannot activate {}: {error}", config.display()));
        }
        return Ok(());
    }
}

fn create_temporary_root(app_data: &Path) -> Result<PathBuf, String> {
    validate_regular_directory(app_data)?;
    let cache = app_data.join("cache");
    fs::create_dir_all(&cache)
        .map_err(|error| format!("cannot create installer cache: {error}"))?;
    validate_regular_directory(&cache)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is invalid: {error}"))?
        .as_nanos();
    for attempt in 0..8u32 {
        let candidate = cache.join(format!(
            "native-install-{}-{timestamp}-{attempt}",
            process_id()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "cannot create installer staging directory: {error}"
                ))
            }
        }
    }
    Err("cannot allocate a unique installer staging directory".to_owned())
}

fn print_installed(paths: &InstallPaths) {
    println!("GOAT installed without Node.js or npm.");
    println!("Launcher: {}", paths.launcher.display());
    println!("Open a new terminal, then run `goat`.");
}

fn ensure_engine(paths: &InstallPaths, force: bool) -> Result<(), String> {
    validate_regular_directory(&paths.app_data)?;
    let executable = paths.engine_root.join("bin").join(engine_executable());
    let manifest = paths.engine_root.join("goat-engine.json");
    match fs::symlink_metadata(&paths.engine_root) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err("installed GOAT engine root is not a regular directory".to_owned());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect installed GOAT engine: {error}")),
    }
    if !force && executable.is_file() && manifest.is_file() {
        verify_engine(&executable, &manifest)?;
        return Ok(());
    }

    let temporary_root = create_temporary_root(&paths.app_data)?;
    let archive = temporary_root.join(engine_archive_name());
    let extracted = temporary_root.join("extracted");
    let staged = temporary_root.join("engine");
    let result = (|| {
        download_engine(&archive)?;
        let archive_size = fs::metadata(&archive)
            .map_err(|error| format!("cannot inspect downloaded engine archive: {error}"))?
            .len();
        if archive_size > MAX_ENGINE_ARCHIVE_BYTES {
            return Err("downloaded GOAT engine archive is too large".to_owned());
        }
        validate_archive_listing(&archive)?;
        fs::create_dir_all(&extracted)
            .map_err(|error| format!("cannot create extraction directory: {error}"))?;
        let executable_entry = format!("package/bin/{}", engine_executable());
        run_command(
            TAR_PATH,
            &[
                "-xzf",
                &path_string(&archive),
                "-C",
                &path_string(&extracted),
                &executable_entry,
                "package/goat-engine.json",
                "package/package.json",
            ],
        )?;

        let package_root = extracted.join("package");
        validate_regular_directory(&package_root)?;
        validate_regular_directory(&package_root.join("bin"))?;
        let source_executable = package_root.join("bin").join(engine_executable());
        let source_manifest = package_root.join("goat-engine.json");
        let source_package = package_root.join("package.json");
        validate_downloaded_package(&source_executable, &source_manifest, &source_package)?;

        fs::create_dir_all(staged.join("bin"))
            .map_err(|error| format!("cannot create engine staging directory: {error}"))?;
        fs::copy(
            &source_executable,
            staged.join("bin").join(engine_executable()),
        )
        .map_err(|error| format!("cannot stage GOAT engine: {error}"))?;
        fs::copy(&source_manifest, staged.join("goat-engine.json"))
            .map_err(|error| format!("cannot stage GOAT manifest: {error}"))?;
        #[cfg(target_os = "macos")]
        set_executable(&staged.join("bin").join(engine_executable()))?;

        verify_engine(
            &staged.join("bin").join(engine_executable()),
            &staged.join("goat-engine.json"),
        )?;
        let backup = activate_engine(&staged, &paths.engine_root)?;
        if let Err(error) = verify_engine(&executable, &manifest) {
            restore_engine(&paths.engine_root, backup.as_deref());
            return Err(error);
        }
        if let Some(backup) = backup {
            let _ = fs::remove_dir_all(backup);
        }
        Ok(())
    })();

    let _ = fs::remove_dir_all(&temporary_root);
    result
}

fn activate_engine(staged: &Path, target: &Path) -> Result<Option<PathBuf>, String> {
    let parent = target.parent().expect("engine root has a parent");
    let engines = parent.parent().expect("engine channel has a parent");
    let app_data = engines.parent().expect("engine directory has a parent");
    validate_regular_directory(app_data)?;
    create_and_validate_directory(engines)?;
    create_and_validate_directory(parent)?;
    let backup = target.with_extension(format!("backup-{}", process_id()));
    if fs::symlink_metadata(&backup).is_ok() {
        return Err("cannot allocate a clean engine backup path".to_owned());
    }
    let had_target = match fs::symlink_metadata(target) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err("existing GOAT engine path is not a regular directory".to_owned());
            }
            fs::rename(target, &backup)
                .map_err(|error| format!("cannot preserve existing GOAT engine: {error}"))?;
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(format!("cannot inspect existing GOAT engine: {error}")),
    };
    if let Err(error) = fs::rename(staged, target) {
        if had_target {
            let _ = fs::rename(&backup, target);
        }
        return Err(format!("cannot activate GOAT engine: {error}"));
    }
    Ok(had_target.then_some(backup))
}

fn create_and_validate_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_regular_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|error| {
                format!(
                    "cannot create GOAT engine directory {}: {error}",
                    path.display()
                )
            })?;
            validate_regular_directory(path)
        }
        Err(error) => Err(format!("cannot inspect GOAT engine directory: {error}")),
    }
}

fn restore_engine(target: &Path, backup: Option<&Path>) {
    let Some(backup) = backup else {
        let _ = fs::remove_dir_all(target);
        return;
    };
    let _ = fs::remove_dir_all(target);
    let _ = fs::rename(backup, target);
}

fn download_engine(archive: &Path) -> Result<(), String> {
    let package = engine_package_name();
    let url = format!("{REGISTRY_ORIGIN}/{package}/-/{package}-{ENGINE_VERSION}.tgz");
    let user_agent = format!("GOAT-native-installer/{LAUNCHER_VERSION}");
    #[cfg(target_os = "windows")]
    {
        let output = path_string(archive);
        let script = format!(
            "$ErrorActionPreference='Stop'; $limit=[int64]{limit}; $handler=New-Object System.Net.Http.HttpClientHandler; $handler.AllowAutoRedirect=$false; $handler.UseProxy=$false; $client=New-Object System.Net.Http.HttpClient($handler); $client.Timeout=[TimeSpan]::FromSeconds(300); $request=New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get,'{url}'); $request.Headers.UserAgent.ParseAdd('{user_agent}'); $response=$client.SendAsync($request,[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult(); if (-not $response.IsSuccessStatusCode) {{ throw \"download returned HTTP $([int]$response.StatusCode)\" }}; if ($response.Content.Headers.ContentLength.HasValue -and $response.Content.Headers.ContentLength.Value -gt $limit) {{ throw 'downloaded GOAT engine archive is too large' }}; $stream=$response.Content.ReadAsStreamAsync().GetAwaiter().GetResult(); $file=[System.IO.File]::Open('{escaped}',[System.IO.FileMode]::CreateNew,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None); try {{ $buffer=New-Object byte[] 65536; [int64]$total=0; while (($read=$stream.Read($buffer,0,$buffer.Length)) -gt 0) {{ $total += $read; if ($total -gt $limit) {{ throw 'downloaded GOAT engine archive is too large' }}; $file.Write($buffer,0,$read) }} }} finally {{ $file.Dispose(); $stream.Dispose(); $response.Dispose(); $client.Dispose() }}",
            escaped = output.replace('\'', "''"),
            limit = MAX_ENGINE_ARCHIVE_BYTES,
            url = url.replace('\'', "''"),
            user_agent = user_agent.replace('\'', "''"),
        );
        run_command(
            POWERSHELL_PATH,
            &["-NoProfile", "-NonInteractive", "-Command", &script],
        )?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let max_archive_size = MAX_ENGINE_ARCHIVE_BYTES.to_string();
        run_command(
            CURL_PATH,
            &[
                "--fail",
                "--location",
                "--retry",
                "3",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--max-redirs",
                "0",
                "--noproxy",
                "*",
                "--connect-timeout",
                "10",
                "--max-time",
                "300",
                "--user-agent",
                &user_agent,
                "--max-filesize",
                &max_archive_size,
                "--output",
                &path_string(archive),
                &url,
            ],
        )?;
        Ok(())
    }
}

fn validate_regular_file(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("GOAT engine file is unavailable: {error}"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("GOAT engine contains a non-regular file".to_owned());
    }
    Ok(())
}

fn validate_regular_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("downloaded GOAT package is missing a directory: {error}"))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err("downloaded GOAT package contains a non-regular directory".to_owned());
    }
    Ok(())
}

fn validate_downloaded_package(
    executable: &Path,
    manifest: &Path,
    package: &Path,
) -> Result<(), String> {
    for required in [executable, manifest, package] {
        let metadata = fs::symlink_metadata(required).map_err(|error| {
            format!("downloaded GOAT package is missing required files: {error}")
        })?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err("downloaded GOAT package contains a non-regular required file".to_owned());
        }
    }
    let package_text = read_bounded_text(package, 64 * 1024, "engine package metadata")?;
    if json_string_field(&package_text, "name").as_deref() != Some(engine_package_name())
        || json_string_field(&package_text, "version").as_deref() != Some(ENGINE_VERSION)
    {
        return Err("downloaded GOAT package metadata is not the expected release".to_owned());
    }
    let manifest_text = read_bounded_text(manifest, 128 * 1024, "engine manifest")?;
    validate_manifest_identity(&manifest_text)?;
    let expected = manifest_field(&manifest_text, "value")
        .ok_or_else(|| "downloaded GOAT engine manifest has no checksum".to_owned())?;
    let actual = sha256_file(executable)?;
    if expected != actual {
        return Err("downloaded GOAT engine checksum does not match its manifest".to_owned());
    }
    Ok(())
}

fn validate_manifest_identity(text: &str) -> Result<(), String> {
    let trusted_key = decode_base64(
        ENGINE_MANIFEST_PUBLIC_KEY_BASE64
            .ok_or_else(|| "native installer trust material is not configured".to_owned())?,
    )?;
    let release_policy_digest = RELEASE_POLICY_DIGEST
        .ok_or_else(|| "native installer release policy is not configured".to_owned())?;
    validate_manifest_identity_with_trust(text, &trusted_key, release_policy_digest)
}

fn validate_manifest_identity_with_trust(
    text: &str,
    trusted_key: &[u8],
    release_policy_digest: &str,
) -> Result<(), String> {
    let manifest: Value = serde_json::from_str(text)
        .map_err(|error| format!("GOAT engine manifest is invalid JSON: {error}"))?;
    let object = manifest
        .as_object()
        .ok_or_else(|| "GOAT engine manifest must be a JSON object".to_owned())?;
    require_exact_keys(
        object,
        &[
            "manifestVersion",
            "releasePolicyDigest",
            "engineVersion",
            "platform",
            "architecture",
            "executablePath",
            "releaseChannel",
            "checksum",
            "compatibility",
            "signature",
        ],
    )?;
    let manifest_release_policy_digest = json_object_string(object, "releasePolicyDigest")
        .filter(|value| is_lowercase_sha256(value))
        .ok_or_else(|| "GOAT engine manifest release policy digest is invalid".to_owned())?;
    if object.get("manifestVersion").and_then(Value::as_u64) != Some(1)
        || release_policy_digest != manifest_release_policy_digest.as_str()
        || json_object_string(object, "engineVersion").as_deref() != Some(ENGINE_VERSION)
        || json_object_string(object, "platform").as_deref() != Some(PLATFORM)
        || json_object_string(object, "architecture").as_deref() != Some(ARCHITECTURE)
        || json_object_string(object, "executablePath").as_deref()
            != Some(if PLATFORM == "win32" {
                "bin/goat-engine.exe"
            } else {
                "bin/goat-engine"
            })
        || json_object_string(object, "releaseChannel").as_deref() != Some("stable")
    {
        return Err("GOAT engine manifest identity is not the expected stable release".to_owned());
    }

    let checksum = object
        .get("checksum")
        .and_then(Value::as_object)
        .ok_or_else(|| "GOAT engine manifest checksum is invalid".to_owned())?;
    require_exact_keys(checksum, &["algorithm", "value"])?;
    if json_object_string(checksum, "algorithm").as_deref() != Some("sha256")
        || json_object_string(checksum, "value")
            .map(|value| !is_lowercase_sha256(&value))
            .unwrap_or(true)
    {
        return Err("GOAT engine manifest checksum is invalid".to_owned());
    }

    let compatibility = object
        .get("compatibility")
        .and_then(Value::as_object)
        .ok_or_else(|| "GOAT engine manifest compatibility is invalid".to_owned())?;
    require_exact_keys_optional(
        compatibility,
        &["minimumLauncherVersion"],
        &["maximumLauncherVersion"],
    )?;
    let minimum_launcher_version = json_object_string(compatibility, "minimumLauncherVersion")
        .ok_or_else(|| "GOAT engine manifest compatibility is invalid".to_owned())?;
    let maximum_launcher_version = compatibility
        .get("maximumLauncherVersion")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| "GOAT engine manifest compatibility is invalid".to_owned())
        })
        .transpose()?;
    if !is_version_string(&minimum_launcher_version)
        || maximum_launcher_version.is_some_and(|value| !is_version_string(value))
        || compare_versions(LAUNCHER_VERSION, &minimum_launcher_version) < 0
        || maximum_launcher_version
            .is_some_and(|value| compare_versions(LAUNCHER_VERSION, value) > 0)
    {
        return Err("GOAT engine is incompatible with the native launcher".to_owned());
    }

    let signature = object
        .get("signature")
        .and_then(Value::as_object)
        .ok_or_else(|| "GOAT engine manifest signature is invalid".to_owned())?;
    require_exact_keys(
        signature,
        &["status", "algorithm", "keyId", "publicKey", "value"],
    )?;
    if json_object_string(signature, "status").as_deref() != Some("signed")
        || json_object_string(signature, "algorithm").as_deref() != Some("ed25519")
    {
        return Err("GOAT engine manifest is not a signed stable release".to_owned());
    }
    let key_id = json_object_string(signature, "keyId")
        .filter(|value| is_lowercase_sha256(value))
        .ok_or_else(|| "GOAT engine manifest signing key id is invalid".to_owned())?;
    let public_key_der = decode_base64url(
        json_object_string(signature, "publicKey")
            .ok_or_else(|| "GOAT engine manifest public key is missing".to_owned())?
            .as_str(),
    )?;
    if public_key_der.len() != 44
        || public_key_der[..12]
            != [
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
            ]
        || sha256_bytes(&public_key_der) != key_id
    {
        return Err("GOAT engine manifest public key is invalid".to_owned());
    }
    if trusted_key != public_key_der.as_slice() {
        return Err("GOAT engine manifest signing key is not trusted".to_owned());
    }
    let signature_bytes = decode_base64url(
        json_object_string(signature, "value")
            .ok_or_else(|| "GOAT engine manifest signature is missing".to_owned())?
            .as_str(),
    )?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "GOAT engine manifest signature has an invalid length".to_owned())?;
    let verifying_key = VerifyingKey::from_bytes(
        public_key_der[12..]
            .try_into()
            .expect("validated Ed25519 key length"),
    )
    .map_err(|_| "GOAT engine manifest public key is invalid".to_owned())?;
    let signature = Signature::from_bytes(&signature_array);
    let canonical = canonical_manifest_payload(object, checksum, compatibility)?;
    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|_| "GOAT engine manifest signature verification failed".to_owned())
}

fn canonical_manifest_payload(
    manifest: &serde_json::Map<String, Value>,
    checksum: &serde_json::Map<String, Value>,
    compatibility: &serde_json::Map<String, Value>,
) -> Result<String, String> {
    let string = |object: &serde_json::Map<String, Value>, field: &str| {
        json_object_string(object, field)
            .ok_or_else(|| format!("manifest field {field} is invalid"))
    };
    let encoded = |value: &str| serde_json::to_string(value).map_err(|error| error.to_string());
    let compatibility_json = if let Some(maximum) = compatibility.get("maximumLauncherVersion") {
        format!(
            "{{\"minimumLauncherVersion\":{},\"maximumLauncherVersion\":{}}}",
            encoded(&string(compatibility, "minimumLauncherVersion")?)?,
            encoded(
                maximum
                    .as_str()
                    .ok_or("manifest maximum launcher version is invalid")?
            )?
        )
    } else {
        format!(
            "{{\"minimumLauncherVersion\":{}}}",
            encoded(&string(compatibility, "minimumLauncherVersion")?)?
        )
    };
    Ok(format!(
        "{{\"manifestVersion\":1,\"releasePolicyDigest\":{},\"engineVersion\":{},\"platform\":{},\"architecture\":{},\"executablePath\":{},\"releaseChannel\":{},\"checksum\":{{\"algorithm\":{},\"value\":{}}},\"compatibility\":{}}}",
        encoded(&string(manifest, "releasePolicyDigest")?)?,
        encoded(&string(manifest, "engineVersion")?)?,
        encoded(&string(manifest, "platform")?)?,
        encoded(&string(manifest, "architecture")?)?,
        encoded(&string(manifest, "executablePath")?)?,
        encoded(&string(manifest, "releaseChannel")?)?,
        encoded(&string(checksum, "algorithm")?)?,
        encoded(&string(checksum, "value")?)?,
        compatibility_json,
    ))
}

fn require_exact_keys(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Result<(), String> {
    require_exact_keys_optional(object, keys, &[])
}

fn require_exact_keys_optional(
    object: &serde_json::Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), String> {
    if required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err("GOAT engine manifest contains unexpected or missing fields".to_owned());
    }
    Ok(())
}

fn json_object_string(object: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
    object.get(field)?.as_str().map(ToOwned::to_owned)
}
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_version_string(value: &str) -> bool {
    let mut sections = value.splitn(2, ['-', '+']);
    let core = sections.next().unwrap_or_default();
    let suffix = sections.next();
    let core_parts: Vec<&str> = core.split('.').collect();
    core_parts.len() == 3
        && core_parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && suffix.is_none_or(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        })
}

fn compare_versions(left: &str, right: &str) -> i8 {
    let left = parse_version(left);
    let right = parse_version(right);
    for index in 0..3 {
        if left[index] != right[index] {
            return if left[index] < right[index] { -1 } else { 1 };
        }
    }
    0
}

fn parse_version(value: &str) -> [u64; 3] {
    let mut result = [0; 3];
    for (index, part) in value.split(['.', '-', '+']).take(3).enumerate() {
        result[index] = part.parse().unwrap_or(0);
    }
    result
}

fn verify_engine(executable: &Path, manifest: &Path) -> Result<(), String> {
    validate_regular_file(executable)?;
    validate_regular_file(manifest)?;
    let manifest_text = read_bounded_text(manifest, 128 * 1024, "installed engine manifest")?;
    validate_manifest_identity(&manifest_text)?;
    let expected = manifest_field(&manifest_text, "value")
        .ok_or_else(|| "installed GOAT engine manifest has no checksum".to_owned())?;
    let actual = sha256_file(executable)?;
    if expected != actual {
        return Err("installed GOAT engine failed its checksum verification".to_owned());
    }
    Ok(())
}

fn manifest_field(text: &str, field: &str) -> Option<String> {
    let manifest: Value = serde_json::from_str(text).ok()?;
    manifest
        .get("checksum")?
        .get(field)?
        .as_str()
        .map(ToOwned::to_owned)
}

fn json_string_field(text: &str, field: &str) -> Option<String> {
    let object: Value = serde_json::from_str(text).ok()?;
    object.get(field)?.as_str().map(ToOwned::to_owned)
}

#[cfg(test)]
fn encode_base64url(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        output.push(TABLE[(first >> 2) as usize] as char);
        output.push(TABLE[((first & 0x03) << 4 | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((second & 0x0f) << 2 | (third >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(TABLE[(third & 0x3f) as usize] as char);
        }
    }
    output
}

fn decode_base64url(value: &str) -> Result<Vec<u8>, String> {
    decode_base64_inner(value, true)
}

fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    decode_base64_inner(value, false)
}

fn decode_base64_inner(value: &str, url_safe: bool) -> Result<Vec<u8>, String> {
    if value.is_empty() || (url_safe && value.contains('=')) {
        return Err("base64 value is invalid".to_owned());
    }
    let mut output = Vec::new();
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    let mut padding = false;
    let mut padding_count = 0u8;
    for byte in value.bytes() {
        if byte == b'=' {
            if url_safe || padding_count == 2 {
                return Err("base64 value is invalid".to_owned());
            }
            padding = true;
            padding_count += 1;
            continue;
        }
        if padding {
            return Err("base64 value is invalid".to_owned());
        }
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' if url_safe => 62,
            b'_' if url_safe => 63,
            b'+' if !url_safe => 62,
            b'/' if !url_safe => 63,
            _ => return Err("base64 value is invalid".to_owned()),
        } as u32;
        accumulator = (accumulator << 6) | digit;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    if (padding_count > 0 && value.len() % 4 != 0)
        || (padding_count == 1 && bits != 2)
        || (padding_count == 2 && bits != 4)
        || bits >= 6
        || accumulator != 0
    {
        return Err("base64 value is not canonical".to_owned());
    }
    Ok(output)
}

fn launch_engine(paths: &InstallPaths, args: &[String]) -> Result<u8, String> {
    let executable = paths.engine_root.join("bin").join(engine_executable());
    let status = Command::new(&executable)
        .args(args)
        .current_dir(
            env::current_dir()
                .map_err(|error| format!("cannot read current directory: {error}"))?,
        )
        .status()
        .map_err(|error| format!("cannot launch GOAT engine: {error}"))?;
    Ok(status.code().unwrap_or(1).try_into().unwrap_or(1))
}

fn run_command(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} exited unsuccessfully"))
    }
}

fn run_command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("{program} did not provide stdout"))?;
    let mut bytes = Vec::new();
    stdout
        .take(MAX_TOOL_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {program} output: {error}"))?;
    if bytes.len() as u64 > MAX_TOOL_OUTPUT_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("{program} returned too much output"));
    }
    let status = child
        .wait()
        .map_err(|error| format!("cannot wait for {program}: {error}"))?;
    if !status.success() {
        return Err(format!("{program} exited unsuccessfully"));
    }
    String::from_utf8(bytes).map_err(|error| format!("{program} returned invalid output: {error}"))
}

fn read_bounded_text(path: &Path, max_bytes: u64, label: &str) -> Result<String, String> {
    let size = fs::metadata(path)
        .map_err(|error| format!("cannot inspect {label}: {error}"))?
        .len();
    if size > max_bytes {
        return Err(format!("{label} is too large"));
    }
    fs::read_to_string(path).map_err(|error| format!("cannot read {label}: {error}"))
}

fn validate_archive_listing(archive: &Path) -> Result<(), String> {
    let listing = run_command_output(TAR_PATH, &["-tzf", &path_string(archive)])?;
    let entries: Vec<&str> = listing.lines().filter(|entry| !entry.is_empty()).collect();
    let executable_entry = format!("package/bin/{}", engine_executable());
    let required_entries = [
        executable_entry,
        "package/goat-engine.json".to_owned(),
        "package/package.json".to_owned(),
    ];
    if entries.is_empty()
        || entries
            .iter()
            .enumerate()
            .any(|(index, entry)| entries[..index].contains(entry))
        || entries.iter().any(|entry| {
            entry.contains('\0')
                || entry.contains('\\')
                || entry.starts_with('/')
                || entry.split('/').any(|part| part == "..")
                || (!required_entries.iter().any(|expected| expected == entry)
                    && *entry != "package/"
                    && *entry != "package/bin/")
        })
        || required_entries
            .iter()
            .any(|expected| !entries.contains(&expected.as_str()))
    {
        return Err("downloaded GOAT engine archive contains an unsafe path".to_owned());
    }
    let verbose = run_command_output(TAR_PATH, &["-tvzf", &path_string(archive)])?;
    if verbose
        .lines()
        .filter(|entry| !entry.is_empty())
        .any(|entry| !matches!(entry.as_bytes().first(), Some(b'-' | b'd')))
    {
        return Err("downloaded GOAT engine archive contains a link or special entry".to_owned());
    }
    Ok(())
}

fn process_id() -> u32 {
    std::process::id()
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn engine_package_name() -> &'static str {
    match (PLATFORM, ARCHITECTURE) {
        ("win32", "x64") => "goat-engine-windows-x64",
        ("win32", "arm64") => "goat-engine-windows-arm64",
        ("darwin", "x64") => "goat-engine-darwin-x64",
        ("darwin", "arm64") => "goat-engine-darwin-arm64",
        _ => unreachable!(),
    }
}

fn engine_executable() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "goat-engine.exe"
    }
    #[cfg(target_os = "macos")]
    {
        "goat-engine"
    }
}

fn engine_archive_name() -> String {
    format!("{}-{ENGINE_VERSION}.tgz", engine_package_name())
}

#[cfg(target_os = "macos")]
fn set_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)
        .map_err(|error| format!("cannot mark {} executable: {error}", path.display()))
}

struct Sha256 {
    state: [u32; 8],
    length: u64,
    buffer: Vec<u8>,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            length: 0,
            buffer: Vec::with_capacity(64),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.length += bytes.len() as u64;
        self.buffer.extend_from_slice(bytes);
        while self.buffer.len() >= 64 {
            let block: Vec<u8> = self.buffer.drain(..64).collect();
            self.compress(&block);
        }
    }

    fn finish(mut self) -> String {
        let bit_length = self.length * 8;
        self.buffer.push(0x80);
        while self.buffer.len() % 64 != 56 {
            self.buffer.push(0);
        }
        self.buffer.extend_from_slice(&bit_length.to_be_bytes());
        while !self.buffer.is_empty() {
            let block: Vec<u8> = self.buffer.drain(..64).collect();
            self.compress(&block);
        }
        self.state
            .iter()
            .map(|word| format!("{word:08x}"))
            .collect()
    }

    fn compress(&mut self, block: &[u8]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut words = [0u32; 64];
        for (index, chunk) in block.chunks_exact(4).take(16).enumerate() {
            words[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let mut working = self.state;
        for index in 0..64 {
            let s1 = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let choose = (working[4] & working[5]) ^ ((!working[4]) & working[6]);
            let temp1 = working[7]
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let majority =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let temp2 = s0.wrapping_add(majority);
            working[7] = working[6];
            working[6] = working[5];
            working[5] = working[4];
            working[4] = working[3].wrapping_add(temp1);
            working[3] = working[2];
            working[2] = working[1];
            working[1] = working[0];
            working[0] = temp1.wrapping_add(temp2);
        }
        for (state, value) in self.state.iter_mut().zip(working.iter().copied()) {
            *state = state.wrapping_add(value);
        }
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    hash.finish()
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        fs::File::open(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn sha256_matches_standard_vector() {
        let mut hash = Sha256::new();
        hash.update(b"abc");
        assert_eq!(
            hash.finish(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn engine_package_url_is_fixed_to_the_supported_target() {
        let package = engine_package_name();
        let url = format!("{REGISTRY_ORIGIN}/{package}/-/{package}-{ENGINE_VERSION}.tgz");
        assert!(url.starts_with("https://registry.npmjs.org/"));
        assert!(!url.contains('?'));
        assert!(!url.contains('#'));
    }

    #[test]
    fn manifest_checksum_extracts_from_checksum_object() {
        let manifest =
            r#"{"checksum":{"algorithm":"sha256","value":"abc"},"signature":{"status":"signed"}}"#;
        assert_eq!(manifest_field(manifest, "value"), Some("abc".to_owned()));
    }

    #[test]
    fn canonical_signed_manifest_verifies_with_the_trusted_key() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let mut public_key_der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        public_key_der.extend_from_slice(&signing_key.verifying_key().to_bytes());
        let policy = "a".repeat(64);
        let key_id = sha256_bytes(&public_key_der);
        let public_key = encode_base64url(&public_key_der);
        let placeholder = encode_base64url(&[0u8; 64]);
        let manifest = |signature: &str| {
            format!(
                "{{\"manifestVersion\":1,\"releasePolicyDigest\":\"{policy}\",\"engineVersion\":\"{ENGINE_VERSION}\",\"platform\":\"win32\",\"architecture\":\"x64\",\"executablePath\":\"bin/goat-engine.exe\",\"releaseChannel\":\"stable\",\"checksum\":{{\"algorithm\":\"sha256\",\"value\":\"{}\"}},\"compatibility\":{{\"minimumLauncherVersion\":\"{LAUNCHER_VERSION}\"}},\"signature\":{{\"status\":\"signed\",\"algorithm\":\"ed25519\",\"keyId\":\"{key_id}\",\"publicKey\":\"{public_key}\",\"value\":\"{signature}\"}}}}",
                "b".repeat(64),
            )
        };
        let placeholder_manifest = manifest(&placeholder);
        let value: Value = serde_json::from_str(&placeholder_manifest).unwrap();
        let object = value.as_object().unwrap();
        let checksum = object.get("checksum").and_then(Value::as_object).unwrap();
        let compatibility = object
            .get("compatibility")
            .and_then(Value::as_object)
            .unwrap();
        let canonical = canonical_manifest_payload(object, checksum, compatibility).unwrap();
        let signature = encode_base64url(&signing_key.sign(canonical.as_bytes()).to_bytes());
        assert!(validate_manifest_identity_with_trust(
            &manifest(&signature),
            &public_key_der,
            &policy
        )
        .is_ok());
        assert!(validate_manifest_identity_with_trust(
            &manifest(&placeholder),
            &public_key_der,
            &policy
        )
        .is_err());
    }

    #[test]
    fn installer_does_not_accept_an_external_download_origin() {
        assert_eq!(REGISTRY_ORIGIN, "https://registry.npmjs.org");
        assert!(REGISTRY_ORIGIN.starts_with("https://"));
    }

    #[test]
    fn base64url_decoder_requires_canonical_unpadded_input() {
        assert_eq!(decode_base64url("SGk"), Ok(b"Hi".to_vec()));
        assert!(decode_base64url("SGk=").is_err());
        assert!(decode_base64url("SGl").is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_user_path_rejects_path_list_delimiters() {
        assert!(
            validate_user_path(Path::new(r"C:\\Users\\goat;attacker"), "LOCALAPPDATA").is_err()
        );
    }
}
