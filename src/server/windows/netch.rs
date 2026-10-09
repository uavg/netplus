use std::{
    ffi::{CStr, OsStr},
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, ensure};
use tracing::info;
use windows_sys::Win32::{
    Foundation::{FreeLibrary, HMODULE},
    System::LibraryLoader::{GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW},
};

use crate::{
    Config,
    config::{ProcessModeConfig, Upstream},
};

const FILTER_LOOPBACK: i32 = 0;
const FILTER_INTRANET: i32 = 1;
const FILTER_PARENT: i32 = 2;
const FILTER_ICMP: i32 = 3;
const FILTER_TCP: i32 = 4;
const FILTER_UDP: i32 = 5;
const FILTER_DNS: i32 = 6;
const TARGET_HOST: i32 = 12;
const TARGET_PORT: i32 = 13;
const TARGET_USER: i32 = 14;
const TARGET_PASSWORD: i32 = 15;
const CLEAR_NAMES: i32 = 16;
const ADD_NAME: i32 = 17;

type RegisterFn = unsafe extern "C" fn(*const u16) -> i32;
type DialFn = unsafe extern "C" fn(i32, *const u16) -> i32;
type InitFn = unsafe extern "C" fn() -> i32;
type FreeFn = unsafe extern "C" fn();

pub(in crate::server) struct NetchProcessMode {
    library: RedirectorLibrary,
}

impl NetchProcessMode {
    pub fn start(config: &Config, process: ProcessModeConfig) -> anyhow::Result<Self> {
        let upstream = config
            .upstream()?
            .context("the Netch backend requires a SOCKS5 upstream")?;
        let library = RedirectorLibrary::load(&process.netch_runtime_dir)?;
        library.ensure_driver(&process.netch_runtime_dir)?;
        configure(&library, &upstream, &process)?;
        library.init()?;

        info!(
            runtime = %process.netch_runtime_dir.display(),
            tcp = true,
            udp = true,
            "experimental Netch process interception started"
        );
        Ok(Self { library })
    }
}

impl Drop for NetchProcessMode {
    fn drop(&mut self) {
        self.library.stop();
    }
}

struct RedirectorLibrary {
    module: HMODULE,
    register: RegisterFn,
    dial: DialFn,
    init: InitFn,
    free: FreeFn,
}

impl RedirectorLibrary {
    fn load(runtime_dir: &Path) -> anyhow::Result<Self> {
        let redirector = runtime_dir.join("Redirector.bin");
        ensure!(
            runtime_dir.join("nfapi.dll").is_file(),
            "{} is missing",
            runtime_dir.join("nfapi.dll").display()
        );
        ensure!(redirector.is_file(), "{} is missing", redirector.display());

        let redirector_wide = wide(redirector.as_os_str());
        let module = unsafe {
            LoadLibraryExW(
                redirector_wide.as_ptr(),
                std::ptr::null_mut(),
                LOAD_WITH_ALTERED_SEARCH_PATH,
            )
        };
        ensure!(
            !module.is_null(),
            "failed to load {}: {}",
            redirector.display(),
            std::io::Error::last_os_error()
        );

        let result = unsafe {
            Ok(Self {
                module,
                register: load_symbol(module, c"aio_register")?,
                dial: load_symbol(module, c"aio_dial")?,
                init: load_symbol(module, c"aio_init")?,
                free: load_symbol(module, c"aio_free")?,
            })
        };
        if result.is_err() {
            unsafe { FreeLibrary(module) };
        }
        result
    }

    fn ensure_driver(&self, runtime_dir: &Path) -> anyhow::Result<()> {
        let installed = installed_driver_path()?;
        if installed.is_file() {
            return Ok(());
        }

        let source = runtime_dir.join("nfdriver.sys");
        ensure!(source.is_file(), "{} is missing", source.display());
        std::fs::copy(&source, &installed).with_context(|| {
            format!(
                "failed to install {} as {}; run netplus as Administrator",
                source.display(),
                installed.display()
            )
        })?;
        let service_name = wide(OsStr::new("netfilter2"));
        if unsafe { (self.register)(service_name.as_ptr()) } == 0 {
            std::fs::remove_file(&installed).with_context(|| {
                format!(
                    "NetFilter driver registration failed and cleanup of {} also failed",
                    installed.display()
                )
            })?;
            anyhow::bail!("NetFilter driver registration failed; the copied driver was removed");
        }
        info!(driver = %installed.display(), "installed local NetFilter test driver");
        Ok(())
    }

    fn set(&self, setting: i32, value: &str) -> anyhow::Result<()> {
        let value = wide(OsStr::new(value));
        ensure!(
            unsafe { (self.dial)(setting, value.as_ptr()) } != 0,
            "Netch redirector rejected setting {setting}"
        );
        Ok(())
    }

    fn init(&self) -> anyhow::Result<()> {
        if unsafe { (self.init)() } == 0 {
            unsafe { (self.free)() };
            anyhow::bail!(
                "Netch redirector initialization failed; verify the netfilter2 driver and runtime binaries"
            );
        }
        Ok(())
    }

    fn stop(&self) {
        unsafe { (self.free)() };
    }
}

impl Drop for RedirectorLibrary {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.module) };
    }
}

fn configure(
    library: &RedirectorLibrary,
    upstream: &Upstream,
    process: &ProcessModeConfig,
) -> anyhow::Result<()> {
    library.set(
        FILTER_LOOPBACK,
        if process.bypass_private {
            "false"
        } else {
            "true"
        },
    )?;
    library.set(
        FILTER_INTRANET,
        if process.bypass_private {
            "false"
        } else {
            "true"
        },
    )?;
    library.set(FILTER_PARENT, "false")?;
    library.set(FILTER_ICMP, "false")?;
    library.set(FILTER_TCP, "true")?;
    library.set(FILTER_UDP, "true")?;
    library.set(FILTER_DNS, "false")?;
    library.set(TARGET_HOST, &upstream.host)?;
    library.set(TARGET_PORT, &upstream.port.to_string())?;
    library.set(
        TARGET_USER,
        upstream.username.as_deref().unwrap_or_default(),
    )?;
    library.set(
        TARGET_PASSWORD,
        upstream.password.as_deref().unwrap_or_default(),
    )?;
    library.set(CLEAR_NAMES, "")?;
    for executable in &process.executable_names {
        library.set(ADD_NAME, &case_insensitive_filename_regex(executable))?;
    }
    Ok(())
}

fn case_insensitive_filename_regex(filename: &str) -> String {
    let mut regex = String::from(r"(^|[\\/])");
    for character in filename.chars() {
        if character.is_ascii_alphabetic() {
            regex.push('[');
            regex.push(character.to_ascii_lowercase());
            regex.push(character.to_ascii_uppercase());
            regex.push(']');
        } else {
            if matches!(
                character,
                '\\' | '.' | '^' | '$' | '|' | '(' | ')' | '[' | ']' | '{' | '}' | '*' | '+' | '?'
            ) {
                regex.push('\\');
            }
            regex.push(character);
        }
    }
    regex.push('$');
    regex
}

fn installed_driver_path() -> anyhow::Result<PathBuf> {
    let system_root =
        std::env::var_os("SystemRoot").context("Windows SystemRoot is not available")?;
    Ok(PathBuf::from(system_root)
        .join("System32")
        .join("drivers")
        .join("netfilter2.sys"))
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

unsafe fn load_symbol<T>(module: HMODULE, name: &CStr) -> anyhow::Result<T>
where
    T: Copy,
{
    let symbol = unsafe { GetProcAddress(module, name.as_ptr().cast()) }.with_context(|| {
        format!(
            "{} is not exported by Redirector.bin",
            name.to_string_lossy()
        )
    })?;
    ensure!(
        std::mem::size_of::<T>() == std::mem::size_of_val(&symbol),
        "unexpected function pointer size"
    );
    Ok(unsafe { std::mem::transmute_copy::<unsafe extern "system" fn() -> isize, T>(&symbol) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_case_insensitive_literal_filename_regex() {
        assert_eq!(
            case_insensitive_filename_regex("Battle.net.exe"),
            "(^|[\\\\/])[bB][aA][tT][tT][lL][eE]\\.[nN][eE][tT]\\.[eE][xX][eE]$"
        );
    }
}
