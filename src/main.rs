extern crate reqwest;
extern crate tempfile;
extern crate winapi;

use std::{error, thread, time, fmt};
use std::ffi::OsString;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::io::copy;
use std::panic;

macro_rules! try_message_box_panic {
    ($expr:expr) => (match $expr {
        std::result::Result::Ok(val) => val,
        std::result::Result::Err(err) => {
            error_message_box(err.to_string());
            panic!("KpRm updater error: {:?}", err);
        }
    });
}

trait Ignore: Sized {
    fn ignore(self) -> () {}
}

impl<T, E> Ignore for Result<T, E> {}

type ProcessResult = std::result::Result<String, ProcessError>;

#[derive(Debug)]
enum ProcessError {
    OpenProcessError,
    GetProcessFileNameError,
    UnicodeError,
    KillError,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ProcessError::OpenProcessError => write!(f, "Failed to open process"),
            ProcessError::GetProcessFileNameError => write!(f, "Failed to get process file name"),
            ProcessError::UnicodeError => write!(f, "Failed path contains invalid Unicode data"),
            ProcessError::KillError => write!(f, "Failed to kill process"),
        }
    }
}

fn download() -> Result<PathBuf, Box<dyn error::Error>> {
    use tempfile::NamedTempFile;

    let target = "https://download.toolslib.net/download/direct/951/latest";
    let tmp_file = NamedTempFile::new()?;
    let (mut tmp_file, path) = tmp_file.keep()?;
    let mut response = reqwest::get(target)?;
    copy(&mut response, &mut tmp_file)?;
    Ok(path)
}

fn error_message_box(content: String) {
    use std::iter::once;
    use winapi::um::winuser::{
        MB_ICONERROR, MB_OK, MB_SYSTEMMODAL, MessageBoxW,
    };

    let lp_text: Vec<u16> = content.encode_utf16().chain(once(0)).collect();
    let lp_caption: Vec<u16> = "KpRm updater error".encode_utf16().chain(once(0)).collect();

    unsafe {
        MessageBoxW(
            null_mut(),
            lp_text.as_ptr(),
            lp_caption.as_ptr(),
            MB_OK | MB_ICONERROR | MB_SYSTEMMODAL,
        );
    }
}

fn kill_process_and_get_path(pid: u32) -> ProcessResult {
    use winapi::um::processthreadsapi::{OpenProcess, TerminateProcess};
    use winapi::um::psapi::GetModuleFileNameExW;
    use winapi::um::handleapi::CloseHandle;
    use winapi::shared::minwindef::{TRUE, MAX_PATH, DWORD};
    use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_READ};
    use std::os::windows::ffi::OsStringExt;

    let desired_access: u32 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE;
    let mut kprm_path: String = String::new();
    let mut the_buffer = Vec::with_capacity(MAX_PATH);

    unsafe {
        let handle = OpenProcess(desired_access, 0, pid);

        if handle.is_null() {
            return Err(
                ProcessError::OpenProcessError
            );
        }

        let length = GetModuleFileNameExW(
            handle,
            null_mut(),
            the_buffer.as_mut_ptr(),
            MAX_PATH as DWORD) as usize;

        if length == 0 {
            CloseHandle(handle);

            return Err(
                ProcessError::GetProcessFileNameError
            );

        } else if length < MAX_PATH {
            the_buffer.set_len(length);

            kprm_path = match OsString::from_wide(&the_buffer).into_string() {
                Ok(s) => s,
                Err(_e) => {
                    CloseHandle(handle);

                    return Err(
                        ProcessError::UnicodeError
                    );
                }
            };
        }

        if TerminateProcess(handle, 0) != TRUE {
            CloseHandle(handle);

            return Err(
                ProcessError::KillError
            );
        }

        CloseHandle(handle);
        Ok(kprm_path)
    }
}

fn main() {
    use std::fs::remove_file;
    use std::process::Command;
    use std::env;

    let args: Vec<String> = env::args().collect();
    assert_eq!(args.len(), 2);
    let pid = args[1].parse::<u32>().unwrap();
    let mut new_version_tmp = try_message_box_panic!(download());
    let kprm_path = try_message_box_panic!(kill_process_and_get_path(pid));
    thread::sleep(time::Duration::from_secs(2));
    try_message_box_panic!(remove_file(&kprm_path));
    let mut new_kprm_path = std::path::Path::new(&kprm_path);
    try_message_box_panic!(std::fs::copy(&mut new_version_tmp, &mut new_kprm_path));
    thread::sleep(time::Duration::from_secs(2));
    remove_file(new_version_tmp).ignore();
    try_message_box_panic!(Command::new(new_kprm_path).spawn());
}
