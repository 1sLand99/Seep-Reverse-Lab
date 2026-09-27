// ============================================================================
//  <项目A> 完美授权激活 PoC —— version.dll (DLL 搜索顺序劫持与热补丁引擎)
//  ---------------------------------------------------------------------------
//  适配版本：<项目A> 28.40.0100 (twinBASIC 982) & 28.30.2600 (x64)
//
//  核心技术成果：
//   1. 进程内授权状态全局写入: license_type = 5 (Lifetime), ver_flag = 1
//   2. 标题栏格式化引擎短路: 0x859AE7 强制跳过 '### 30-Day Trial Version ###'
//   3. 试用文案生成点消解: 0x64699D 与 0x646AD3 消除试用天数与非免费提醒模板
//   4. 关于框许可证判定跳转: 0x15E2A47 直接短路切入 'Lifetime License' 呈现分支
//   5. 导出并转发系统原版 version.dll 全部 17 个接口，保障宿主基础功能不受损
// ============================================================================
#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use core::ffi::c_void;
use std::fs::OpenOptions;
use std::io::Write;
use std::thread;
use std::time::Duration;

type Hmod = *mut c_void;

extern "system" {
    fn GetModuleHandleW(name: *const u16) -> Hmod;
    fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> Hmod;
    fn GetProcAddress(h: Hmod, name: *const u8) -> *mut c_void;
    fn GetModuleFileNameW(h: Hmod, buf: *mut u16, size: u32) -> u32;
    fn VirtualProtect(addr: *mut c_void, size: usize, new_prot: u32, old_prot: *mut u32) -> i32;
    fn CreateThread(attr: *mut c_void, size: usize,
                    start: unsafe extern "system" fn(*mut c_void) -> u32,
                    param: *mut c_void, flags: u32, tid: *mut u32) -> *mut c_void;
}

const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

struct CodePatch {
    rva: usize,
    bytes: &'static [u8],
}

struct Map {
    size_of_image: u32,
    lic: usize,
    flag: usize,
    code_patches: &'static [CodePatch],
}

// 28.40 专属代码短路热补丁
static PATCHES_2840: [CodePatch; 4] = [
    // 1. 标题栏格式化引擎短路: 跳过 ### 30-Day Trial Version - Day 1 ###
    CodePatch {
        rva: 0x859AE7,
        bytes: &[0xE9, 0x38, 0x06, 0x00, 0x00, 0x90],
    },
    // 2. 消解 271 号试用文案模板 (<#>-Day Trial Version...)
    CodePatch {
        rva: 0x64699D,
        bytes: &[0x6A, 0x00, 0x4C, 0x8D, 0x1D, 0x61, 0xD8, 0xB6, 0x01],
    },
    // 3. 消解非免费评估文案模板 (<$app> is not freeware...)
    CodePatch {
        rva: 0x646AD3,
        bytes: &[0x6A, 0x00, 0x90, 0x90, 0x90, 0x4C, 0x8D, 0x1D, 0x2E, 0xD7, 0xB6, 0x01],
    },
    // 4. 关于框短路进入 'Lifetime License' 文本呈现
    CodePatch {
        rva: 0x15E2A47,
        bytes: &[0xE9, 0x40, 0x00, 0x00, 0x00],
    },
];

// 28.30 专属代码热补丁
static PATCHES_2830: [CodePatch; 2] = [
    CodePatch {
        rva: 0x66FC95,
        bytes: &[
            0x66, 0xC7, 0x05, 0xAC, 0x46, 0xC8, 0x01, 0x00, 0x00,
            0xC7, 0x05, 0x9C, 0x90, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00,
            0xC7, 0x05, 0xAA, 0x50, 0xC7, 0x01, 0x05, 0x00, 0x00, 0x00,
            0xE9, 0xF0, 0x00, 0x00, 0x00
        ],
    },
    CodePatch {
        rva: 0x66DB7B,
        bytes: &[0x66, 0xB8, 0xFF, 0xFF, 0x90],
    },
];

static MAPS: [Map; 2] = [
    Map {
        size_of_image: 0x0285_0000,
        lic: 0x22FD724,
        flag: 0x230170C,
        code_patches: &PATCHES_2840,
    },
    Map {
        size_of_image: 0x0283_B000,
        lic: 0x22E4D5C,
        flag: 0x22E8D44,
        code_patches: &PATCHES_2830,
    },
];

unsafe fn read_u32(p: usize) -> u32 { core::ptr::read_unaligned(p as *const u32) }
unsafe fn write_u32(p: usize, v: u32) { core::ptr::write_unaligned(p as *mut u32, v) }

fn log_path() -> Option<std::path::PathBuf> {
    unsafe {
        let mut buf = vec![0u16; 1024];
        let n = GetModuleFileNameW(core::ptr::null_mut(), buf.as_mut_ptr(), 1024);
        if n == 0 { return None; }
        let s = String::from_utf16_lossy(&buf[..n as usize]);
        let mut p = std::path::PathBuf::from(s);
        p.set_file_name("version_poc.log");
        Some(p)
    }
}

fn log(msg: &str) {
    if let Some(p) = log_path() {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
            let _ = writeln!(f, "{}", msg);
        }
    }
}

unsafe fn apply_code_patch(addr: usize, bytes: &[u8]) -> bool {
    let mut old_prot: u32 = 0;
    if VirtualProtect(addr as *mut c_void, bytes.len(), PAGE_EXECUTE_READWRITE, &mut old_prot) == 0 {
        return false;
    }
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, bytes.len());
    VirtualProtect(addr as *mut c_void, bytes.len(), old_prot, &mut old_prot);
    true
}

unsafe fn pick_map(base: usize) -> Option<&'static Map> {
    let e_lfanew = read_u32(base + 0x3C) as usize;
    if e_lfanew < 0x40 || e_lfanew > 0x1000 { return None; }
    let size_of_image = read_u32(base + e_lfanew + 0x50);
    for m in MAPS.iter() {
        if m.size_of_image == size_of_image {
            return Some(m);
        }
    }
    for m in MAPS.iter() {
        let v = read_u32(base + m.lic);
        if v <= 5 { return Some(m); }
    }
    None
}

unsafe fn patch() -> bool {
    let base = GetModuleHandleW(core::ptr::null()) as usize;
    if base == 0 { return false; }
    let m = match pick_map(base) { Some(m) => m, None => return false };

    let mut changed = false;

    // 1. 维持授权全局状态
    if read_u32(base + m.lic) != 5 {
        write_u32(base + m.lic, 5);
        changed = true;
    }
    if read_u32(base + m.flag) != 1 {
        write_u32(base + m.flag, 1);
        changed = true;
    }

    // 2. 执行底层机器码热补丁
    for p in m.code_patches {
        let target = base + p.rva;
        let mut cur = vec![0u8; p.bytes.len()];
        core::ptr::copy_nonoverlapping(target as *const u8, cur.as_mut_ptr(), p.bytes.len());
        if cur.as_slice() != p.bytes {
            apply_code_patch(target, p.bytes);
            changed = true;
        }
    }

    changed
}

unsafe extern "system" fn worker(_param: *mut c_void) -> u32 {
    let mut reported = false;
    for i in 0..2400 {
        if patch() && !reported {
            reported = true;
            let base = GetModuleHandleW(core::ptr::null()) as usize;
            let lic = pick_map(base).map(|m| read_u32(base + m.lic)).unwrap_or(0);
            log(&format!("[+] 28.40 授权与全UI去试用热补丁已生效: license_type={}", lic));
        }
        let d = if i < 160 { 50 } else { 500 };
        thread::sleep(Duration::from_millis(d));
    }
    0
}

#[no_mangle]
pub unsafe extern "system" fn DllMain(_hinst: Hmod, reason: u32, _res: *mut c_void) -> i32 {
    if reason == 1 {
        // 同步预打一次，确保启动早期第一道逻辑就生效
        patch();
        let mut tid: u32 = 0;
        CreateThread(core::ptr::null_mut(), 0, worker, core::ptr::null_mut(), 0, &mut tid);
    }
    1
}

// ============================================================================
// version.dll 导出转发
// ============================================================================
static mut REAL: Hmod = core::ptr::null_mut();

unsafe fn real() -> Hmod {
    if REAL.is_null() {
        let sys: Vec<u16> = "C:\\Windows\\System32\\version.dll\0".encode_utf16().collect();
        REAL = LoadLibraryExW(sys.as_ptr(), core::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
    REAL
}

macro_rules! fwd {
    ($name:ident, $($arg:ident : $ty:ty),*) => {
        #[no_mangle]
        pub unsafe extern "system" fn $name($($arg: $ty),*) -> isize {
            let h = real();
            let f = GetProcAddress(h, concat!(stringify!($name), "\0").as_ptr());
            if f.is_null() { return 0; }
            let fp: unsafe extern "system" fn($($ty),*) -> isize = core::mem::transmute(f);
            fp($($arg),*)
        }
    };
}

fwd!(GetFileVersionInfoA, a: *const u8, b: u32, c: u32, d: *mut c_void);
fwd!(GetFileVersionInfoW, a: *const u16, b: u32, c: u32, d: *mut c_void);
fwd!(GetFileVersionInfoByHandle, a: u32, b: *mut c_void, c: u32, d: *mut c_void);
fwd!(GetFileVersionInfoExA, a: u32, b: *const u8, c: u32, d: u32, e: *mut c_void);
fwd!(GetFileVersionInfoExW, a: u32, b: *const u16, c: u32, d: u32, e: *mut c_void);
fwd!(GetFileVersionInfoSizeA, a: *const u8, b: *mut u32);
fwd!(GetFileVersionInfoSizeW, a: *const u16, b: *mut u32);
fwd!(GetFileVersionInfoSizeExA, a: u32, b: *const u8, c: *mut u32);
fwd!(GetFileVersionInfoSizeExW, a: u32, b: *const u16, c: *mut u32);
fwd!(VerFindFileA, a: u32, b: *const u8, c: *const u8, d: *const u8, e: *mut u8, f: *mut u32, g: *mut u8, h: *mut u32);
fwd!(VerFindFileW, a: u32, b: *const u16, c: *const u16, d: *const u16, e: *mut u16, f: *mut u32, g: *mut u16, h: *mut u32);
fwd!(VerInstallFileA, a: u32, b: *const u8, c: *const u8, d: *const u8, e: *const u8, f: *mut u8, g: *mut u32);
fwd!(VerInstallFileW, a: u32, b: *const u16, c: *const u16, d: *const u16, e: *const u16, f: *mut u16, g: *mut u32);
fwd!(VerLanguageNameA, a: u32, b: *mut u8, c: u32);
fwd!(VerLanguageNameW, a: u32, b: *mut u16, c: u32);
fwd!(VerQueryValueA, a: *const c_void, b: *const u8, c: *mut *mut c_void, d: *mut u32);
fwd!(VerQueryValueW, a: *const c_void, b: *const u16, c: *mut *mut c_void, d: *mut u32);
