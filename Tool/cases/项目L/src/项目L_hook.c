// ============================================================================
//  项目L 翻译源自定义 Hook DLL  (Zig cc / MinGW-w64 编译)
//  编译产物: 项目L_Auth.dll  —— 代理官方 项目L_AuthReal.dll 全部 282 个导出
//
//  能力:
//    1. 运行时内存重定向 项目L.exe 的 {API_ENDPOINT} -> 用户自定义翻译源
//    2. 运行时内存解除 项目L_AuthReal.dll 的 14 项会员特权判定 (CWE-602)
//    3. Hook 翻译设置面板, 注入「自定义翻译源」下拉项
//    4. 面板销毁时持久化用户填写的接口地址到 项目L_hook.ini
//
//  磁盘上的官方 项目L.exe / 项目L_AuthReal.dll 保持 100% 原版 (零字节修改)
//
//  ui 配置项:
//    0 = 完全关闭 UI 注入
//    1 = 仅注入下拉项
//    2 = 注入下拉项 + 持久化 (默认)
// ============================================================================
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "项目L_bridge.h"

// ---------------------------------------------------------------- 目标 RVA
#define RVA_DOMAIN      0x0CF16E0u   // "https://api.项目L.cn" 字符串槽位 (48B)
#define RVA_MOV_LEN     0x02052E5u   // mov edx, imm32
#define RVA_LEA_1       0x02052EAu   // lea rcx, [rip+..]
#define RVA_LEA_2       0x0205316u   // lea rdx, [rip+..]
#define DOMAIN_MAX      46

#define RVA_CTOR        0x01D4C80u   // ConfWidgetTranslateKey::ctor
#define RVA_VTABLE      0x0CE8228u   // ConfWidgetTranslateKey vtable
#define VTABLE_DTOR_IDX 3

/* 默认回退端点 = 官方 API (中性占位) */
#define DEFAULT_ENDPOINT "https://api.项目L.cn"

// 控件偏移 (ui 结构体位于 widget+0x60)
#define OFF_CMB_SERVICE 0x88
#define OFF_CHK_CUSTOM  0x90
#define OFF_EDT_ID      0xB0
#define OFF_EDT_KEY     0xB8
#define CUSTOM_ITEM_IDX 2

// ---------------------------------------------------------------- 会员特权补丁表
typedef struct { DWORD rva; const BYTE* expect; DWORD elen; const BYTE* repl; DWORD rlen; } VIP_PATCH;

static const BYTE E_4883EC28[]      = {0x48,0x83,0xEC,0x28};
static const BYTE E_4883C110[]      = {0x48,0x83,0xC1,0x10};
static const BYTE E_40534883EC20[]  = {0x40,0x53,0x48,0x83,0xEC,0x20};
static const BYTE E_48895C10_48[]   = {0x48,0x89,0x5C,0x24,0x10,0x48};
static const BYTE E_48895C10_56[]   = {0x48,0x89,0x5C,0x24,0x10,0x56};
static const BYTE E_48895C08_57[]   = {0x48,0x89,0x5C,0x24,0x08,0x57};
static const BYTE E_405355565748[]  = {0x40,0x53,0x55,0x56,0x57,0x48};
static const BYTE E_405553565741[]  = {0x40,0x55,0x53,0x56,0x57,0x41};

static const BYTE P_B001C3[]        = {0xB0,0x01,0xC3};
static const BYTE P_B801000000C3[]  = {0xB8,0x01,0x00,0x00,0x00,0xC3};
static const BYTE P_31C0C3[]        = {0x31,0xC0,0xC3};
static const BYTE P_32C0C3[]        = {0x32,0xC0,0xC3};
static const BYTE P_C3[]            = {0xC3};

static const VIP_PATCH g_vip[] = {
    { 0x0C3270, E_4883EC28,     4, P_B001C3,       3 }, // UserInfo::isProUser
    { 0x09C430, E_4883C110,     4, P_B001C3,       3 }, // Application::isProUser
    { 0x0EE950, E_40534883EC20, 6, P_B001C3,       3 }, // VipInfo::isVip
    { 0x0EE910, E_40534883EC20, 6, P_B001C3,       3 }, // Subscription::isVip
    { 0x0EE7B0, E_40534883EC20, 6, P_B001C3,       3 }, // PrepaidInfo::isVip (ICF)
    { 0x0A74D0, E_48895C10_48,  6, P_B801000000C3, 6 }, // checkFeatureAllow -> Allow(1)
    { 0x0A8040, E_48895C10_56,  6, P_31C0C3,       3 }, // featureStatus   -> Available(0)
    { 0x0A86F0, E_48895C08_57,  6, P_32C0C3,       3 }, // isProFeature    -> false
    { 0x0A84B0, E_40534883EC20, 6, P_B001C3,       3 }, // hasActivatedTrialAccess -> true
    { 0x0A8C30, E_405355565748, 6, P_C3,           1 }, // rescheduleTrialExpireTimer
    { 0x09D560, E_405553565741, 6, P_C3,           1 }, // showSubscriptionTrialReminder
};

// ---------------------------------------------------------------- 云控/更新 屏蔽表
// 全部为函数入口恒值化: xor eax,eax; ret —— 直接返回“无更新/无云端配置”
typedef struct { DWORD rva; const BYTE* expect; DWORD elen; const char* name; } KILL_PATCH;

static const BYTE K_40555356574154[] = {0x40,0x55,0x53,0x56,0x57,0x41,0x54}; // checkNewVersion
static const BYTE K_40555356574156[] = {0x40,0x55,0x53,0x56,0x57,0x41,0x56}; // UserConfig*

static const KILL_PATCH g_kill[] = {
    { 0x452070, K_40555356574154, 7, "项目L_Upgrade::checkNewVersion (自动更新检查)" },
    { 0x1C8BB0, K_40555356574156, 7, "UserConfigGet    (云端配置拉取)" },
    { 0x1C8DD0, K_40555356574156, 7, "UserConfigUpdate (云端配置上报)" },
};
static const BYTE K_RET0[] = {0x31, 0xC0, 0xC3};   // xor eax,eax; ret

// ---------------------------------------------------------------- 全局状态
static char g_iniPath[MAX_PATH] = {0};
static char g_endpoint[256]     = {0};
static int  g_optVip = 1, g_optUi = 2, g_optRedirect = 1, g_optNoCloud = 1;

// 内嵌大模型网关配置
static char g_llmUrl[1024]  = {0};
static char g_llmKey[512]   = {0};
static char g_llmModel[128] = {0};
static int  g_llmStyle  = 0;    // 0=auto 1=openai 2=gemini 3=anthropic
static int  g_optBridge = 1;    // 是否启用内嵌网关
static int  g_bridgeOn  = 0;    // 网关是否已启动

static void BuildBridgeCfg(BridgeConfig* bc)
{
    memset(bc, 0, sizeof(*bc));
    strncpy(bc->llmUrl,   g_llmUrl,   sizeof(bc->llmUrl)   - 1);
    strncpy(bc->llmKey,   g_llmKey,   sizeof(bc->llmKey)   - 1);
    strncpy(bc->llmModel, g_llmModel, sizeof(bc->llmModel) - 1);
    bc->llmStyle = g_llmStyle;
    strcpy(bc->upstreamHost, "api.项目L.cn");
}

// ---------------------------------------------------------------- 日志
void HookLog(const char* fmt, ...)
{
    char path[MAX_PATH], line[1024];
    SYSTEMTIME st;
    int n;
    va_list ap;
    if (!g_iniPath[0]) return;
    strcpy(path, g_iniPath);
    { char* p = strrchr(path, '.'); if (p) strcpy(p, ".log"); else strcat(path, ".log"); }
    GetLocalTime(&st);
    n = snprintf(line, sizeof(line) - 4, "[%04d-%02d-%02d %02d:%02d:%02d] ",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    if (n < 0) n = 0;
    va_start(ap, fmt);
    { int m = vsnprintf(line + n, sizeof(line) - 4 - n, fmt, ap); if (m > 0) n += m; }
    va_end(ap);
    line[n++] = '\r'; line[n++] = '\n'; line[n] = 0;
    {
        HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(h, line, (DWORD)n, &w, NULL); CloseHandle(h); }
    }
}

// ---------------------------------------------------------------- 配置
static void Trim(char* s)
{
    int len = (int)strlen(s);
    char* p = s;
    while (len > 0 && (s[len-1]==' '||s[len-1]=='\r'||s[len-1]=='\n'||s[len-1]=='"')) s[--len] = 0;
    while (*p==' '||*p=='"') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
}

static void ConfigLoad(void)
{
    g_endpoint[0] = 0;
    GetPrivateProfileStringA("translate", "endpoint", DEFAULT_ENDPOINT, g_endpoint, sizeof(g_endpoint), g_iniPath);
    g_optVip      = GetPrivateProfileIntA("translate", "vip",      1, g_iniPath);
    g_optUi       = GetPrivateProfileIntA("translate", "ui",       2, g_iniPath);
    g_optRedirect = GetPrivateProfileIntA("translate", "redirect", 1, g_iniPath);
    g_optBridge   = GetPrivateProfileIntA("translate", "bridge",   1, g_iniPath);
    g_optNoCloud  = GetPrivateProfileIntA("translate", "nocloud",  1, g_iniPath);
    Trim(g_endpoint);
    if (!g_endpoint[0]) strcpy(g_endpoint, DEFAULT_ENDPOINT);

    // 大模型网关配置
    g_llmUrl[0] = 0; g_llmKey[0] = 0; g_llmModel[0] = 0;
    GetPrivateProfileStringA("translate", "llm_url",   "", g_llmUrl,   sizeof(g_llmUrl),   g_iniPath);
    GetPrivateProfileStringA("translate", "llm_key",   "", g_llmKey,   sizeof(g_llmKey),   g_iniPath);
    GetPrivateProfileStringA("translate", "llm_model", "", g_llmModel, sizeof(g_llmModel), g_iniPath);
    g_llmStyle = GetPrivateProfileIntA("translate", "llm_style", 0, g_iniPath);
    Trim(g_llmUrl); Trim(g_llmKey); Trim(g_llmModel);

    if (GetFileAttributesA(g_iniPath) == INVALID_FILE_ATTRIBUTES) {
        WritePrivateProfileStringA("translate", "endpoint", g_endpoint, g_iniPath);
        WritePrivateProfileStringA("translate", "vip",      "1", g_iniPath);
        WritePrivateProfileStringA("translate", "ui",       "2", g_iniPath);
        WritePrivateProfileStringA("translate", "redirect", "1", g_iniPath);
        WritePrivateProfileStringA("translate", "bridge",   "1", g_iniPath);
        WritePrivateProfileStringA("translate", "nocloud",  "1", g_iniPath);
        WritePrivateProfileStringA("translate", "llm_url",  "", g_iniPath);
        WritePrivateProfileStringA("translate", "llm_key",  "", g_iniPath);
        WritePrivateProfileStringA("translate", "llm_model","", g_iniPath);
        WritePrivateProfileStringA("translate", "llm_style","0", g_iniPath);
    }
}

// ---------------------------------------------------------------- 宿主校验
static int HostIs项目L(void)
{
    char path[MAX_PATH];
    char* p;
    DWORD n = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return 0;
    p = strrchr(path, '\\');
    if (!p) return 0;
    p++;
    return (strcmp(p, "项目L.exe") == 0);
}

// ---------------------------------------------------------------- 内存写入
static BOOL MemWrite(void* addr, const void* data, SIZE_T len)
{
    DWORD old;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    memcpy(addr, data, len);
    VirtualProtect(addr, len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
    return TRUE;
}

// ---------------------------------------------------------------- 1. 端点重定向
static BOOL PatchTranslateEndpoint(const char* domain)
{
    HMODULE exe = GetModuleHandleW(NULL);
    BYTE* base;
    size_t dlen;
    BYTE buf[64], movlen[5], lea1[7], lea2[7];
    if (!exe) return FALSE;
    if (!HostIs项目L()) { HookLog("redirect: host is not 项目L.exe, skipped"); return FALSE; }
    base = (BYTE*)exe;
    dlen = strlen(domain);
    if (dlen == 0 || dlen > DOMAIN_MAX) { HookLog("redirect: bad len %d", (int)dlen); return FALSE; }

    memset(buf, 0, sizeof(buf));
    memcpy(buf, domain, dlen);
    if (!MemWrite(base + RVA_DOMAIN, buf, 48)) { HookLog("redirect: domain fail"); return FALSE; }

    movlen[0] = 0xBA;
    *(DWORD*)(movlen + 1) = (DWORD)dlen;
    if (!MemWrite(base + RVA_MOV_LEN, movlen, 5)) { HookLog("redirect: movlen fail"); return FALSE; }

    lea1[0]=0x48; lea1[1]=0x8D; lea1[2]=0x0D;
    *(DWORD*)(lea1 + 3) = (DWORD)((INT64)RVA_DOMAIN - (INT64)(RVA_LEA_1 + 7));
    if (!MemWrite(base + RVA_LEA_1, lea1, 7)) { HookLog("redirect: lea1 fail"); return FALSE; }

    lea2[0]=0x48; lea2[1]=0x8D; lea2[2]=0x15;
    *(DWORD*)(lea2 + 3) = (DWORD)((INT64)RVA_DOMAIN - (INT64)(RVA_LEA_2 + 7));
    if (!MemWrite(base + RVA_LEA_2, lea2, 7)) { HookLog("redirect: lea2 fail"); return FALSE; }

    HookLog("redirect: {API_ENDPOINT} -> %s", domain);
    return TRUE;
}

// ---------------------------------------------------------------- 2. 会员特权解除
static void PatchVip(HMODULE real)
{
    BYTE* base;
    int done = 0, skip = 0, fail = 0, i;
    if (!real) { HookLog("vip: 项目L_AuthReal.dll not loaded"); return; }
    base = (BYTE*)real;
    for (i = 0; i < (int)(sizeof(g_vip)/sizeof(g_vip[0])); i++) {
        const VIP_PATCH* p = &g_vip[i];
        BYTE* addr = base + p->rva;
        if (memcmp(addr, p->repl, p->rlen) == 0) { skip++; continue; }
        if (memcmp(addr, p->expect, p->elen) != 0) { fail++; HookLog("vip: mismatch @0x%X", p->rva); continue; }
        if (MemWrite(addr, p->repl, p->rlen)) done++; else fail++;
    }
    HookLog("vip: applied=%d already=%d mismatch=%d", done, skip, fail);
}

// ---------------------------------------------------------------- 2.5 云控与更新屏蔽
static void PatchNoCloud(void)
{
    HMODULE exe = GetModuleHandleW(NULL);
    BYTE* base;
    int done = 0, skip = 0, fail = 0, i;
    if (!exe) return;
    if (!HostIs项目L()) { HookLog("nocloud: host is not 项目L.exe, skipped"); return; }
    base = (BYTE*)exe;
    for (i = 0; i < (int)(sizeof(g_kill) / sizeof(g_kill[0])); i++) {
        const KILL_PATCH* p = &g_kill[i];
        BYTE* addr = base + p->rva;
        if (memcmp(addr, K_RET0, 3) == 0) { skip++; continue; }
        if (memcmp(addr, p->expect, p->elen) != 0) {
            fail++;
            HookLog("nocloud: 特征码不匹配 @0x%X (%s)", p->rva, p->name);
            continue;
        }
        if (MemWrite(addr, K_RET0, 3)) { done++; HookLog("nocloud: 已屏蔽 %s", p->name); }
        else fail++;
    }
    HookLog("nocloud: applied=%d already=%d mismatch=%d", done, skip, fail);
}

// ---------------------------------------------------------------- 3. Qt 接口
// QString / QByteArray / QVariant / QIcon 均为 8~16 字节的非平凡类型,
// 统一用 32 字节缓冲兜底 (x64 MSVC ABI: 隐藏返回指针在 rcx)
typedef struct { unsigned char b[32]; } QBlob;

typedef void        (*fn_fromUtf8)(void* ret, const char* s, int len);
typedef void        (*fn_variantCtor)(void* var, const void* qs);
typedef void        (*fn_iconCtor)(void* icon);
typedef int         (*fn_count)(void* combo);
typedef void        (*fn_insertItem)(void* combo, int idx, const void* icon, const void* label, const void* var);
typedef int         (*fn_currentIndex)(void* combo);
typedef void        (*fn_text)(void* ret, void* edit);
typedef void        (*fn_toUtf8)(void* ret, const void* qs);
typedef const char* (*fn_constData)(void* ba);

static fn_fromUtf8     p_fromUtf8  = NULL;
static fn_variantCtor  p_varCtor   = NULL;
static fn_iconCtor     p_iconCtor  = NULL;
static fn_count        p_count     = NULL;
static fn_insertItem   p_insert    = NULL;
static fn_currentIndex p_curIdx    = NULL;
static fn_text         p_text      = NULL;
static fn_toUtf8       p_toUtf8    = NULL;
static fn_constData    p_constData = NULL;

static void* g_widget = NULL;

static FARPROC Resolve(HMODULE m, const char* n)
{
    FARPROC p = m ? GetProcAddress(m, n) : NULL;
    if (!p) HookLog("qt: missing %s", n);
    return p;
}

static void InitQt(void)
{
    HMODULE w = GetModuleHandleA("Qt5Widgets.dll");
    HMODULE c = GetModuleHandleA("Qt5Core.dll");
    HMODULE g = GetModuleHandleA("Qt5Gui.dll");
    if (!w || !c) { HookLog("qt: dll not loaded (w=%p c=%p)", w, c); return; }
    p_fromUtf8  = (fn_fromUtf8)     Resolve(c, "?fromUtf8@QString@@SA?AV1@PEBDH@Z");
    p_varCtor   = (fn_variantCtor)  Resolve(c, "??0QVariant@@QEAA@AEBVQString@@@Z");
    p_toUtf8    = (fn_toUtf8)       Resolve(c, "?toUtf8@QString@@QEBA?AVQByteArray@@XZ");
    p_constData = (fn_constData)    Resolve(c, "?constData@QByteArray@@QEBAPEBDXZ");
    p_iconCtor  = (fn_iconCtor)     Resolve(g, "??0QIcon@@QEAA@XZ");
    p_count     = (fn_count)        Resolve(w, "?count@QComboBox@@QEBAHXZ");
    p_insert    = (fn_insertItem)   Resolve(w, "?insertItem@QComboBox@@QEAAXHAEBVQIcon@@AEBVQString@@AEBVQVariant@@@Z");
    p_curIdx    = (fn_currentIndex) Resolve(w, "?currentIndex@QComboBox@@QEBAHXZ");
    p_text      = (fn_text)         Resolve(w, "?text@QLineEdit@@QEBA?AVQString@@XZ");
}

static void StrToUtf8(const QBlob* qs, char* out, int outSize)
{
    QBlob ba;
    const char* s;
    out[0] = 0;
    if (!p_toUtf8 || !p_constData) return;
    memset(&ba, 0, sizeof(ba));
    p_toUtf8(&ba, qs);
    s = p_constData(&ba);
    if (s) { strncpy(out, s, outSize - 1); out[outSize-1] = 0; }
}

// 从面板读回用户填写的自定义大模型接口地址与 Key
static void SaveFromWidget(void* self)
{
    void* combo;
    void* edt;
    void* edtKey;
    char url[1024];
    char key[512];
    QBlob qs;
    int changed = 0;

    if (!self || !p_text || !p_curIdx || !p_toUtf8) return;
    combo  = *(void**)((BYTE*)self + OFF_CMB_SERVICE);
    edt    = *(void**)((BYTE*)self + OFF_EDT_ID);
    edtKey = *(void**)((BYTE*)self + OFF_EDT_KEY);
    if (!combo || !edt) return;
    if (p_curIdx(combo) != CUSTOM_ITEM_IDX) return;   // 仅自定义项生效

    // --- 接口地址 (APP ID 栏) ---
    memset(&qs, 0, sizeof(qs));
    p_text(&qs, edt);
    StrToUtf8(&qs, url, sizeof(url));
    Trim(url);
    if (url[0] && (strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0)
        && strcmp(url, g_llmUrl) != 0) {
        strncpy(g_llmUrl, url, sizeof(g_llmUrl) - 1);
        g_llmUrl[sizeof(g_llmUrl) - 1] = 0;
        WritePrivateProfileStringA("translate", "llm_url", g_llmUrl, g_iniPath);
        HookLog("ui: llm_url saved -> %s", g_llmUrl);
        changed = 1;
    }

    // --- API Key (密钥 栏) ---
    if (edtKey) {
        memset(&qs, 0, sizeof(qs));
        p_text(&qs, edtKey);
        StrToUtf8(&qs, key, sizeof(key));
        Trim(key);
        if (key[0] && strcmp(key, g_llmKey) != 0) {
            strncpy(g_llmKey, key, sizeof(g_llmKey) - 1);
            g_llmKey[sizeof(g_llmKey) - 1] = 0;
            WritePrivateProfileStringA("translate", "llm_key", g_llmKey, g_iniPath);
            HookLog("ui: llm_key saved (len=%d)", (int)strlen(g_llmKey));
            changed = 1;
        }
    }

    if (!changed) return;

    // --- 热更新网关 + 确保端点指向本地网关 ---
    if (g_llmUrl[0]) {
        BridgeConfig bc;
        BuildBridgeCfg(&bc);
        if (g_bridgeOn) {
            BridgeUpdateConfig(&bc);
        } else {
            int port = BridgeStart(&bc);
            if (port > 0) {
                char local[64];
                sprintf(local, "http://127.0.0.1:%d", port);
                PatchTranslateEndpoint(local);
                g_bridgeOn = 1;
                HookLog("bridge: started on demand -> %s", local);
            }
        }
    } else {
        PatchTranslateEndpoint(g_endpoint);
    }
}

// ---------------------------------------------------------------- 4. Hook 安装
static BYTE* g_ctorTarget = NULL;
static BYTE  g_origBytes[15];
static BYTE  g_patchBytes[15];
static int   g_hookArmed = 0;
typedef void* (*PFN_CTOR)(void* self, void* a2, void* a3);
typedef void* (*PFN_DTOR)(void* self, unsigned int flags);
static PFN_DTOR g_dtorOrig = NULL;

// 还原原始 15 字节
static void CtorUnpatch(void)
{
    DWORD old;
    if (!g_hookArmed) return;
    VirtualProtect(g_ctorTarget, 15, PAGE_EXECUTE_READWRITE, &old);
    memcpy(g_ctorTarget, g_origBytes, 15);
    FlushInstructionCache(GetCurrentProcess(), g_ctorTarget, 15);
    VirtualProtect(g_ctorTarget, 15, old, &old);
}

// 重新写入绝对跳转
static void CtorRepatch(void)
{
    DWORD old;
    if (!g_hookArmed) return;
    VirtualProtect(g_ctorTarget, 15, PAGE_EXECUTE_READWRITE, &old);
    memcpy(g_ctorTarget, g_patchBytes, 15);
    FlushInstructionCache(GetCurrentProcess(), g_ctorTarget, 15);
    VirtualProtect(g_ctorTarget, 15, old, &old);
}

/*
 * 关键修正 (v1.4):
 *   A. 弃用 trampoline (栈语义错误) -> 改用标准 unhook-call-rehook
 *   B. 必须保留 rax 返回值 (MSVC x64 构造函数在 rax 中返回 this)
 *   C. **必须转发全部 3 个参数**。工厂函数 (RVA 0x1D55F0) 的反汇编为:
 *          mov r8, rbx        ; 第 3 个参数
 *          mov rdx, rdi
 *          mov rcx, rax       ; this
 *          call 0x1401d4c80   ; ctor(this, arg1, arg2)
 *      而该构造函数首部会直接以当前 rcx/rdx/r8 调用基类构造函数,
 *      因此漏掉 r8 会让基类拿到野指针 -> 崩溃。
 */
static void* CtorHook(void* self, void* a2, void* a3)
{
    void* combo;
    QBlob label, key, var, icon;

    HookLog("ui: [1] CtorHook ENTER self=%p a2=%p a3=%p", self, a2, a3);
    CtorUnpatch();
    HookLog("ui: [2] original ctor calling...");
    ((PFN_CTOR)g_ctorTarget)(self, a2, a3);   // 完整转发 3 个参数
    HookLog("ui: [3] original ctor returned");
    CtorRepatch();

    g_widget = self;

    if (g_optUi < 1) return self;
    if (!p_insert || !p_fromUtf8 || !p_varCtor || !p_iconCtor || !p_count) {
        HookLog("ui: qt funcs unavailable, skip injection");
        return self;
    }

    combo = *(void**)((BYTE*)self + OFF_CMB_SERVICE);
    HookLog("ui: [4] cmbService=%p count=%d", combo, combo ? p_count(combo) : -1);
    if (!combo) { HookLog("ui: cmbService null @%p", self); return self; }

    // 完全复刻官方写法:
    //   cmbService->insertItem(count(), QIcon(), tr("自定义翻译源"), QVariant(QString("custom")))
    memset(&label, 0, sizeof(label));
    memset(&key,   0, sizeof(key));
    memset(&var,   0, sizeof(var));
    memset(&icon,  0, sizeof(icon));
    p_fromUtf8(&label, "\xE8\x87\xAA\xE5\xAE\x9A\xE4\xB9\x89\xE7\xBF\xBB\xE8\xAF\x91\xE6\xBA\x90", -1); // 自定义翻译源
    p_fromUtf8(&key,   "custom", -1);
    p_varCtor(&var, &key);       // QVariant(QString) —— 必须是有效 QVariant
    p_iconCtor(&icon);           // QIcon()

    {
        int idx = p_count(combo);
        HookLog("ui: [5] inserting at idx=%d", idx);
        p_insert(combo, idx, &icon, &label, &var);
        HookLog("ui: [6] custom item inserted at idx=%d (combo=%p)", idx, combo);
    }
    return self;                 // <-- 保留构造函数返回值 rax = this
}

static void* DtorHook(void* self, unsigned int flags)
{
    SaveFromWidget(self);
    if (g_widget == self) g_widget = NULL;
    return g_dtorOrig(self, flags);
}

static void InstallHooks(void)
{
    HMODULE exe = GetModuleHandleW(NULL);
    static const BYTE expect[15] = {
        0x48,0x89,0x5C,0x24,0x10,   /* mov [rsp+0x10], rbx */
        0x48,0x89,0x74,0x24,0x18,   /* mov [rsp+0x18], rsi */
        0x48,0x89,0x4C,0x24,0x08    /* mov [rsp+8], rcx    */
    };
    /*
     * 重要: 项目L.exe 与我们的 DLL 在 64 位地址空间上可能相隔 > 2GB,
     *       因此 **绝不能** 使用 5 字节 rel32 跳转 (会溢出回绕导致
     *       0xC0000005 EXECUTE 访问违例)。统一使用 14 字节绝对跳转:
     *         FF 25 00 00 00 00   jmp qword ptr [rip+0]
     *         <8 字节绝对地址>
     *       共覆盖目标函数前 15 字节 (3 条完整指令), 无指令切断风险。
     */

    if (!exe || !HostIs项目L()) { HookLog("ui: host is not 项目L.exe, skip hooks"); return; }
    g_ctorTarget = (BYTE*)exe + RVA_CTOR;

    // --- 构造函数 detour (绝对跳转 + unhook-call-rehook) ---
    if (memcmp(g_ctorTarget, expect, sizeof(expect)) != 0) {
        HookLog("ui: ctor signature mismatch, skip");
    } else {
        memcpy(g_origBytes, g_ctorTarget, 15);
        g_patchBytes[0] = 0xFF; g_patchBytes[1] = 0x25;
        *(DWORD*)(g_patchBytes + 2) = 0;
        *(void**)(g_patchBytes + 6) = (void*)&CtorHook;
        g_patchBytes[14] = 0x90;

        g_hookArmed = 1;
        if (MemWrite(g_ctorTarget, g_patchBytes, 15))
            HookLog("ui: ctor hooked @%p -> %p (abs jmp + unhook-call-rehook, dist=0x%llX)",
                    g_ctorTarget, (void*)&CtorHook,
                    (unsigned long long)((INT64)(BYTE*)&CtorHook - (INT64)g_ctorTarget));
        else {
            g_hookArmed = 0;
            HookLog("ui: ctor hook write failed");
        }
    }

    // --- vtable 析构函数替换 (仅 ui>=2 时启用持久化) ---
    if (g_optUi >= 2) {
        void** vt = (void**)((BYTE*)exe + RVA_VTABLE);
        void** slot = vt + VTABLE_DTOR_IDX;
        void*  newp = (void*)&DtorHook;
        g_dtorOrig = (PFN_DTOR)(*slot);
        if (MemWrite(slot, &newp, sizeof(void*)))
            HookLog("ui: dtor hooked (orig=%p)", (void*)g_dtorOrig);
        else
            HookLog("ui: dtor hook failed");
    } else {
        HookLog("ui: dtor hook disabled (ui=%d)", g_optUi);
    }
}

// ---------------------------------------------------------------- 初始化线程
static DWORD WINAPI InitThread(LPVOID param)
{
    int i;
    (void)param;
    for (i = 0; i < 300; i++) {
        if (GetModuleHandleA("Qt5Widgets.dll") && GetModuleHandleA("项目L_AuthReal.dll")) break;
        Sleep(50);
    }
    ConfigLoad();
    HookLog("=== 项目L Hook v2.0 === endpoint=%s vip=%d ui=%d redirect=%d bridge=%d",
            g_endpoint, g_optVip, g_optUi, g_optRedirect, g_optBridge);
    HookLog("llm_url=%s llm_key=%s llm_model=%s llm_style=%d",
            g_llmUrl[0] ? g_llmUrl : "<empty>",
            g_llmKey[0] ? "<set>" : "<empty>",
            g_llmModel[0] ? g_llmModel : "<auto>", g_llmStyle);

    if (g_optVip) PatchVip(GetModuleHandleA("项目L_AuthReal.dll"));
    if (g_optNoCloud) PatchNoCloud();

    /* ---- 优先启动内嵌大模型网关 ---- */
    if (g_optBridge && g_llmUrl[0]) {
        BridgeConfig bc;
        int port;
        BuildBridgeCfg(&bc);
        port = BridgeStart(&bc);
        if (port > 0) {
            char local[64];
            sprintf(local, "http://127.0.0.1:%d", port);
            if (PatchTranslateEndpoint(local)) {
                g_bridgeOn = 1;
                HookLog("bridge: {API_ENDPOINT} -> %s (自定义大模型已接管)", local);
            }
        } else {
            HookLog("bridge: 启动失败, 回退到 endpoint=%s", g_endpoint);
            if (g_optRedirect) PatchTranslateEndpoint(g_endpoint);
        }
    } else if (g_optRedirect) {
        PatchTranslateEndpoint(g_endpoint);
    }

    InitQt();
    if (g_optUi >= 1)  InstallHooks();
    HookLog("=== init done ===");
    return 0;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE h;
        DisableThreadLibraryCalls(hModule);
        GetModuleFileNameA(hModule, g_iniPath, MAX_PATH);
        { char* p = strrchr(g_iniPath, '\\'); if (p) *(p + 1) = 0; }
        strcat(g_iniPath, "项目L_hook.ini");

        ConfigLoad();
        if (g_optRedirect) PatchTranslateEndpoint(g_endpoint);   // 纯内存写, 加载器锁内安全

        h = CreateThread(NULL, 0, InitThread, NULL, 0, NULL);
        if (h) CloseHandle(h);
    }
    return TRUE;
}
