/*
 * erc++ - x64dbg plugin
 * SearchMemory / SearchModules with ASLR, SafeSEH, DEP, Rebase filters
 *
 * Build (x64):
 *   cl /EHsc /W3 /O2 /LD /DWIN32 /D_WINDOWS /D_USRDLL /DUNICODE /D_UNICODE
 *      erc_plus.cpp /Fe:erc_plus.dp64 /link /DEF:erc_plus.def
 *      pluginsdk\x64dbg.lib pluginsdk\x64bridge.lib
 *
 * Build (x86):
 *   cl /EHsc /W3 /O2 /LD /DWIN32 /D_WINDOWS /D_USRDLL /DUNICODE /D_UNICODE
 *      erc_plus.cpp /Fe:erc_plus.dp32 /link /DEF:erc_plus.def
 *      pluginsdk\x32dbg.lib pluginsdk\x32bridge.lib
 *
 * Invocation (commas separate arguments, per x64dbg docs):
 *   erc++ -SearchMemory, "jmp esp"
 *   erc++ -SearchMemory, "FF E4", -ASLR
 *   erc++ -SearchMemory, "FF E4", -ASLR, -DEP
 *   erc++ -SearchModules, "jmp esp", -Modules, "kernel32.dll,user32.dll"
 *   erc++ -SearchModules, "FF E4", -Modules, ntdll.dll, -ASLR, -SafeSEH
 */

#include "pluginsdk/_plugins.h"
#include "pluginsdk/_scriptapi_module.h"
#include "pluginsdk/_scriptapi_memory.h"
#include "pluginsdk/_scriptapi_misc.h"

#include <windows.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <unordered_map>

#pragma comment(lib, "psapi.lib")

// ─── plugin metadata ────────────────────────────────────────────────────────
#define PLUGIN_NAME    "erc++"
#define PLUGIN_VERSION 1
static int g_pluginHandle = 0;

// ─── helpers ────────────────────────────────────────────────────────────────
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}
static std::string toUpper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    return s;
}

static void log(const std::string& msg) {
    _plugin_logprintf("[erc++] %s\n", msg.c_str());
}
static void logOk(const std::string& msg) {
    _plugin_logprintf("[erc++] \033[92m%s\033[0m\n", msg.c_str());   // green
}
static void logErr(const std::string& msg) {
    _plugin_logprintf("[erc++] \033[91mError: %s\033[0m\n", msg.c_str()); // red
}

// ─── instruction → opcode map (x86/x64 common gadgets) ─────────────────────
static const std::unordered_map<std::string, std::vector<uint8_t>> INSN_MAP = {
    // JMP reg
    {"jmp esp",  {0xFF, 0xE4}},
    {"jmp eax",  {0xFF, 0xE0}},
    {"jmp ebx",  {0xFF, 0xE3}},
    {"jmp ecx",  {0xFF, 0xE1}},
    {"jmp edx",  {0xFF, 0xE2}},
    {"jmp esi",  {0xFF, 0xE6}},
    {"jmp edi",  {0xFF, 0xE7}},
    {"jmp ebp",  {0xFF, 0xE5}},
    // JMP reg (x64)
    {"jmp rsp",  {0xFF, 0xE4}},
    {"jmp rax",  {0xFF, 0xE0}},
    {"jmp rbx",  {0xFF, 0xE3}},
    {"jmp rcx",  {0xFF, 0xE1}},
    {"jmp rdx",  {0xFF, 0xE2}},
    {"jmp rsi",  {0xFF, 0xE6}},
    {"jmp rdi",  {0xFF, 0xE7}},
    {"jmp rbp",  {0xFF, 0xE5}},
    // CALL reg
    {"call esp", {0xFF, 0xD4}},
    {"call eax", {0xFF, 0xD0}},
    {"call ebx", {0xFF, 0xD3}},
    {"call ecx", {0xFF, 0xD1}},
    {"call edx", {0xFF, 0xD2}},
    {"call esi", {0xFF, 0xD6}},
    {"call edi", {0xFF, 0xD7}},
    {"call rsp", {0xFF, 0xD4}},
    {"call rax", {0xFF, 0xD0}},
    // PUSH reg / RET
    {"push esp", {0x54}},
    {"push eax", {0x50}},
    {"pop eax",  {0x58}},
    {"pop ebx",  {0x5B}},
    {"pop ecx",  {0x59}},
    {"pop edx",  {0x5A}},
    {"pop esi",  {0x5E}},
    {"pop edi",  {0x5F}},
    {"pop ebp",  {0x5D}},
    {"ret",      {0xC3}},
    {"nop",      {0x90}},
};

// ─── Almacén del último patrón generado para --Pattern o ────────────────────
static std::string g_lastPattern;
static int         g_lastPatternSize = 0;

// ─── wildcard-aware pattern byte ────────────────────────────────────────────
// wildcard=true means "match any byte at this position" (like ?? in OllyDbg)
struct PatternByte {
    uint8_t value    = 0;
    bool    wildcard = false;
};

// ─── Genera un patrón cíclico único (estilo Metasploit/ERC) ─────────────────
static std::string generatePattern(int size) {
    const char sets[3][40] = {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789"
    };
    std::string out;
    out.reserve(size);
    for (int i = 0; i < size; ++i) {
        out += sets[0][(i / (26 * 10)) % 26];
        out += sets[1][(i / 10) % 26];
        out += sets[2][i % 10];
    }
    out.resize(size); // recorta al tamaño exacto si no es múltiplo de 3
    return out;
}

// ─── Convierte un valor hex (p.ej. 0xAABBCCDD) a string de bytes little-endian
static bool hexValueToLeString(const std::string& rawHex, std::string& out) {
    std::string clean;
    for (size_t i = 0; i < rawHex.size(); ++i) {
        char c = rawHex[i];
        if (c == ' ' || c == '\t') continue;
        // Saltar prefijo \x
        if (c == '\\' && i+1 < rawHex.size() &&
            (rawHex[i+1] == 'x' || rawHex[i+1] == 'X')) { ++i; continue; }
        // Saltar prefijo 0x  (mirando el SIGUIENTE carácter, no clean.back())
        if (c == '0' && i+1 < rawHex.size() &&
            (rawHex[i+1] == 'x' || rawHex[i+1] == 'X')) { ++i; continue; }
        if (!isxdigit((unsigned char)c)) return false;
        clean += c;
    }
    if (clean.empty() || clean.size() % 2 != 0) return false;
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < clean.size(); i += 2)
        bytes.push_back((uint8_t)std::stoul(clean.substr(i, 2), nullptr, 16));
    std::reverse(bytes.begin(), bytes.end());   // little-endian
    out.assign(bytes.begin(), bytes.end());
    return !out.empty();
}

// ─── Resuelve el valor de --Pattern o a un needle para buscar en el patrón ──
// Modo hex:   0x...  |  \x..\x..  |  hex pelado con longitud par
// Modo ASCII: cualquier otra cosa se busca literalmente en el patrón
// Si ASCII no encuentra match, se reintenta como hex.
static bool resolveOffsetValue(const std::string& raw,
                               const std::string& pattern,
                               std::string& needle,
                               std::string& display)
{
    auto toHexDisplay = [](const std::string& s) {
        std::string d;
        for (unsigned char c : s) { char b[8]; sprintf_s(b, "\\x%02X", c); d += b; }
        return d;
    };

    // 1) Prefijo hex explícito → forzar modo hex
    bool explicitHex = false;
    if (raw.size() >= 2 &&
        (raw[0] == '0' || raw[0] == '\\') &&
        (raw[1] == 'x' || raw[1] == 'X'))
        explicitHex = true;

    if (explicitHex) {
        if (!hexValueToLeString(raw, needle)) return false;
        display = toHexDisplay(needle);
        return true;
    }

    // 2) Sin prefijo → intentar ASCII literal primero
    if (pattern.find(raw) != std::string::npos) {
        needle  = raw;
        display = raw + "  (ASCII)";
        return true;
    }

    // 3) Fallback a hex (útil si pegas "41306141" sin 0x)
    if (hexValueToLeString(raw, needle)) {
        display = toHexDisplay(needle) + "  (hex)";
        return true;
    }

    return false;
}

// ─── Comando --Pattern (c = crear, o = offset) ─────────────────────────────
static void doPatternCommand(const std::vector<std::string>& tokens) {
    // tokens[0] = "c" u "o"
    std::string mode = toLower(tokens[0]);

    if (mode == "c") {
        if (tokens.size() < 2) {
            logErr("Uso: erc++ --Pattern, c, <tamaño>");
            return;
        }
        int size = 0;
        try { size = std::stoi(tokens[1]); } catch (...) {
            logErr("Tamaño inválido. Debe ser un entero positivo.");
            return;
        }
        if (size <= 0 || size > 1000000) {
            logErr("Tamaño fuera de rango (1..1000000).");
            return;
        }

        std::string pattern = generatePattern(size);
        g_lastPattern = pattern;
        g_lastPatternSize = size;

        _plugin_logprintf("[erc++] Pattern creado (%d bytes):\n", size);

        // Salida ASCII
        _plugin_logprintf("[erc++] ASCII:\n%s\n", pattern.c_str());

        // Salida hexadecimal \x..
        std::string hexOut;
        hexOut.reserve(pattern.size() * 4);
        for (unsigned char c : pattern) {
            char buf[8];
            sprintf_s(buf, "\\x%02X", c);
            hexOut += buf;
        }
        _plugin_logprintf("[erc++] HEX:\n%s\n", hexOut.c_str());

        logOk("Pattern almacenado. Usa 'erc++ --Pattern, o, 0xXXXXXXXX' para buscar un offset.");
        return;
    }

    if (mode == "o") {
        if (tokens.size() < 2) {
            logErr("Uso: erc++ --Pattern, o, <0xVALOR | CADENA_ASCII>");
            return;
        }
        if (g_lastPattern.empty()) {
            logErr("No hay patrón en memoria. Ejecuta primero 'erc++ --Pattern, c, <tamaño>'.");
            return;
        }

        std::string needle, display;
        if (!resolveOffsetValue(tokens[1], g_lastPattern, needle, display)) {
            logErr("Valor inválido: " + tokens[1]);
            return;
        }

        size_t pos = g_lastPattern.find(needle);
        if (pos == std::string::npos) {
            logErr("Offset no encontrado para " + tokens[1] +
                   " (interpretado como: " + display + ")");
            return;
        }

        _plugin_logprintf("[erc++] Valor: %s\n", tokens[1].c_str());
        _plugin_logprintf("[erc++] Interpretado: %s\n", display.c_str());
        _plugin_logprintf("[erc++] Offset encontrado en la posición: %zu (0x%zX)\n",
                          pos, pos);
        return;
    }

    logErr("Subcomando desconocido '" + tokens[0] + "'. Usa 'c' o 'o'.");
}

// ─── hex string → bytes ─────────────────────────────────────────────────────
static bool hexToBytes(const std::string& hex, std::vector<uint8_t>& out) {
    std::string clean;
    for (size_t i = 0; i < hex.size(); ++i) {
        char c = hex[i];
        if (c == ' ' || c == '\t') continue;
        // Skip \x prefix
        if (c == '\\' && i+1 < hex.size() && (hex[i+1] == 'x' || hex[i+1] == 'X')) {
            i++; continue;
        }
        // Skip 0x prefix (only when it IS a prefix, i.e. followed by a hex digit)
        if (c == '0' && i+1 < hex.size() && (hex[i+1] == 'x' || hex[i+1] == 'X')) {
            i++; continue;
        }
        if (!isxdigit((unsigned char)c)) return false;
        clean += c;
    }
    if (clean.empty() || clean.size() % 2 != 0) return false;
    for (size_t i = 0; i < clean.size(); i += 2) {
        uint8_t b = (uint8_t)std::stoul(clean.substr(i, 2), nullptr, 16);
        out.push_back(b);
    }
    return !out.empty();
}

// Añade esta función en tu código, por ejemplo, antes de doSearch
static std::string getPagePermissions(duint address) {
    // Obtiene el handle del proceso que se está depurando
    HANDLE hProcess = DbgGetProcessHandle();
    if (!hProcess) return "???";

    MEMORY_BASIC_INFORMATION mbi;
    // Consulta la información de la página de memoria en la dirección dada
    if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
        return "???"; // No se pudo obtener la información
    }

    // Si la región no está comprometida (reservada o libre), no tiene permisos de acceso
    if (mbi.State != MEM_COMMIT) {
        return "---";
    }

    std::string perms = "---";
    DWORD prot = mbi.Protect;

    // Mapea las constantes de protección de Windows a las letras R, W, X
    if (prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | 
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        perms[0] = 'R';
    }
    if (prot & (PAGE_READWRITE | PAGE_WRITECOPY | 
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        perms[1] = 'W';
    }
    if (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        perms[2] = 'X';
    }

    return perms;
}

// ─── resolve pattern: single mnemonic, gadget, or hex (wildcard-aware) ──────
//
// Wildcards:
//   In hex mode  → "??" token matches any single byte:
//                   "FF ?? C3"  →  [{FF,exact}, {00,wild}, {C3,exact}]
//   In gadget mode → "pop ?" or "pop *" matches any single pop-reg byte (0x58-0x5F):
//                   "pop ?; pop ?; ret"  →  [{wild}, {wild}, {C3,exact}]
//
static bool resolvePattern(const std::string& raw, std::vector<PatternByte>& out) {
    std::string lo = toLower(raw);

    // Helper: append an exact byte
    auto pushExact = [&](uint8_t b) {
        out.push_back({b, false});
    };
    // Helper: append a wildcard byte
    auto pushWild = [&]() {
        out.push_back({0x00, true});
    };

    // 1) Direct single-mnemonic match (no wildcards possible here)
    {
        auto it = INSN_MAP.find(lo);
        if (it != INSN_MAP.end()) {
            for (uint8_t b : it->second) pushExact(b);
            return true;
        }
    }

    // 2) Multi-instruction gadget: "pop ?; pop ?; ret" / "push esp; ret" / "push esp + ret"
    //    Separators: ';' or '+'.  "pop ?" and "pop *" act as single-byte wildcards.
    {
        std::string s = raw;
        std::replace(s.begin(), s.end(), '+', ';');

        if (s.find(';') != std::string::npos) {
            std::vector<PatternByte> combined;
            bool ok = true;
            std::istringstream iss(s);
            std::string part;
            while (std::getline(iss, part, ';')) {
                size_t a = part.find_first_not_of(" \t");
                size_t b = part.find_last_not_of(" \t");
                if (a == std::string::npos) continue;   // skip empty segment
                part = part.substr(a, b - a + 1);
                std::string partLo = toLower(part);

                // "pop ?" / "pop *"  →  wildcard byte (pop reg = 1 byte, 0x58-0x5F)
                if (partLo == "pop ?" || partLo == "pop *") {
                    combined.push_back({0x00, true});
                    continue;
                }

                auto pit = INSN_MAP.find(partLo);
                if (pit == INSN_MAP.end()) { ok = false; break; }
                for (uint8_t byte : pit->second)
                    combined.push_back({byte, false});
            }
            if (ok && !combined.empty()) {
                out = combined;
                return true;
            }
        }
    }

    // 3) Hex fallback with ?? wildcard support:
    //    Tokens separated by whitespace; each token is either two hex digits or "??"
    {
        // Only enter hex mode if the string looks like hex/wildcard tokens,
        // i.e. every non-space token is two hex chars OR "??"
        std::istringstream iss(raw);
        std::string token;
        std::vector<PatternByte> hexOut;
        bool looksHex = false;
        bool valid    = true;

        while (iss >> token) {
            looksHex = true;   // at least one token found

            // Strip a leading 0x or \x on a token if present
            if (token.size() >= 2 && token[0] == '\\' &&
                (token[1] == 'x' || token[1] == 'X'))
                token = token.substr(2);
            else if (token.size() >= 2 && token[0] == '0' &&
                     (token[1] == 'x' || token[1] == 'X'))
                token = token.substr(2);

            if (token == "??" || token == "?") {
                hexOut.push_back({0x00, true});
            } else if (token.size() == 2 &&
                       isxdigit((unsigned char)token[0]) &&
                       isxdigit((unsigned char)token[1])) {
                uint8_t b = (uint8_t)std::stoul(token, nullptr, 16);
                hexOut.push_back({b, false});
            } else {
                // Not a valid two-char hex or wildcard → not hex mode
                valid = false;
                break;
            }
        }

        if (looksHex && valid && !hexOut.empty()) {
            out = hexOut;
            return true;
        }
    }

    // 4) Bare hex string (no spaces): "FFE4C3" or "\xFF\xE4\xC3" etc.
    //    No wildcard support in this form (no spaces to separate tokens).
    {
        std::vector<uint8_t> raw8;
        if (hexToBytes(raw, raw8)) {
            for (uint8_t b : raw8) pushExact(b);
            return true;
        }
    }

    logErr("Unknown pattern '" + raw + "'. "
           "Use hex (FF E4 | FF ?? C3), a mnemonic (jmp esp), "
           "or a gadget ('pop ?; pop ?; ret').");
    return false;
}

// ─── PE flags from a module ──────────────────────────────────────────────────
struct ModuleFlags {
    bool aslr     = false;
    bool safeseh  = false;
    bool dep      = false;   // NXCompat
    bool rebase   = false;
};

// IMAGE_DLLCHARACTERISTICS_* values
#define DLLCHAR_DYNAMIC_BASE 0x0040   // ASLR
#define DLLCHAR_NX_COMPAT    0x0100   // DEP/NXCompat
#define DLLCHAR_NO_SEH       0x0400   // handler table present ↔ SafeSEH

static ModuleFlags getModuleFlags(const std::string& modPath) {
    ModuleFlags f;
    HMODULE hMod = LoadLibraryExA(modPath.c_str(), NULL,
        LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!hMod) return f;

    auto base = reinterpret_cast<BYTE*>(hMod);
    // Strip LOAD_LIBRARY_AS_DATAFILE flag bit
    base = reinterpret_cast<BYTE*>((ULONG_PTR)base & ~(ULONG_PTR)3);

    __try {
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) { FreeLibrary(hMod); return f; }
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) { FreeLibrary(hMod); return f; }

        WORD ch = nt->OptionalHeader.DllCharacteristics;
        f.aslr    = (ch & DLLCHAR_DYNAMIC_BASE) != 0;
        f.dep     = (ch & DLLCHAR_NX_COMPAT)    != 0;

        // SafeSEH: check for SE handler table in Load Config directory
        if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) {
            auto& lcDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
            if (lcDir.VirtualAddress && lcDir.Size) {
#ifdef _WIN64
                auto lc = reinterpret_cast<IMAGE_LOAD_CONFIG_DIRECTORY64*>(
                    base + lcDir.VirtualAddress);
                f.safeseh = (lc->SEHandlerCount > 0);
#else
                auto lc = reinterpret_cast<IMAGE_LOAD_CONFIG_DIRECTORY32*>(
                    base + lcDir.VirtualAddress);
                f.safeseh = (lc->SEHandlerCount > 0);
#endif
            }
        }

        // Rebase: same as ASLR flag
        f.rebase = f.aslr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    FreeLibrary(hMod);
    return f;
}



// ─── search bytes in a memory buffer ────────────────────────────────────────
static std::vector<duint> searchInBuffer(
    const uint8_t* buf, size_t bufLen, duint baseAddr,
    const std::vector<PatternByte>& pattern)
{
    std::vector<duint> hits;
    if (pattern.empty() || bufLen < pattern.size()) return hits;

    for (size_t i = 0; i <= bufLen - pattern.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (!pattern[j].wildcard && buf[i + j] != pattern[j].value) {
                match = false;
                break;
            }
        }
        if (match)
            hits.push_back(baseAddr + (duint)i);
    }
    return hits;
}

// ─── get all loaded modules from the debuggee ────────────────────────────────
struct ModInfo {
    duint      base;
    duint      size;
    std::string name;   // just filename, lowercase
    std::string path;   // full path
};

static std::vector<ModInfo> getLoadedModules() {
    std::vector<ModInfo> mods;

    BridgeList<Script::Module::ModuleInfo> list;
    if (!Script::Module::GetList(&list))
        return mods;

    int count = list.Count();
    Script::Module::ModuleInfo* data = list.Data();
    for (int i = 0; i < count; ++i) {
        ModInfo info;
        info.base = data[i].base;
        info.size = data[i].size;
        info.path = data[i].path;
        std::string p(data[i].path);
        size_t sl = p.find_last_of("\\/ ");
        info.name = toLower(sl == std::string::npos ? p : p.substr(sl + 1));
        mods.push_back(info);
    }
    return mods;
}

// ─── print banner ────────────────────────────────────────────────────────────
static void printBanner() {
    _plugin_logprintf(
        "  ___  ____   ___   __    _\n"
        " / _ \\|  _ \\ / __| /  \\  | |\n"
        "| |_| | |_) | |__ | /\\ | | |\n"
        " \\___/|____/ \\___||_||_| |_|\n"
        "                  ++ v%d\n"
        "------------------------------------\n",
        PLUGIN_VERSION);
}

// ─── print usage ─────────────────────────────────────────────────────────────
static void printHelp() {
    printBanner();
    _plugin_logprintf(
        "Commands are CASE-INSENSITIVE. Arguments are separated by COMMAS.\n\n"

        "  erc++ -SearchMemory, <pattern>[, <flag>...]\n"
        "    Search all process memory for a byte pattern or mnemonic.\n"
        "    Filters (exclude modules that have this feature):\n"
        "      -ASLR     exclude ASLR-enabled modules\n"
        "      -SafeSEH  exclude SafeSEH-enabled modules\n"
        "      -DEP      exclude DEP/NXCompat-enabled modules\n"
        "      -Rebase   exclude Rebase-enabled modules\n\n"

        "  erc++ -SearchModules, <pattern>, -Modules, <list>[, <flag>...]\n"
        "    Same as SearchMemory but restricted to specific modules.\n"
        "    <list> is a comma-separated module list, e.g. \"kernel32.dll,user32.dll\"\n\n"

        "  erc++ -Pattern, c, <length>\n"
        "    Genera un patrón cíclico único (ASCII + hex \\x..).\n"
        "    Guarda el patrón para el comando 'o'.\n\n"

        "  erc++ -Pattern, o, <valor>\n"
        "    Busca <valor> en el último patrón generado y muestra su offset.\n"
        "    Formato hex  : 0x41306141  |  \\x41\\x61\\x30\\x41  |  41306141\n"
        "    Formato ASCII: Aa0A   (los caracteres visibles en el patrón)\n\n"

        "  erc++ -help\n"
        "    Show this message.\n\n"

        "Patterns:\n"
        "  Hex bytes     : FF E4  |  FFE4  |  \\xFF\\xE4  |  0xFF 0xE4\n"
        "  Wildcards     : FF ?? C3  |  ?? ?? C3   (?? = any byte)\n"
        "  Mnemonics     : jmp esp, call eax, pop ebx, ret, nop ...\n"
        "  Gadgets       : \"push esp; ret\"  |  \"jmp esp; ret\"\n"
        "                  (separator: ';' or '+', always quoted)\n"
        "  Wildcard regs : \"pop ?; pop ?; ret\"  (pop ? = any pop-reg byte)\n"
        "                  \"pop *; pop *; ret\"  (same, alternate syntax)\n\n"

        "Examples:\n"
        "  erc++ -Pattern, c, 1000\n"
        "  erc++ -Pattern, o, 0xAABBCCDD\n"
        "  erc++ -Pattern, o, Aa0A\n"
        "  erc++ -SearchMemory, \"jmp esp\"\n"
        "  erc++ -SearchMemory, \"FF E4\", -ASLR\n"
        "  erc++ -SearchMemory, \"FF E4\", -ASLR, -DEP\n"
        "  erc++ -SearchModules, \"jmp esp\", -Modules, \"kernel32.dll,user32.dll\"\n"
        "  erc++ -SearchModules, \"FF E4\", -Modules, ntdll.dll, -ASLR, -SafeSEH\n"
        "  erc++ -SearchMemory, \"push esp; ret\"\n"
        "  erc++ -SearchMemory, \"push esp; ret\", -ASLR\n"
        "  erc++ -SearchMemory, \"54 C3\"\n"
        "  erc++ -SearchMemory, \"FF ?? C3\"\n"
        "  erc++ -SearchMemory, \"pop ?; pop ?; ret\"\n"
        "  erc++ -SearchMemory, \"pop ?; pop ?; ret\", -ASLR\n"
    );
}

// ─── arg parser ──────────────────────────────────────────────────────────────
struct SearchArgs {
    std::string        pattern;
    bool               filterASLR    = false;
    bool               filterSafeSEH = false;
    bool               filterDEP     = false;
    bool               filterRebase  = false;
    std::vector<std::string> modules; // empty = all
    bool               valid         = false;
};

// Parse from argv[] (already comma-separated by x64dbg).
// Non-flag tokens preceding the first flag are joined into the pattern.
// -Modules collects subsequent tokens until the next flag (comma-joined),
// so both "kernel32.dll,user32.dll" (one token) and kernel32.dll,user32.dll
// (multiple tokens) work.
static SearchArgs parseArgv(int argc, char* argv[], int start) {
    SearchArgs sa;
    if (start >= argc) return sa;

    std::string pat;
    int i = start;
    for (; i < argc; ++i) {
        std::string tok(argv[i]);
        if (!tok.empty() && tok[0] == '-') break;
        if (!pat.empty()) pat += ' ';
        pat += tok;
    }

    if (pat.empty()) {
        logErr("No pattern specified after command.");
        return sa;
    }
    sa.pattern = pat;

    for (; i < argc; ++i) {
        std::string lo = toLower(std::string(argv[i]));
        if      (lo == "-aslr")    sa.filterASLR    = true;
        else if (lo == "-safeseh") sa.filterSafeSEH = true;
        else if (lo == "-dep")     sa.filterDEP     = true;
        else if (lo == "-rebase")  sa.filterRebase  = true;
        else if (lo == "-modules") {
            std::string modList;
            ++i;
            for (; i < argc; ++i) {
                std::string m(argv[i]);
                if (!m.empty() && m[0] == '-') { --i; break; }
                if (!modList.empty()) modList += ',';
                modList += m;
            }
            if (modList.empty()) {
                logErr("-Modules requires a comma-separated list of module names.");
                return sa;
            }
            std::istringstream mss(modList);
            std::string m;
            while (std::getline(mss, m, ','))
                if (!m.empty()) sa.modules.push_back(toLower(m));
        } else {
            logErr("Unknown flag '" + std::string(argv[i]) + "'. Try erc++ -help.");
            return sa;
        }
    }
    sa.valid = true;
    return sa;
}

// ─── format address ──────────────────────────────────────────────────────────
static std::string fmtAddr(duint addr) {
#ifdef _WIN64
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << std::setw(16) << std::setfill('0') << addr;
    return ss.str();
#else
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << addr;
    return ss.str();
#endif
}

// ─── core search ─────────────────────────────────────────────────────────────
static void doSearch(const SearchArgs& sa, bool modulesOnly) {
    std::vector<PatternByte> pat;
    if (!resolvePattern(sa.pattern, pat)) return;

    std::string patHex;
    for (auto& pb : pat) {
        if (pb.wildcard) {
            patHex += "?? ";
        } else {
            char buf[4]; sprintf_s(buf, "%02X ", pb.value);
            patHex += buf;
        }
    }

    std::string filterDesc;
    if (sa.filterASLR)    filterDesc += " -ASLR";
    if (sa.filterSafeSEH) filterDesc += " -SafeSEH";
    if (sa.filterDEP)     filterDesc += " -DEP";
    if (sa.filterRebase)  filterDesc += " -Rebase";
    if (filterDesc.empty()) filterDesc = " (no filters)";

    _plugin_logprintf("[erc++] Searching for: %s [%s]%s\n",
        sa.pattern.c_str(), patHex.c_str(), filterDesc.c_str());

    auto mods = getLoadedModules();
    if (mods.empty()) { logErr("Could not enumerate process modules. Is a process attached?"); return; }

    int totalHits = 0;
    int skipped   = 0;

    for (auto& mod : mods) {
        if (!sa.modules.empty()) {
            bool found = false;
            for (auto& wantedMod : sa.modules)
                if (mod.name == wantedMod || mod.path.find(wantedMod) != std::string::npos)
                    { found = true; break; }
            if (!found) continue;
        }

        ModuleFlags flags = getModuleFlags(mod.path);

        if (sa.filterASLR    && flags.aslr)    { ++skipped; continue; }
        if (sa.filterSafeSEH && flags.safeseh) { ++skipped; continue; }
        if (sa.filterDEP     && flags.dep)     { ++skipped; continue; }
        if (sa.filterRebase  && flags.rebase)  { ++skipped; continue; }

        std::vector<uint8_t> buf(mod.size);
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(DbgGetProcessHandle(),
                               reinterpret_cast<LPCVOID>(mod.base),
                               buf.data(), mod.size, &bytesRead) || bytesRead == 0)
            continue;

        auto hits = searchInBuffer(buf.data(), bytesRead, mod.base, pat);
        if (!hits.empty()) {
            _plugin_logprintf("[erc++] ── %s ──\n", mod.name.c_str());
            _plugin_logprintf("[erc++]    ASLR:%-4s SafeSEH:%-4s DEP:%-4s Rebase:%-4s\n",
                flags.aslr?"yes":"no", flags.safeseh?"yes":"no",
                flags.dep?"yes":"no",  flags.rebase?"yes":"no");
            for (duint a : hits) {
    	    	// Obtiene los permisos de la página para esta dirección específica
    		std::string perms = getPagePermissions(a);
    
    		_plugin_logprintf("[erc++]    %s  %s  [%s]\n",
       			fmtAddr(a).c_str(), mod.name.c_str(), perms.c_str());
    		++totalHits;
	    }
        }
    }

    _plugin_logprintf("[erc++] ────────────────────────────────\n");
    _plugin_logprintf("[erc++] Found %d result(s)  |  %d module(s) skipped by filters\n",
        totalHits, skipped);
}

// ─── comma-aware tokenizer (quote-aware, trims whitespace per token) ─────────
// Fallback for x64dbg versions that still deliver the whole tail as argv[1].
static std::vector<std::string> splitByCommas(const std::string& s) {
    std::vector<std::string> tokens;
    std::string cur;
    char quote = 0;
    for (char c : s) {
        if (quote) {
            if (c == quote) quote = 0;
            else            cur += c;
        } else if (c == '"' || c == '\'') {
            quote = c;
        } else if (c == ',') {
            size_t a = cur.find_first_not_of(" \t");
            size_t b = cur.find_last_not_of(" \t");
            if (a != std::string::npos)
                tokens.push_back(cur.substr(a, b - a + 1));
            cur.clear();
        } else {
            cur += c;
        }
    }
    size_t a = cur.find_first_not_of(" \t");
    size_t b = cur.find_last_not_of(" \t");
    if (a != std::string::npos)
        tokens.push_back(cur.substr(a, b - a + 1));
    return tokens;
}

// ─── command handler ──────────────────────────────────────────────────────────
static bool cbCommand(int argc, char* argv[]) {
    if (argc < 2) { printHelp(); return true; }

    // x64dbg splits arguments by commas → each argv entry is one logical token.
    // Some builds instead pass the whole tail as argv[1]; split it ourselves then.
    std::vector<std::string> tokens;
    if (argc == 2) {
        tokens = splitByCommas(argv[1]);
    } else {
        for (int i = 1; i < argc; ++i) {
            std::string t(argv[i]);
            size_t a = t.find_first_not_of(" \t");
            size_t b = t.find_last_not_of(" \t");
            if (a != std::string::npos)
                tokens.push_back(t.substr(a, b - a + 1));
        }
    }
    if (tokens.empty()) { printHelp(); return true; }

    std::string subcmd = toLower(tokens[0]);

    if (subcmd == "-help" || subcmd == "--help" || subcmd == "help") {
        printHelp();
        return true;
    }

    if (subcmd == "-searchmemory" || subcmd == "-searchmodules") {
        bool modulesOnly = (subcmd == "-searchmodules");

        if (tokens.size() < 2) {
            logErr("No pattern specified. Usage: erc++ " +
                   std::string(modulesOnly ? "-SearchModules" : "-SearchMemory") +
                   ", \"<pattern>\"[, -Modules, \"a.dll,b.dll\"][, flags]");
            return true;
        }

        std::vector<const char*> targv;
        for (size_t i = 1; i < tokens.size(); ++i)
            targv.push_back(tokens[i].c_str());

        SearchArgs sa = parseArgv((int)targv.size(), (char**)targv.data(), 0);
        if (!sa.valid) return true;

        if (modulesOnly && sa.modules.empty()) {
            logErr("-SearchModules requires -Modules \"mod1.dll,mod2.dll,...\"");
            return true;
        }

        doSearch(sa, modulesOnly);
        return true;
    }

    // ── --Pattern ──────────────────────────────────────────────────────────
    if (subcmd == "--pattern" || subcmd == "-pattern") {
        if (tokens.size() < 2) {
            logErr("Uso: erc++ --Pattern, c, <tamaño>  |  erc++ --Pattern, o, <hex>");
            return true;
        }
        doPatternCommand(std::vector<std::string>(tokens.begin() + 1, tokens.end()));
        return true;
    }

    logErr("Unknown command '" + tokens[0] + "'. Try: erc++ -help");
    return true;
}

// ─── plugin entry points (required by x64dbg) ────────────────────────────────
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct) {
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion    = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
    g_pluginHandle = initStruct->pluginHandle;
    return true;
}

extern "C" __declspec(dllexport) void plugstop() {}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    _plugin_registercommand(g_pluginHandle, "erc++", cbCommand, false);
    log("loaded. Type 'erc++ -help' to get started.");
}
