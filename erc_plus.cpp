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
 */

#include "pluginsdk/_plugins.h"
#include "pluginsdk/_scriptapi_module.h"
#include "pluginsdk/_scriptapi_memory.h"
#include "pluginsdk/_scriptapi_misc.h"
#include "pluginsdk/bridgemain.h"

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
    _plugin_logprintf("[erc++] \033[92m%s\033[0m\n", msg.c_str());
}
static void logErr(const std::string& msg) {
    _plugin_logprintf("[erc++] \033[91mError: %s\033[0m\n", msg.c_str());
}

// ─── instruction → opcode map ────────────────────────────────────────────────
static const std::unordered_map<std::string, std::vector<uint8_t>> INSN_MAP = {
    {"jmp esp",  {0xFF, 0xE4}},
    {"jmp eax",  {0xFF, 0xE0}},
    {"jmp ebx",  {0xFF, 0xE3}},
    {"jmp ecx",  {0xFF, 0xE1}},
    {"jmp edx",  {0xFF, 0xE2}},
    {"jmp esi",  {0xFF, 0xE6}},
    {"jmp edi",  {0xFF, 0xE7}},
    {"jmp ebp",  {0xFF, 0xE5}},
    {"jmp rsp",  {0xFF, 0xE4}},
    {"jmp rax",  {0xFF, 0xE0}},
    {"jmp rbx",  {0xFF, 0xE3}},
    {"jmp rcx",  {0xFF, 0xE1}},
    {"jmp rdx",  {0xFF, 0xE2}},
    {"jmp rsi",  {0xFF, 0xE6}},
    {"jmp rdi",  {0xFF, 0xE7}},
    {"jmp rbp",  {0xFF, 0xE5}},
    {"call esp", {0xFF, 0xD4}},
    {"call eax", {0xFF, 0xD0}},
    {"call ebx", {0xFF, 0xD3}},
    {"call ecx", {0xFF, 0xD1}},
    {"call edx", {0xFF, 0xD2}},
    {"call esi", {0xFF, 0xD6}},
    {"call edi", {0xFF, 0xD7}},
    {"call rsp", {0xFF, 0xD4}},
    {"call rax", {0xFF, 0xD0}},
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

// ─── cyclic pattern ──────────────────────────────────────────────────────────
static std::string g_lastPattern;
static int         g_lastPatternSize = 0;

struct SearchArgs {
    std::string              pattern;
    bool                     filterASLR    = false;
    bool                     filterSafeSEH = false;
    bool                     filterDEP     = false;
    bool                     filterRebase  = false;
    std::vector<std::string> modules;
    std::vector<uint8_t>     badChars;     // ← nuevo
    bool                     valid         = false;
    std::vector<std::string> permFilters;   // ← nuevo: "R--", "RW-", etc.
};

// ─── get loaded modules ───────────────────────────────────────────────────────
struct ModInfo {
    duint       base;
    duint       size;
    std::string name;
    std::string path;
};


// ─── Obtener un registro vía DbgValFromString ───────────────────────────────
static duint getRegisterValue(const char* regName) {
    // DbgValFromString evalúa una expresión del depurador y devuelve duint.
    // Acepta nombres de registro en minúsculas ("eax", "esp", "eip", …)
    // y también los alias architecture-independent ("cax", "csp", "cip", …).
    return DbgValFromString(regName);
}

// ─── findOffsetOfDword (sin cambios) ────────────────────────────────────────
static int findOffsetOfDword(duint dwordValue) {
    if (g_lastPattern.size() < 4) return -1;
    uint8_t b[4] = {
        (uint8_t)(dwordValue & 0xFF),
        (uint8_t)((dwordValue >> 8) & 0xFF),
        (uint8_t)((dwordValue >> 16) & 0xFF),
        (uint8_t)((dwordValue >> 24) & 0xFF)
    };
    for (size_t i = 0; i <= g_lastPattern.size() - 4; ++i)
        if ((uint8_t)g_lastPattern[i]     == b[0] &&
            (uint8_t)g_lastPattern[i + 1] == b[1] &&
            (uint8_t)g_lastPattern[i + 2] == b[2] &&
            (uint8_t)g_lastPattern[i + 3] == b[3])
            return (int)i;
    return -1;
}

// ★ NUEVO: devuelve qué offset del PATRÓN corresponde a la memoria en 'addr'
// (no "dónde empieza el patrón en el buffer", sino "qué trozo del patrón hay aquí")
static int findPatternOffsetAt(duint addr, size_t probe = 16) {
    if (g_lastPattern.size() < probe) return -1;
    std::vector<uint8_t> buf(probe);
    SIZE_T got = 0;
    if (!ReadProcessMemory(DbgGetProcessHandle(), (LPCVOID)addr,
                           buf.data(), probe, &got) || got < probe)
        return -1;
    for (size_t off = 0; off + probe <= g_lastPattern.size(); ++off)
        if (memcmp(buf.data(), g_lastPattern.data() + off, probe) == 0)
            return (int)off;
    return -1;
}

// ★ REESCRITA: clasifica el crash
static void doAnalyze(const std::vector<uint8_t>& badChars) {
    if (g_lastPattern.empty()) {
        logErr("No hay patrón. Ejecuta 'erc++ --Pattern, c, <tamaño>' primero.");
        return;
    }

    _plugin_logprintf("[erc++] === Crash Analysis (patrón %zu bytes) ===\n",
                      g_lastPattern.size());

    // ── 1) Volcar registros con su rol en el patrón ─────────────────────────
    const char* regs[] = {"EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP","EIP"};
    struct RegInfo { const char* name; duint val; int inOffset; int toOffset; };
    std::vector<RegInfo> info;

    for (auto rn : regs) {
        RegInfo ri{ rn, getRegisterValue(rn), -1, -1 };
        ri.inOffset = findOffsetOfDword(ri.val);       // contiene patrón?
        if (ri.inOffset < 0 && ri.val != 0)
            ri.toOffset = findPatternOffsetAt(ri.val); // apunta al patrón?
        info.push_back(ri);

        if (ri.inOffset >= 0)
            _plugin_logprintf("[erc++]   %s = 0x%p  contains pattern @ offset %d\n",
                              rn, (void*)ri.val, ri.inOffset);
        else if (ri.toOffset >= 0)
            _plugin_logprintf("[erc++]   %s = 0x%p  points to pattern @ offset %d\n",
                              rn, (void*)ri.val, ri.toOffset);
        else
            _plugin_logprintf("[erc++]   %s = 0x%p\n", rn, (void*)ri.val);
    }

    // ── 2) Localizar EIP y ESP en la tabla ──────────────────────────────────
    RegInfo* eip = nullptr;
    RegInfo* esp = nullptr;
    for (auto& r : info) {
        if (strcmp(r.name, "EIP") == 0) eip = &r;
        if (strcmp(r.name, "ESP") == 0) esp = &r;
    }

    // ── 3) ★ CLASIFICACIÓN ──────────────────────────────────────────────────
    _plugin_logprintf("[erc++] \n");

    int  eipOff = eip ? eip->inOffset  : -1;   // EIP contiene patrón
    int  espOff = esp ? esp->toOffset  : -1;   // ESP apunta al patrón
    std::string explType;

    if (eipOff >= 0) {
        // ── Caso A: EIP está directamente sobrescrito con patrón ───────────
        if (espOff >= 0 && espOff == eipOff + 4) {
            // Caso A1: ESP apunta exactamente al byte justo después de EIP
            explType = "direct ret overwrite (stack pivot to ESP)";
            _plugin_logprintf("[erc++] type of exploit: %s (offset %d)\n",
                              explType.c_str(), eipOff);
            _plugin_logprintf("[erc++] ESP @ offset %d  ==  EIP_off + 4  → 'jmp esp' viable\n",
                              espOff);
        }
        else if (espOff >= 0) {
            // Caso A2: EIP sobrescrito, pero ESP apunta a otra zona del patrón
            explType = "direct ret overwrite (frame offset mismatch)";
            _plugin_logprintf("[erc++] type of exploit: %s (offset %d)\n",
                              explType.c_str(), eipOff);
            _plugin_logprintf("[erc++] ESP @ offset %d  !=  EIP_off + 4 (%d)\n",
                              espOff, eipOff + 4);
        }
        else {
            // Caso A3: EIP sobrescrito pero ESP no apunta al patrón
            explType = "direct ret overwrite (EIP only)";
            _plugin_logprintf("[erc++] type of exploit: %s (offset %d)\n",
                              explType.c_str(), eipOff);

            // Buscar pivots alternativos
            for (auto& r : info) {
                if (strcmp(r.name, "ESP") == 0) continue;
                if (r.toOffset >= 0) {
                    _plugin_logprintf("[erc++]   pivot candidate: %s @ offset %d\n",
                                      r.name, r.toOffset);
                }
            }
        }
    }
    else {
        // ── Caso B: EIP NO es patrón → posible SEH overwrite ───────────────
        // En SEH, tras la excepción, [ESP] = nSEH y [ESP+4] = SEH handler
        int nsehOff = esp ? findPatternOffsetAt(esp->val)     : -1;
        int sehOff  = esp ? findPatternOffsetAt(esp->val + 4) : -1;

        if (nsehOff >= 0 || sehOff >= 0) {
            explType = "SEH overwrite";
            _plugin_logprintf("[erc++] type of exploit: %s (nSEH off %d, SEH off %d)\n",
                              explType.c_str(), nsehOff, sehOff);
        } else {
            explType = "unknown (EIP not pattern, SEH not pattern)";
            _plugin_logprintf("[erc++] type of exploit: %s\n", explType.c_str());
        }
    }

    // ── 4) ★ Esqueleto Python, ahora con el offset correcto ─────────────────
    if (eipOff >= 0) {
        std::string badchars = "b'";
        if (badChars.empty()) badchars += "\\x00\\x0A\\x0D\\x1A";
        else for (uint8_t b : badChars) {
            char t[8]; sprintf_s(t, "\\x%02X", b); badchars += t;
        }
        badchars += "'";

        _plugin_logprintf("[erc++] \n");
        _plugin_logprintf("[erc++] Suggested Python exploit skeleton:\n");
        _plugin_logprintf("[erc++] -------------------------------------------------\n");
        _plugin_logprintf("[erc++] #!/usr/bin/env python3\n");
        _plugin_logprintf("[erc++] from struct import pack\n");
        _plugin_logprintf("[erc++] \n");
        _plugin_logprintf("[erc++] badchars = %s\n", badchars.c_str());
        _plugin_logprintf("[erc++] offset   = %d            # EIP offset\n", eipOff);
        _plugin_logprintf("[erc++] \n");
        _plugin_logprintf("[erc++] # Find a usable jump with:\n");
        _plugin_logprintf("[erc++] #   erc++ -SearchMemory, \"jmp esp\", -ASLR, -RX, -b\n");
        _plugin_logprintf("[erc++] jmp_esp  = 0xDEADBEEF  # ← replace\n");
        _plugin_logprintf("[erc++] \n");
        _plugin_logprintf("[erc++] shellcode = b\"\"       # ← your shellcode\n");
        _plugin_logprintf("[erc++] \n");
        _plugin_logprintf("[erc++] payload  = b'A' * offset\n");
        _plugin_logprintf("[erc++] payload += pack('<I', jmp_esp)\n");
        _plugin_logprintf("[erc++] payload += shellcode\n");
        _plugin_logprintf("[erc++] \n");
        _plugin_logprintf("[erc++] # send(payload) ...\n");
        _plugin_logprintf("[erc++] -------------------------------------------------\n");
    }

    _plugin_logprintf("[erc++] === End Analysis ===\n");
}

// ─── Parse permission spec "rw", "R-X", "x", etc. → "RW-", "R-X", "--X" ─────
static bool parsePermSpec(const std::string& raw, std::string& outSpec) {
    bool r = false, w = false, x = false, any = false;
    for (char c : raw) {
        char u = (char)toupper((unsigned char)c);
        if      (u == 'R') { r = true; any = true; }
        else if (u == 'W') { w = true; any = true; }
        else if (u == 'X') { x = true; any = true; }
        else if (u == '-' || u == ' ' || u == '\t') continue;
        else return false;
    }
    if (!any) return false;
    outSpec.clear();
    outSpec += r ? 'R' : '-';
    outSpec += w ? 'W' : '-';
    outSpec += x ? 'X' : '-';
    return true;
}

// ─── Wildcard match (glob): soporta '*' y '?' ────────────────────────────────
// '*' = cero o más caracteres
// '?' = exactamente un carácter
// Ambos argumentos deben venir ya en lowercase.
static bool wildcardMatch(const char* pat, const char* str) {
    const char* star   = nullptr;   // último '*' visto en el patrón
    const char* mark   = nullptr;   // posición en 'str' cuando vimos ese '*'
    while (*str) {
        if (*pat == '?' || *pat == *str) {
            ++pat; ++str;
        } else if (*pat == '*') {
            star = pat++;
            mark = str;
        } else if (star) {
            pat = star + 1;
            str = ++mark;
        } else {
            return false;
        }
    }
    while (*pat == '*') ++pat;
    return *pat == '\0';
}


// ─── ¿el módulo matchea con un patrón de -Modules? ───────────────────────────
static bool matchModulePattern(const ModInfo& mod, const std::string& pattern) {
    bool hasWild = pattern.find('*') != std::string::npos ||
                   pattern.find('?') != std::string::npos;

    if (hasWild) {
        // Wildcard contra el nombre (lowercased) …
        if (wildcardMatch(pattern.c_str(), mod.name.c_str())) return true;
        // … y también contra la ruta completa (lowercased on-the-fly)
        std::string pathLo = toLower(mod.path);
        return wildcardMatch(pattern.c_str(), pathLo.c_str());
    }

    // Sin wildcards: comportamiento original
    if (mod.name == pattern) return true;
    std::string pathLo = toLower(mod.path);
    return pathLo.find(pattern) != std::string::npos;
}

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
    out.resize(size);
    return out;
}

static bool hexValueToLeString(const std::string& rawHex, std::string& out) {
    std::string clean;
    for (size_t i = 0; i < rawHex.size(); ++i) {
        char c = rawHex[i];
        if (c == ' ' || c == '\t') continue;
        if (c == '\\' && i+1 < rawHex.size() &&
            (rawHex[i+1] == 'x' || rawHex[i+1] == 'X')) { ++i; continue; }
        if (c == '0' && i+1 < rawHex.size() &&
            (rawHex[i+1] == 'x' || rawHex[i+1] == 'X')) { ++i; continue; }
        if (!isxdigit((unsigned char)c)) return false;
        clean += c;
    }
    if (clean.empty() || clean.size() % 2 != 0) return false;
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < clean.size(); i += 2)
        bytes.push_back((uint8_t)std::stoul(clean.substr(i, 2), nullptr, 16));
    std::reverse(bytes.begin(), bytes.end());
    out.assign(bytes.begin(), bytes.end());
    return !out.empty();
}

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

    if (pattern.find(raw) != std::string::npos) {
        needle  = raw;
        display = raw + "  (ASCII)";
        return true;
    }

    if (hexValueToLeString(raw, needle)) {
        display = toHexDisplay(needle) + "  (hex)";
        return true;
    }

    return false;
}

static void doPatternCommand(const std::vector<std::string>& tokens) {
    std::string mode = toLower(tokens[0]);

    if (mode == "c") {
        if (tokens.size() < 2) {
            logErr("Uso: erc++ --Pattern, c, <tamaño>");
            return;
        }
        int size = 0;
        try { size = std::stoi(tokens[1]); } catch (...) {
            logErr("Tamaño inválido.");
            return;
        }
        if (size <= 0 || size > 1000000) {
            logErr("Tamaño fuera de rango (1..1000000).");
            return;
        }

        std::string pattern = generatePattern(size);
        g_lastPattern     = pattern;
        g_lastPatternSize = size;

        _plugin_logprintf("[erc++] Pattern creado (%d bytes):\n", size);
        _plugin_logprintf("[erc++] ASCII:\n%s\n", pattern.c_str());

        std::string hexOut;
        hexOut.reserve(pattern.size() * 4);
        for (unsigned char c : pattern) {
            char buf[8];
            sprintf_s(buf, "\\x%02X", c);
            hexOut += buf;
        }
        _plugin_logprintf("[erc++] HEX:\n%s\n", hexOut.c_str());
        logOk("Pattern almacenado. Usa 'erc++ --Pattern, o, 0xXXXXXXXX' para buscar offset.");
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
        _plugin_logprintf("[erc++] Offset en posición: %zu (0x%zX)\n", pos, pos);
        return;
    }

    logErr("Subcomando desconocido '" + tokens[0] + "'. Usa 'c' o 'o'.");
}

// ─── hex string → bytes ──────────────────────────────────────────────────────
static bool hexToBytes(const std::string& hex, std::vector<uint8_t>& out) {
    std::string clean;
    for (size_t i = 0; i < hex.size(); ++i) {
        char c = hex[i];
        if (c == ' ' || c == '\t') continue;
        if (c == '\\' && i+1 < hex.size() && (hex[i+1] == 'x' || hex[i+1] == 'X')) {
            i++; continue;
        }
        if (c == '0' && i+1 < hex.size() && (hex[i+1] == 'x' || hex[i+1] == 'X')) {
            i++; continue;
        }
        if (!isxdigit((unsigned char)c)) return false;
        clean += c;
    }
    if (clean.empty() || clean.size() % 2 != 0) return false;
    for (size_t i = 0; i < clean.size(); i += 2)
        out.push_back((uint8_t)std::stoul(clean.substr(i, 2), nullptr, 16));
    return !out.empty();
}

// ─── page permissions ────────────────────────────────────────────────────────
static std::string getPagePermissions(duint address) {
    HANDLE hProcess = DbgGetProcessHandle();
    if (!hProcess) return "???";

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == 0)
        return "???";
    if (mbi.State != MEM_COMMIT)
        return "---";

    std::string perms = "---";
    DWORD prot = mbi.Protect;
    if (prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        perms[0] = 'R';
    if (prot & (PAGE_READWRITE | PAGE_WRITECOPY |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        perms[1] = 'W';
    if (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        perms[2] = 'X';
    return perms;
}

// ─── wildcard-aware pattern byte ─────────────────────────────────────────────
struct PatternByte {
    uint8_t value    = 0;
    bool    wildcard = false;
    bool    hasRange = false;
    uint8_t rangeMin = 0x00;
    uint8_t rangeMax = 0xFF;
};

// ─── gadget part ─────────────────────────────────────────────────────────────
enum class MatchType {
    Exact,       // "ret", "jmp esp"       → instrucción completa exacta
    MnemOnly,    // "pop ?", "add ?"       → mnemónico base, cualquier operando
    MnemWithOps, // "add eax, ?"           → mnemónico + destino fijo, src wildcard
};

struct GadgetPart {
    MatchType   type;
    std::string mnemonic;  // mnemónico base lowercase
    std::string fixedOps;  // para MnemWithOps: parte fija de operandos ("eax")
};

// ─── parser de una parte del gadget ──────────────────────────────────────────
static GadgetPart parseGadgetPart(const std::string& partLo) {
    GadgetPart gp{};

    // "add eax, ?" → MnemWithOps
    size_t commaWild = partLo.rfind(", ?");
    if (commaWild != std::string::npos && commaWild == partLo.size() - 3) {
        size_t sp = partLo.find(' ');
        gp.type     = MatchType::MnemWithOps;
        gp.mnemonic = partLo.substr(0, sp);
        std::string ops = partLo.substr(sp + 1, commaWild - sp - 1);
        size_t a = ops.find_first_not_of(" \t");
        size_t b = ops.find_last_not_of(" \t");
        gp.fixedOps = (a != std::string::npos) ? ops.substr(a, b - a + 1) : "";
        return gp;
    }

    // "pop ?", "add ?" → MnemOnly
    size_t spaceWild = partLo.rfind(' ');
    if (spaceWild != std::string::npos) {
        std::string afterSpace = partLo.substr(spaceWild + 1);
        if (afterSpace == "?") {
            gp.type     = MatchType::MnemOnly;
            gp.mnemonic = partLo.substr(0, spaceWild);
            gp.fixedOps = "";
            return gp;
        }
    }

    // instrucción exacta: "ret", "nop", "jmp esp"
    gp.type     = MatchType::Exact;
    gp.mnemonic = partLo;
    gp.fixedOps = "";
    return gp;
}

// ─── split instrucción en base + operandos ───────────────────────────────────
static void splitInstruction(const std::string& insn,
                             std::string& base,
                             std::string& ops)
{
    size_t sp = insn.find(' ');
    if (sp == std::string::npos) {
        base = insn;
        ops  = "";
    } else {
        base = insn.substr(0, sp);
        ops  = insn.substr(sp + 1);
        size_t a = ops.find_first_not_of(" \t");
        size_t b = ops.find_last_not_of(" \t");
        ops = (a != std::string::npos) ? ops.substr(a, b - a + 1) : "";
    }
}

// ─── validación de gadget instrucción por instrucción ────────────────────────
// Desensambla EXACTAMENTE parts.size() instrucciones desde address.
// Cada una debe coincidir con su GadgetPart. Ni una instrucción extra.
static bool validateGadget(duint address, const std::vector<GadgetPart>& parts, size_t* outLen = nullptr) {
    duint cursor = address;

    for (size_t i = 0; i < parts.size(); ++i) {
        const GadgetPart& gp = parts[i];

        BASIC_INSTRUCTION_INFO info;
        memset(&info, 0, sizeof(info));

	DbgDisasmFastAt(cursor, &info);
        if (info.size == 0)
            return false;

        // Mnemónico real, lowercase y trimmed
        std::string actual = toLower(std::string(info.instruction));
        size_t a = actual.find_first_not_of(" \t");
        size_t b = actual.find_last_not_of(" \t");
        if (a == std::string::npos) return false;
        actual = actual.substr(a, b - a + 1);

        std::string actualBase, actualOps;
        splitInstruction(actual, actualBase, actualOps);

        switch (gp.type) {

        case MatchType::Exact:
            if (actual != gp.mnemonic)
                return false;
            break;

        case MatchType::MnemOnly:
            // "pop ?" → acepta "pop eax", "pop ebx", etc.
            // "add ?" → acepta "add eax, 0x10", "add var_4, 2", etc.
            if (actualBase != gp.mnemonic)
                return false;
            break;

        case MatchType::MnemWithOps:
            // "add eax, ?" → base=="add" y ops empieza con "eax,"
            if (actualBase != gp.mnemonic)
                return false;
            {
                std::string expectedPrefix = gp.fixedOps + ",";
                if (actualOps.size() < expectedPrefix.size())
                    return false;
                if (actualOps.substr(0, expectedPrefix.size()) != expectedPrefix)
                    return false;
            }
            break;
        }

        // Avanza por el tamaño REAL de la instrucción
        cursor += info.size;
    }

    if (outLen) *outLen = (size_t)(cursor - address); 
    return true;
}

// ─── resolve pattern ─────────────────────────────────────────────────────────
static bool resolvePattern(const std::string& raw,
                           std::vector<PatternByte>& out,
                           std::vector<GadgetPart>& gadgetParts)
{
    std::string lo = toLower(raw);
    std::string s  = raw;
    std::replace(s.begin(), s.end(), '+', ';');

    auto pushExact = [&](uint8_t b) {
        out.push_back({b, false, false, 0x00, 0xFF});
    };
    auto pushWildRange = [&](uint8_t mn, uint8_t mx) {
        out.push_back({0x00, true, true, mn, mx});
    };
    auto pushWildAny = [&]() {
        out.push_back({0x00, true, false, 0x00, 0xFF});
    };

    // ── Gadget multi-instrucción ─────────────────────────────────────────────
    if (s.find(';') != std::string::npos) {
        std::vector<PatternByte> combined;
        std::vector<GadgetPart>  parts;
        bool ok = true;

        std::istringstream iss(s);
        std::string part;

        while (std::getline(iss, part, ';')) {
            size_t a = part.find_first_not_of(" \t");
            size_t b = part.find_last_not_of(" \t");
            if (a == std::string::npos) continue;
            part = part.substr(a, b - a + 1);
            std::string partLo = toLower(part);

            GadgetPart gp = parseGadgetPart(partLo);
            parts.push_back(gp);

            switch (gp.type) {
            case MatchType::MnemOnly:
                if (gp.mnemonic == "pop") {
                    // pop reg = 1 byte en rango 0x58-0x5F
                    pushWildRange(0x58, 0x5F);
                } else {
                    // Otro mnemónico wildcard: ancla de 1 byte
                    // validateGadget verificará el mnemónico real
                    pushWildAny();
                }
                break;

            case MatchType::MnemWithOps:
                // Tamaño desconocido → ancla de 1 byte cualquiera
                pushWildAny();
                break;

            case MatchType::Exact: {
                auto pit = INSN_MAP.find(partLo);
                if (pit == INSN_MAP.end()) {
                    logErr("Unknown instruction '" + part + "' in gadget.");
                    ok = false;
                } else {
                    for (uint8_t byte : pit->second)
                        pushExact(byte);
                }
                break;
            }
            }

            if (!ok) break;
        }

        if (ok && !combined.empty()) {
            out         = combined;
            gadgetParts = parts;
            return true;
        }

        // ── BUG FIX: combined se llenó arriba pero nunca se usó ──────────────
        // Corregido: usamos `out` directamente via pushExact/pushWild*
        if (ok && !out.empty()) {
            gadgetParts = parts;
            return true;
        }

        return false;
    }

    // ── Mnemónico simple ─────────────────────────────────────────────────────
    {
        auto it = INSN_MAP.find(lo);
        if (it != INSN_MAP.end()) {
            for (uint8_t b : it->second) pushExact(b);
            gadgetParts.clear();
            return true;
        }
    }

    // ── Hex con wildcards (tokens separados por espacios) ────────────────────
    {
        std::istringstream iss(raw);
        std::string token;
        bool looksHex = false, valid = true;

        while (iss >> token) {
            looksHex = true;
            if (token.size() >= 2 && token[0] == '\\' &&
                (token[1] == 'x' || token[1] == 'X')) token = token.substr(2);
            else if (token.size() >= 2 && token[0] == '0' &&
                     (token[1] == 'x' || token[1] == 'X')) token = token.substr(2);

            if (token == "??" || token == "?") {
                pushWildAny();
            } else if (token.size() == 2 &&
                       isxdigit((unsigned char)token[0]) &&
                       isxdigit((unsigned char)token[1])) {
                pushExact((uint8_t)std::stoul(token, nullptr, 16));
            } else {
                valid = false; break;
            }
        }

        if (looksHex && valid && !out.empty()) {
            gadgetParts.clear();
            return true;
        }
        out.clear();
    }

    // ── Hex sin espacios ─────────────────────────────────────────────────────
    {
        std::vector<uint8_t> raw8;
        if (hexToBytes(raw, raw8)) {
            for (uint8_t b : raw8) pushExact(b);
            gadgetParts.clear();
            return true;
        }
    }

    logErr("Unknown pattern '" + raw + "'. "
           "Use hex (FF E4 | FF ?? C3), a mnemonic (jmp esp), "
           "or a gadget (pop ?; pop ?; ret).");
    return false;
}

// ─── PE flags ────────────────────────────────────────────────────────────────
struct ModuleFlags {
    bool aslr    = false;
    bool safeseh = false;
    bool dep     = false;
    bool rebase  = false;
};

#define DLLCHAR_DYNAMIC_BASE 0x0040
#define DLLCHAR_NX_COMPAT    0x0100

static ModuleFlags getModuleFlags(const std::string& modPath) {
    ModuleFlags f;
    HMODULE hMod = LoadLibraryExA(modPath.c_str(), NULL,
        LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!hMod) return f;

    auto base = reinterpret_cast<BYTE*>((ULONG_PTR)hMod & ~(ULONG_PTR)3);

    __try {
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) { FreeLibrary(hMod); return f; }
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) { FreeLibrary(hMod); return f; }

        WORD ch   = nt->OptionalHeader.DllCharacteristics;
        f.aslr    = (ch & DLLCHAR_DYNAMIC_BASE) != 0;
        f.dep     = (ch & DLLCHAR_NX_COMPAT)    != 0;
        f.rebase  = f.aslr;

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
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    FreeLibrary(hMod);
    return f;
}

// ─── search bytes in buffer ───────────────────────────────────────────────────
static std::vector<duint> searchInBuffer(
    const uint8_t* buf, size_t bufLen, duint baseAddr,
    const std::vector<PatternByte>& pattern)
{
    std::vector<duint> hits;
    if (pattern.empty() || bufLen < pattern.size()) return hits;

    for (size_t i = 0; i <= bufLen - pattern.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            const PatternByte& pb = pattern[j];
            uint8_t b = buf[i + j];

            if (pb.wildcard) {
                if (pb.hasRange && (b < pb.rangeMin || b > pb.rangeMax)) {
                    match = false;
                    break;
                }
            } else {
                if (b != pb.value) {
                    match = false;
                    break;
                }
            }
        }
        if (match)
            hits.push_back(baseAddr + (duint)i);
    }
    return hits;
}

// ─── Badchars detection ───────────────────────────────────────────────────
static bool containsBadChars(const uint8_t* buf, size_t len,
                             const std::vector<uint8_t>& bad)
{
    if (bad.empty()) return false;
    for (size_t i = 0; i < len; ++i)
        if (std::find(bad.begin(), bad.end(), buf[i]) != bad.end())
            return true;
    return false;
}

static std::vector<ModInfo> getLoadedModules() {
    std::vector<ModInfo> mods;
    BridgeList<Script::Module::ModuleInfo> list;
    if (!Script::Module::GetList(&list)) return mods;

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

// ─── print banner ─────────────────────────────────────────────────────────────
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

// ─── print help ───────────────────────────────────────────────────────────────
static void printHelp() {
    printBanner();
    _plugin_logprintf(
        "Commands are CASE-INSENSITIVE. Arguments separated by COMMAS.\n\n"
        "  erc++ -SearchMemory, <pattern>[, <flag>...]\n"
        "    Search all process memory for a byte pattern or mnemonic.\n"
        "    Filters:\n"
        "      -ASLR     exclude ASLR-enabled modules\n"
        "      -SafeSEH  exclude SafeSEH-enabled modules\n"
        "      -DEP      exclude DEP/NXCompat-enabled modules\n"
        "      -Rebase   exclude Rebase-enabled modules\n\n"
        "      -b        exclude hits containing bad characters\n"
        "                (default: 00 0A 0D 1A if no list given)\n"
        "      -b, <hex> custom badchar list, e.g. \"00 0A 0D 1A\"\n"
        "                or \"\\x00\\x0A\\x0D\\x1A\"\n\n"
        "      -RWX      filtrar las paginas por permissiones\n"
        "      Combine with OR:  -RX -RWX  →  (R-X) or (RWX)\n\n"
        "  erc++ -SearchModules, <pattern>, -Modules, <list>[, <flag>...]\n"
        "    Same as SearchMemory but restricted to specific modules.\n"
        "    <list> accepts wildcards: 'ep*.dll', '*user*', 'nt?ll.dll'\n\n"
        "  erc++ --Pattern, c, <length>\n"
        "    Generate a unique cyclic pattern (ASCII + hex).\n\n"
        "  erc++ --Pattern, o, <value>\n"
        "    Find offset of <value> in the last generated pattern.\n\n"
        "  erc++ -help\n"
        "    Show this message.\n\n"
        "Patterns:\n"
        "  Hex bytes     : FF E4  |  FFE4  |  \\xFF\\xE4\n"
        "  Wildcards     : FF ?? C3  (?? = any byte)\n"
        "  Mnemonics     : jmp esp, call eax, ret, nop ...\n"
        "  Gadgets       : \"pop ?; pop ?; ret\"\n"
        "                  \"pop ?; add ?; ret\"\n"
        "                  \"pop ?; add eax, ?; ret\"\n"
        "                  (separator: ';' or '+')\n\n"
        "Gadget wildcards:\n"
        "  pop ?         matches any single pop-reg instruction\n"
        "  add ?         matches any add instruction (any operands)\n"
        "  add eax, ?    matches add eax with any source operand\n\n"
        "Examples:\n"
        "  erc++ --Pattern, c, 1000\n"
        "  erc++ --Pattern, o, 0xAABBCCDD\n"
        "  erc++ -SearchMemory, \"jmp esp\"\n"
        "  erc++ -SearchMemory, \"FF E4\", -ASLR\n"
        "  erc++ -SearchMemory, \"pop ?; pop ?; ret\"\n"
        "  erc++ -SearchMemory, \"pop ?; add ?; ret\", -ASLR\n"
        "  erc++ -SearchMemory, \"pop ?; add eax, ?; ret\"\n"
        "  erc++ -SearchModules, \"jmp esp\", -Modules, \"kernel32.dll,user32.dll\"\n"
        "  erc++ -SearchModules, \"jmp esp\", -Modules, \"ep*.dll\"\n"
        "  erc++ -SearchModules, \"pop ?; pop ?; ret\", -Modules, \"*user*\"\n"
        "  erc++ -SearchMemory, \"pop ?; pop ?; ret\", -b\n"
        "  erc++ -SearchMemory, \"pop ?; pop ?; ret\", -b, \"00 0A 0D 1A\", -ASLR\n"
	"  erc++ --Pattern, c, 1000\n"
	"  erc++ -analyze\n"
	"  erc++ -analyze, -b, \"00 0A\"\n"
    );
}


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
    if (pat.empty()) { logErr("No pattern specified."); return sa; }
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
                logErr("-Modules requires a module list.");
                return sa;
            }
            std::istringstream mss(modList);
            std::string m;
            while (std::getline(mss, m, ',')) {
                // x64dbg solo elimina comillas dobles; los usuarios escriben
                // a veces 'mod.dll' con comillas simples. Las limpiamos aquí.
                size_t a = m.find_first_not_of(" \t'\"");
                size_t b = m.find_last_not_of(" \t'\"");
                if (a == std::string::npos) continue;
                m = m.substr(a, b - a + 1);
                if (!m.empty()) sa.modules.push_back(toLower(m));
            }
        } 
        else if (lo == "-b" || lo == "-badchars") {
            std::vector<uint8_t> badBytes;
            if (i + 1 < argc) {
                std::string next(argv[i + 1]);
                // Strip quotes (single or double)
                size_t a = next.find_first_not_of(" \t'\"");
                size_t b = next.find_last_not_of(" \t'\"");
                if (a != std::string::npos)
                    next = next.substr(a, b - a + 1);

                if (!next.empty() && next[0] != '-') {
                    ++i;
                    if (!hexToBytes(next, badBytes)) {
                        logErr("-b invalid byte list: " + next);
                        return sa;
                    }
                }
            }
            if (badBytes.empty())
                badBytes = { 0x00, 0x0A, 0x0D, 0x1A };
            sa.badChars = badBytes;
        }
	else {
            // Intentar parsear como filtro de permisos: -R, -RW, -RX, -RWX, -X, -W, ...
            std::string permSpec;
            bool isPerm = false;
            if (lo.size() >= 2 && lo[0] == '-') {
                isPerm = parsePermSpec(lo.substr(1), permSpec);
            }
            if (!isPerm) {
                logErr("Unknown flag '" + std::string(argv[i]) + "'. Try erc++ -help.");
                return sa;
            }
            sa.permFilters.push_back(permSpec);
        }
    }
    sa.valid = true;
    return sa;
}

// ─── format address ───────────────────────────────────────────────────────────
static std::string fmtAddr(duint addr) {
    std::ostringstream ss;
#ifdef _WIN64
    ss << "0x" << std::uppercase << std::hex << std::setw(16) << std::setfill('0') << addr;
#else
    ss << "0x" << std::uppercase << std::hex << std::setw(8)  << std::setfill('0') << addr;
#endif
    return ss.str();
}

// ─── core search ──────────────────────────────────────────────────────────────
static void doSearch(const SearchArgs& sa, bool modulesOnly) {
    std::vector<PatternByte> pat;
    std::vector<GadgetPart>  gadgetParts;

    if (!resolvePattern(sa.pattern, pat, gadgetParts)) return;

    // Build display string for the pattern
    std::string patHex;
    for (auto& pb : pat) {
        if (pb.wildcard) {
            if (pb.hasRange) {
                char buf[16];
                sprintf_s(buf, "[%02X-%02X] ", pb.rangeMin, pb.rangeMax);
                patHex += buf;
            } else {
                patHex += "?? ";
            }
        } else {
            char buf[4];
            sprintf_s(buf, "%02X ", pb.value);
            patHex += buf;
        }
    }

    std::string filterDesc;
    if (sa.filterASLR)    filterDesc += " -ASLR";
    if (sa.filterSafeSEH) filterDesc += " -SafeSEH";
    if (sa.filterDEP)     filterDesc += " -DEP";
    if (sa.filterRebase)  filterDesc += " -Rebase";
    if (!sa.permFilters.empty()) {
        std::string disp;
        for (size_t i = 0; i < sa.permFilters.size(); ++i) {
            if (i > 0) disp += ",";
            std::string d = sa.permFilters[i];
            while (!d.empty() && d.front() == '-') d.erase(0, 1);
            while (!d.empty() && d.back()  == '-') d.pop_back();
            if (d.empty()) d = "---";
            disp += d;
        }
        filterDesc += " -Perms[" + disp + "]";
    }
    if (filterDesc.empty()) filterDesc = " (no filters)";

    if (!sa.badChars.empty()) {
        std::string bstr;
        for (uint8_t b : sa.badChars) {
            char bb[4]; sprintf_s(bb, "%02X ", b); bstr += bb;
        }
        _plugin_logprintf("[erc++] BadChars: %s\n", bstr.c_str());
    }

    _plugin_logprintf("[erc++] Searching for: %s [%s]%s\n",
        sa.pattern.c_str(), patHex.c_str(), filterDesc.c_str());

    if (!gadgetParts.empty())
        _plugin_logprintf("[erc++] Gadget validation: ON (%zu instructions expected)\n",
            gadgetParts.size());

    auto mods = getLoadedModules();
    if (mods.empty()) {
        logErr("Could not enumerate modules. Is a process attached?");
        return;
    }

    int totalHits = 0;
    int skipped   = 0;

    for (auto& mod : mods) {
        // Filter by module list if specified
        if (!sa.modules.empty()) {
            bool found = false;
            for (auto& wantedMod : sa.modules) {
                if (matchModulePattern(mod, wantedMod)) { found = true; break; }
            }
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

        // Fast byte-level scan
        auto hits = searchInBuffer(buf.data(), bytesRead, mod.base, pat);

        // Estructura local para no llamar dos veces a getPagePermissions
        struct ValidHit {
            duint       addr;
            std::string perms;
        };
        std::vector<ValidHit> validHits;

        for (duint addr : hits) {
            size_t matchLen = 0;

            // 1) validación gadget
            if (!gadgetParts.empty()) {
                if (!validateGadget(addr, gadgetParts, &matchLen))
                    continue;
            } else {
                matchLen = pat.size();
            }

            // 2) badchars (barato)
            if (!sa.badChars.empty()) {
                size_t off = (size_t)(addr - mod.base);
                if (off + matchLen > bytesRead) continue;
                if (containsBadChars(buf.data() + off, matchLen, sa.badChars))
                    continue;
            }

            // 3) permisos de memoria (syscall) — solo si hay filtro
            std::string perms = getPagePermissions(addr);
            if (!sa.permFilters.empty()) {
                bool match = false;
                for (auto& p : sa.permFilters) {
                    if (perms == p) { match = true; break; }
                }
                if (!match) continue;
            }

            validHits.push_back({ addr, perms });
        }

        if (!validHits.empty()) {
            _plugin_logprintf("[erc++] ── %s ──\n", mod.name.c_str());
            _plugin_logprintf("[erc++]    ASLR:%-4s SafeSEH:%-4s DEP:%-4s Rebase:%-4s\n",
                flags.aslr?"yes":"no", flags.safeseh?"yes":"no",
                flags.dep?"yes":"no",  flags.rebase?"yes":"no");
            for (auto& h : validHits) {
                _plugin_logprintf("[erc++]    %s  %s  [%s]\n",
                    fmtAddr(h.addr).c_str(), mod.name.c_str(), h.perms.c_str());
                ++totalHits;
            }
        }
    }

    _plugin_logprintf("[erc++] ────────────────────────────────\n");
    _plugin_logprintf("[erc++] Found %d result(s)  |  %d module(s) skipped by filters\n",
        totalHits, skipped);
}

// ─── comma-aware tokenizer ────────────────────────────────────────────────────
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
            logErr("No pattern specified.");
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

    if (subcmd == "--pattern" || subcmd == "-pattern") {
        if (tokens.size() < 2) {
            logErr("Uso: erc++ --Pattern, c, <tamaño>  |  erc++ --Pattern, o, <hex>");
            return true;
        }
        doPatternCommand(std::vector<std::string>(tokens.begin() + 1, tokens.end()));
        return true;
    }

    if (subcmd == "-analyze" || subcmd == "--analyze") {
        std::vector<uint8_t> badChars = { 0x00, 0x0A, 0x0D, 0x1A };

        // Args opcionales tras -analyze (sólo -b por ahora)
        for (size_t k = 1; k < tokens.size(); ++k) {
            std::string lo = toLower(tokens[k]);
            if (lo == "-b" || lo == "-badchars") {
                if (k + 1 < tokens.size()) {
                    std::string next = tokens[k + 1];
                    size_t a = next.find_first_not_of(" \t'\"");
                    size_t b = next.find_last_not_of(" \t'\"");
                    if (a != std::string::npos) next = next.substr(a, b - a + 1);
                    if (!next.empty() && next[0] != '-') {
                        ++k;
                        std::vector<uint8_t> custom;
                        if (hexToBytes(next, custom)) badChars = custom;
                    }
                }
            }
        }

        doAnalyze(badChars);
        return true;
    }

    logErr("Unknown command '" + tokens[0] + "'. Try: erc++ -help");
    return true;
}

// ─── plugin entry points ──────────────────────────────────────────────────────
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
