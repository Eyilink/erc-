# erc++ — x64dbg plugin

Plugin para x64dbg que reemplaza la funcionalidad de búsqueda de ERC con una interfaz limpia y filtros confiables.

---

## Instalación rápida

### 1. Prerequisitos

- Visual Studio 2022 (o Build Tools for Visual Studio) con la carga de trabajo **"Desktop development with C++"**
- x64dbg instalado

### 2. Descargar el SDK de x64dbg

Descarga el SDK oficial desde las releases de x64dbg:
```
https://github.com/x64dbg/x64dbg/releases
```
Extrae la carpeta `pluginsdk\` al lado de `build.ps1`:
```
erc_plus\
├── erc_plus.cpp
├── erc_plus.def
├── build.ps1
├── README.md
└── pluginsdk\
    ├── x32\
    │   ├── x32dbg.lib
    │   └── x32bridge.lib
    └── x64\
        ├── x64dbg.lib
        └── x64bridge.lib
```

### 3. Compilar

If you have previous compilation artifacts, you need to erase them for modifications to be taken into account.

```powershell
# Ambas arquitecturas (default)
.\build.ps1

# Solo x64
.\build.ps1 -Platform x64

# Solo x86
.\build.ps1 -Platform x86

# Si x64dbg no está en C:\x64dbg
.\build.ps1 -X64dbgRoot "D:\Tools\x64dbg\release"
```

El script compila, verifica la arquitectura del DLL producido y lo copia automáticamente a la carpeta `plugins\` de x64dbg.

### 4. Cargar

Reinicia x64dbg. El plugin aparece en la consola:
```
[erc++] loaded. Type 'erc++ -help' to get started.
```

---

## Uso

### Ayuda

```
erc++ -help
```

### SearchMemory

Busca en **toda la memoria del proceso** (módulos + heap + stack).

```
erc++ -SearchMemory "<patrón>" [filtros]
```

**Filtros disponibles** (excluyen módulos que TIENEN esa protección):

| Flag       | Qué excluye                              |
|------------|------------------------------------------|
| `-ASLR`    | Módulos con ASLR activado                |
| `-SafeSEH` | Módulos con SafeSEH activado             |
| `-DEP`     | Módulos con DEP/NXCompat activado        |
| `-Rebase`  | Módulos con Rebase activado              |

**Ejemplos:**

```
erc++ -SearchMemory, "jmp esp"
erc++ -SearchMemory, "FF E4", -ASLR
erc++ -SearchMemory, "FF E4", -ASLR, -DEP
erc++ -SearchMemory, "jmp esp", -ASLR, -SafeSEH, -DEP, -Rebase
erc++ -SearchModules, "jmp esp", -Modules, "kernel32.dll,user32.dll"
erc++ -SearchModules, "FF E4", -Modules, ntdll.dll, -ASLR, -SafeSEH
```

### SearchModules

Igual que SearchMemory pero **restringido a módulos específicos**.

```
erc++ -SearchModules "<patrón>" -Modules mod1.dll,mod2.dll [filtros]
```

**Ejemplos:**

```
# Buscar JMP ESP solo en kernel32 y user32
erc++ -SearchModules, "jmp esp", -Modules, "kernel32.dll,user32.dll"

# Buscar en ntdll, excluyendo si tiene ASLR
erc++ -SearchModules, "FF E4", -Modules, ntdll.dll, -ASLR

# Varios módulos con varios filtros
erc++ -SearchModules, "FF E4", -Modules, ntdll.dll, -ASLR, -SafeSEH
```

---

## Patrones soportados

### Hex bytes
```
FF E4
FFE4
\xFF\xE4
0xFF 0xE4
```

### Mnemonics (sin distinguir mayúsculas)
```
jmp esp      jmp eax      jmp ebx      jmp ecx
jmp edx      jmp esi      jmp edi      jmp ebp
jmp rsp      jmp rax      jmp rbx      (x64)
call esp     call eax     call ebx     ...
pop eax      pop ebx      pop ecx      pop edx
pop esi      pop edi      pop ebp
push esp     push eax
ret          nop
```

---

## Formato de salida

```
[erc++] Searching for: jmp esp [FF E4 ] -ASLR -SafeSEH
[erc++] ── kernel32.dll ──
[erc++]    ASLR:no   SafeSEH:no   DEP:yes  Rebase:no
[erc++]    0x7C86467B  kernel32.dll
[erc++]    0x7C864B3F  kernel32.dll
[erc++] ────────────────────────────────
[erc++] Found 2 result(s)  |  3 module(s) skipped by filters
```

---

## Flags de seguridad explicados

| Flag    | PE Header                      | Descripción                                              |
|---------|--------------------------------|----------------------------------------------------------|
| ASLR    | `DYNAMIC_BASE` (0x0040)        | El módulo puede ser cargado en dirección aleatoria       |
| SafeSEH | Load Config / SEHandlerCount   | Los manejadores de excepción están validados             |
| DEP     | `NX_COMPAT` (0x0100)           | Stack/heap marcados como no ejecutables                  |
| Rebase  | Igual que ASLR                 | El módulo tiene dirección base variable                  |

---

## Workflow típico para buffer overflow clásico (x86, sin DEP)

```
# 1. Ver qué hay en el proceso
erc++ -SearchMemory, "jmp esp", -ASLR

# 2. Si hay demasiados resultados, filtrar más
erc++ -SearchMemory, "jmp esp", -ASLR, -SafeSEH, -Rebase

# 3. Si sabes que kernel32 no tiene ASLR en tu target
erc++ -SearchModules, "jmp esp", -Modules, kernel32.dll, -ASLR

# 4. Usar la dirección resultante como return address en el exploit
```

---

## Compilación manual (sin PowerShell)

```bat
rem x64 — desde Developer Command Prompt de VS2022
cl /EHsc /W3 /O2 /LD /DWIN32 /D_WINDOWS /D_USRDLL /DUNICODE /D_UNICODE ^
   /I"pluginsdk" ^
   erc_plus.cpp ^
   /Fe:erc_plus.dp64 ^
   /link /DEF:erc_plus.def ^
   pluginsdk\x64\x64dbg.lib ^
   pluginsdk\x64\x64bridge.lib ^
   psapi.lib

rem x86
cl /EHsc /W3 /O2 /LD /DWIN32 /D_WINDOWS /D_USRDLL /DUNICODE /D_UNICODE ^
   /I"pluginsdk" ^
   erc_plus.cpp ^
   /Fe:erc_plus.dp32 ^
   /link /DEF:erc_plus.def ^
   pluginsdk\x32\x32dbg.lib ^
   pluginsdk\x32\x32bridge.lib ^
   psapi.lib
```
