"""Tiered forensic signatures, cheat indicators, and allowlists.

Signatures are partitioned by specificity so engines can enforce strict vs.
contextual co-occurrence rules and avoid false positives on standard Linux
or legitimate optimization mods.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# 1. Strict Cheat Client / Ghost Client / Injector Identifiers (High Precision)
# ---------------------------------------------------------------------------
STRICT_CHEAT_IDENTIFIERS: tuple[str, ...] = (
    "vapev4",
    "vapelite",
    "vape.gg",
    "gg/vape",
    "me/vape",
    "driplite",
    "drip.gg",
    "doomsdayclient",
    "doomsday_client",
    "com/doomsday",
    "meteorclient",
    "meteor-client",
    "meteordevelopment",
    "liquidbounce",
    "net/ccbluex",
    "ccbluex",
    "wurstclient",
    "net/wurstclient",
    "aristois",
    "me/deftware",
    "rusherhack",
    "org/rusherhack",
    "futureclient",
    "net/futureclient",
    "impactclient",
    "bleachhack",
    "org/bleachhack",
    "3arthh4ck",
    "me/earth/earthhack",
    "earthhack",
    "thunderhack",
    "thunder/hack",
    "fdpclient",
    "augustusclient",
    "tenacityclient",
    "novoline",
    "riseclient",
    "bozeclient",
    "shorelineclient",
    "mioclient",
    "konasclient",
    "salhack",
    "kamiblue",
    "gamesenseclient",
    "seppuku",
    "pyroclient",
    "aresclient",
    "mathax",
    "coffeeclient",
    "trouserstreak",
    "ravenb+",
    "ravenbs",
    "ravenxd",
    "slinkyclient",
    "whiteoutclient",
    "iceteaclient",
    "itamiclient",
    "kryptonclient",
    "phantomclient",
    "dreamclient",
    "seedcracker",
    "advanced-xray",
    "chestesp",
    "xclicker",
    "opautoclicker",
    "gsautoclicker",
    "speedautoclicker",
    "speed-autoclicker",
    "tiny-task",
    "tinytask",
    "selfdestruct",
    "self_destruct",
)

# ---------------------------------------------------------------------------
# 2. Contextual Cheat Modules / Features
#    - High-signal in mod filenames, keybinds (`key_...`), class names, configs
#    - Require >= 2 distinct co-occurring terms in raw RAM / log lines
# ---------------------------------------------------------------------------
CONTEXTUAL_CHEAT_MODULES: tuple[str, ...] = (
    "killaura",
    "kill_aura",
    "triggerbot",
    "aimassist",
    "aim_assist",
    "aimbot",
    "autoclick",
    "autoclicker",
    "auto_clicker",
    "autopot",
    "autototem",
    "autoarmor",
    "autocrystal",
    "anchor_aura",
    "crystalaura",
    "cheststealer",
    "scaffoldwalk",
    "scaffold",
    "antivelocity",
    "antibot",
    "antiknockback",
    "anti_kb",
    "nofall",
    "no_fall",
    "noslow",
    "fastbreak",
    "fastplace",
    "speedmine",
    "nuker",
    "jesuswalk",
    "stephack",
    "phasehack",
    "blinkhack",
    "hitbox",
    "hitboxes",
    "reachhack",
    "reach_expand",
    "nametags",
    "tracers",
    "playeresp",
    "storageesp",
    "itemesp",
    "cavefinder",
    "fullbright",
    "gammautils",
    "freecam",
    "xray",
    "x-ray",
    "clickgui",
    "hudeditor",
    "modulelist",
    "activemodules",
    "baritone",
    "wallhack",
    "esp_box",
    "velocity",
    "reach",
    "criticals",
    "blink",
    "timerhack",
    "flyhack",
    "killaura_range",
    "wtap_macro",
    "jitterclick",
    "butterfly_macro",
)

# High-signal subset even individually in class/filename/keybind contexts
HIGH_SIGNAL_MODULE_NAMES: frozenset[str] = frozenset(
    {
        "killaura",
        "kill_aura",
        "triggerbot",
        "aimassist",
        "aim_assist",
        "aimbot",
        "autoclick",
        "autoclicker",
        "auto_clicker",
        "autopot",
        "autototem",
        "autocrystal",
        "crystalaura",
        "cheststealer",
        "scaffoldwalk",
        "antivelocity",
        "antiknockback",
        "anti_kb",
        "hitbox",
        "hitboxes",
        "reachhack",
        "reach_expand",
        "playeresp",
        "storageesp",
        "cavefinder",
        "fullbright",
        "gammautils",
        "freecam",
        "xray",
        "x-ray",
        "clickgui",
        "baritone",
        "wallhack",
        "selfdestruct",
        "self_destruct",
        "jitterclick",
    }
)

# ---------------------------------------------------------------------------
# 3. Cheat / Suspicious Download & Auth Domains
# ---------------------------------------------------------------------------
CHEAT_DOMAINS: tuple[str, ...] = (
    "vape.gg",
    "drip.gg",
    "doomsdayclient.com",
    "meteorclient.com",
    "liquidbounce.net",
    "wurstclient.net",
    "aristois.net",
    "rusherhack.org",
    "futureclient.net",
    "impactclient.net",
    "bleachhack.org",
    "fdpinfo.github.io",
    "riseclient.com",
    "intent.store",
    "novoline.wtf",
    "slinky.gg",
    "entropy.club",
    "whiteout.lol",
    "kryptonclient.com",
    "boze.dev",
    "konasclient.com",
    "pyroclient.com",
    "phant0m.org",
    "xclicker.xyz",
    "opautoclicker.com",
    "cheatengine.org",
    "unknowncheats.me",
    "mpgh.net",
    "elitepvpers.com",
)

SUSPICIOUS_UNVERIFIED_MOD_ORIGINS: tuple[str, ...] = (
    "cdn.discordapp.com",
    "media.discordapp.net",
    "anonfiles.",
    "gofile.io",
    "mediafire.com",
    "mega.nz",
    "catbox.moe",
    "transfer.sh",
    "file.io",
    "0x0.st",
    "pixeldrain.com",
    "workupload.com",
    "sendspace.com",
)

TRUSTED_MOD_ORIGINS: tuple[str, ...] = (
    "modrinth.com",
    "cdn.modrinth.com",
    "curseforge.com",
    "mediafilez.forgecdn.net",
    "edge.forgecdn.net",
    "optifine.net",
    "optifined.net",
    "fabricmc.net",
    "maven.fabricmc.net",
    "maven.neoforged.net",
    "files.minecraftforge.net",
    "maven.quiltmc.org",
    "mojang.com",
    "minecraft.net",
    "lunarclient.com",
    "badlion.net",
    "prism",
    "adoptium.net",
)

# ---------------------------------------------------------------------------
# 4. Dangerous JVM Bytecode / API Symbols (Detected inside .class Constant Pool)
# ---------------------------------------------------------------------------
JVM_SUSPICIOUS_API_SYMBOLS: dict[str, tuple[str, str]] = {
    "java/awt/Robot": ("HIGH", "Java Robot input synthesis (AutoClicker/Macro)"),
    "com/sun/tools/attach/VirtualMachine": ("CRITICAL", "Dynamic JVM Attach injector capability"),
    "sun/tools/attach/": ("CRITICAL", "Low-level JVM Attach API"),
    "java/lang/instrument/Instrumentation": ("CRITICAL", "JVM Instrumentation / Class retransformation"),
    "retransformClasses": ("HIGH", "Runtime bytecode retransformation"),
    "redefineClasses": ("HIGH", "Runtime bytecode redefinition"),
    "sun/misc/Unsafe": ("MEDIUM", "Unsafe memory/class manipulation"),
    "jdk/internal/misc/Unsafe": ("MEDIUM", "Internal Unsafe memory/class manipulation"),
    "defineAnonymousClass": ("HIGH", "Hidden anonymous class loading"),
    "defineHiddenClass": ("HIGH", "Java 15+ hidden class injection"),
    "java/lang/System.loadLibrary": ("MEDIUM", "Native JNI library loading"),
    "java/lang/System.load": ("HIGH", "Absolute-path native .so/.dll loading"),
}

# Known Java obfuscator / packer markers in Constant Pool / Manifest / Class names
OBFUSCATOR_MARKERS: tuple[str, ...] = (
    "Allatori",
    "ZKM",
    "Zelix",
    "Stringer",
    "DashO",
    "Paramorphism",
    "Skidfuscator",
    "Branchlock",
    "Binscure",
    "Radon",
    "Bozer",
    "jnic",
    "JNICLoader",
    "dev/jnic/",
)

# ---------------------------------------------------------------------------
# 5. Native ELF / JNI / Input Injection Symbols
# ---------------------------------------------------------------------------
ELF_CHEAT_OR_INJECT_SYMBOLS: dict[str, tuple[str, str]] = {
    "Agent_OnLoad": ("CRITICAL", "JVMTI native agent entry point"),
    "Agent_OnAttach": ("CRITICAL", "JVMTI dynamic attach entry point"),
    "XTestFakeButtonEvent": ("CRITICAL", "X11 synthetic mouse/key click injection"),
    "XTestFakeKeyEvent": ("HIGH", "X11 synthetic key injection"),
    "ptrace": ("HIGH", "Process tracing / memory injection syscall"),
    "process_vm_writev": ("CRITICAL", "Cross-process memory write syscall"),
    "process_vm_readv": ("HIGH", "Cross-process memory read syscall"),
    "glXSwapBuffers": ("MEDIUM", "OpenGL swap hook symbol (ESP/Overlay injection)"),
    "eglSwapBuffers": ("MEDIUM", "EGL swap hook symbol (Wayland/GL overlay injection)"),
    "uinput": ("HIGH", "Linux kernel virtual input device reference"),
}

# ---------------------------------------------------------------------------
# 6. Macro / Autoclicker Process & Binary Names
# ---------------------------------------------------------------------------
MACRO_PROCESS_NAMES: frozenset[str] = frozenset(
    {
        "xclicker",
        "xdotool",
        "ydotool",
        "ydotoold",
        "dotool",
        "dotoold",
        "wtype",
        "evtest",
        "autokey",
        "autokey-gtk",
        "autokey-qt",
        "input-remapper-service",
        "input-remapper-gtk",
        "input-remapper-control",
        "clicker",
        "autoclicker",
        "tinytask",
        "opautoclicker",
        "gsautoclicker",
    }
)

HARDWARE_CONFIG_APPS: frozenset[str] = frozenset(
    {
        "piper",
        "ratbagd",
        "ratbagctl",
        "solaar",
        "openrazer-daemon",
        "polychromatic",
        "polychromatic-controller",
        "ckb-next",
        "rivalcfg",
    }
)

# ---------------------------------------------------------------------------
# 7. Anti-Forensic Shell / Wipe Commands
# ---------------------------------------------------------------------------
ANTI_FORENSIC_CMD_RE = re.compile(
    r"(?:^|\s|;|&&|\|)(?:/(?:usr/)?bin/)?(?:"
    r"shred\b|srm\b|wipe\b|bleachbit\b|"
    r"history\s+(?:-c|-w|-d\b)|unset\s+HISTFILE|HISTSIZE=0|HISTFILESIZE=0|HISTFILE=/dev/null|"
    r"set\s+\+o\s+history|kill\s+-9\s+\$\$|"
    r"truncate\s+-s\s*0\b|"
    r"(?:(?::\s*|(?:cat|cp)\s+/dev/null\s*)?>\s*)[^\n;|&]*?(?:\.?(?:bash_history|zsh_history|fish_history)|minecraft/logs|recently-used\.xbel)|"
    r"(?:rm\s+(?:-[a-zA-Z]+\s+)*|unlink\s+)[^\n;|&]*?(?:\.minecraft|PrismLauncher|lunarclient|\bmods\b|\blogs\b|Trash|recently-used|klipper|History|places\.sqlite|\.bash_history|\.zsh_history|\.fish_history)|"
    r"touch\s+-(?:d|t|r)\b|"
    r"journalctl\s+--(?:vacuum|rotate)|"
    r"sqlite3\s+[^\n;|&]*?(?:History|places\.sqlite)[^\n;|&]*?DELETE|"
    r"setfattr\s+-x\s+user\.xdg\.origin\.url|"
    r"swapoff\b"
    r")",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# 8. Legitimate Minecraft / Linux Allowlists (Noise Suppression)
# ---------------------------------------------------------------------------
LEGIT_TMP_SO_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^liblwjgl[^/]*\.so$"),
    re.compile(r"^libopenal[^/]*\.so$"),
    re.compile(r"^libglfw[^/]*\.so$"),
    re.compile(r"^libjemalloc[^/]*\.so$"),
    re.compile(r"^libjinput[^/]*\.so$"),
    re.compile(r"^libzstd-jni[^/]*\.so$"),
    re.compile(r"^sqlite-[0-9a-f.-]+-libsqlitejdbc\.so$"),
    re.compile(r"^jna[0-9]+\.tmp$"),
    re.compile(r"^libjansi[^/]*\.so$"),
    re.compile(r"^librocksdbjni[^/]*\.so$"),
    re.compile(r"^libopus[^/]*\.so$"),
    re.compile(r"^libwebrtc[^/]*\.so$"),
)

LEGIT_JAVA_PREFIXES: tuple[str, ...] = (
    "java/",
    "javax/",
    "sun/",
    "jdk/",
    "com/sun/",
    "net/minecraft/",
    "com/mojang/",
    "org/lwjgl/",
    "io/netty/",
    "com/google/",
    "org/apache/",
    "org/slf4j/",
    "net/fabricmc/",
    "net/minecraftforge/",
    "net/neoforged/",
    "org/spongepowered/",
    "me/jellysquid/mods/sodium/",
    "net/caffeinemc/mods/sodium/",
    "net/coderbot/iris/",
    "net/irisshaders/",
)

# Solid opaque blocks that MUST NOT contain transparent pixels in legitimate packs
XRAY_SENSITIVE_BLOCK_TEXTURES: frozenset[str] = frozenset(
    {
        "stone.png",
        "deepslate.png",
        "deepslate_top.png",
        "netherrack.png",
        "dirt.png",
        "coarse_dirt.png",
        "sand.png",
        "red_sand.png",
        "gravel.png",
        "cobblestone.png",
        "cobbled_deepslate.png",
        "andesite.png",
        "diorite.png",
        "granite.png",
        "tuff.png",
        "basalt_side.png",
        "basalt_top.png",
        "smooth_basalt.png",
        "end_stone.png",
        "blackstone.png",
        "terracotta.png",
        "obsidian.png",
        "bedrock.png",
        "oak_planks.png",
        "spruce_planks.png",
        "grass_block_top.png",
        "grass_block_side.png",
        "clay.png",
        "calcite.png",
        "dripstone_block.png",
        "mud.png",
        "packed_mud.png",
    }
)

# Spoofed popular mod filenames -> expected mod IDs or package fragments
POPULAR_MOD_IDENTITY_MAP: dict[str, tuple[str, ...]] = {
    "sodium": ("sodium", "jellysquid", "caffeinemc"),
    "iris": ("iris", "coderbot", "irisshaders"),
    "lithium": ("lithium", "jellysquid", "caffeinemc"),
    "optifine": ("optifine", "net/optifine"),
    "fabric-api": ("fabric-api", "fabricmc"),
    "modmenu": ("modmenu", "terraformersmc"),
    "ferritecore": ("ferritecore", "malte0811"),
    "entityculling": ("entityculling", "tr7zw"),
    "immediatelyfast": ("immediatelyfast", "florianmichael", "rk_01"),
    "voicechat": ("voicechat", "henkelmax"),
    "replaymod": ("replaymod",),
    "appleskin": ("appleskin", "squeek502"),
    "jei": ("jei", "mezz"),
    "rei": ("roughlyenoughitems", "shedaniel"),
    "xaero": ("xaero",),
    "journeymap": ("journeymap",),
}

MOJANG_AND_STANDARD_DOMAINS: tuple[str, ...] = (
    "minecraft.net",
    "mojang.com",
    "minecraftservices.com",
    "xboxlive.com",
    "live.com",
    "microsoft.com",
    "lunarclient.com",
    "badlion.net",
    "modrinth.com",
    "curseforge.com",
)
