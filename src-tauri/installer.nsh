; Tauri NSIS hooks for the `tervia` CLI launcher + user-data safety net.
;
; Binary layout in $INSTDIR after install:
;   TerviaApp.exe   GUI subsystem — the actual app. Named so PATHEXT does NOT
;                 resolve `tervia` to it; the user-facing entry point is the
;                 console stub below.
;   tervia.exe      console subsystem — built from tervia-cli/src/main.rs. This is
;                 what PowerShell / cmd invoke when the user types `tervia`.
;                 Dispatches `--help` / `--version` inline, runs `--update`
;                 synchronously with inherited stdio, detaches
;                 GUI launches. Fixes the long-standing PowerShell-doesn't-
;                 wait-for-GUI ordering bug where `tervia --help` printed
;                 below the next prompt and left the cursor garbled.
;
; On install:
;   * Snapshot the user's app-data dir (history, settings, sessions, ...)
;     to %TEMP% before the rest of the installer (or the
;     previous uninstaller, which auto-update invokes in passive mode) gets
;     a chance to touch it. PREINSTALL runs before any file deletion.
;   * Drop `tervia.exe` (console stub) next to `TerviaApp.exe` via NSIS File
;     directive. Path is relative to the generated installer.nsi at
;     `<src-tauri>/target/release/bundle/nsis/<lang>/`.
;   * Append the install dir to the user's PATH (HKCU\Environment) if not
;     already present, then broadcast WM_SETTINGCHANGE so freshly-spawned
;     shells pick it up without a logout. Through PowerShell, not NSIS
;     registry instructions - NSIS cannot hold a PATH longer than 1024
;     characters and mangles it on the way through.
;   * Restore the user-data snapshot when key files vanished during the
;     install. Belt-and-suspenders against Tauri NSIS template variants
;     that wipe app data on upgrade.
;
; On uninstall we delete the binary-as-data we wrote (`tervia.exe`) but
; deliberately leave the PATH entry alone: a stale entry to a non-existent dir
; is harmless (Windows skips it during PATH lookup), while every write to that
; value is a chance to corrupt the user's PATH, and auto-update runs the old
; uninstaller mid-flight.

!include "LogicLib.nsh"
!include "WinMessages.nsh"

; PowerShell-provider form of the user environment key. The PATH append runs
; through PowerShell rather than NSIS registry instructions - see the block in
; NSIS_HOOK_POSTINSTALL for why.
!define TERVIA_ENV_REG_PS "HKCU:\Environment"

; --- "Open with Tervia" shell verbs -----------------------------------------
; Explorer builds a context menu from static verbs under
; <root>\shell\<verb>, so registering under HKCU\Software\Classes gives the
; whole thing without an elevated installer (installMode is currentUser).
; Four roots, because Explorer treats them as unrelated:
;   Directory             right-click ON a folder
;   Directory\Background  right-click on empty space INSIDE a folder
;   Drive                 right-click on a drive root (C:\, D:\, ...)
;   *                     right-click on any file
;
; `%V` is the folder the menu was raised on and is the only field code the
; Background root understands; `*` has no `%V`, so files use `%1`.
;
; The command points at TerviaApp.exe, NOT the tervia.exe console stub: the stub
; is console-subsystem and would flash a console window on every click.
; TerviaApp.exe already resolves a positional path via `cli::capture_startup`
; and forwards it to a running instance through single-instance, so one click
; either boots Tervia at that path or opens a tab in the window already up.
;
; Windows 11 note: these are classic verbs, so they appear under
; "Show more options" (Shift+F10) rather than the trimmed default menu.
; Top-level placement needs an IExplorerCommand COM handler shipped from a
; packaged (MSIX/sparse) app - the same limitation VS Code's "Open with Code"
; lives with.
!define TERVIA_VERB "Tervia"
!define TERVIA_VERB_LABEL "Open with Tervia"

; Write one shell verb. `_root` is the class root, `_arg` the field code.
!macro TerviaWriteVerb _root _arg
  WriteRegStr HKCU "Software\Classes\${_root}\shell\${TERVIA_VERB}" "" "${TERVIA_VERB_LABEL}"
  WriteRegStr HKCU "Software\Classes\${_root}\shell\${TERVIA_VERB}" "Icon" '"$INSTDIR\TerviaApp.exe",0'
  WriteRegStr HKCU "Software\Classes\${_root}\shell\${TERVIA_VERB}\command" "" '"$INSTDIR\TerviaApp.exe" "${_arg}"'
!macroend

!macro TerviaDeleteVerb _root
  DeleteRegKey HKCU "Software\Classes\${_root}\shell\${TERVIA_VERB}"
!macroend

; --- "Open with" app-picker entry -----------------------------------------
; Separate mechanism from the shell verbs above, and easy to conflate: the
; verbs put a top-level "Open with Tervia" line on the menu, while Explorer
; builds the "Open with >" submenu from apps registered under
; Software\Classes\Applications\<exe>. Registering only the verbs leaves
; Tervia absent from that submenu even though its own line is right there on
; the same menu.
;
; A shell\open\command is the whole registration - this is what VS Code
; ships and nothing more. No SupportedTypes (the app opens anything) and no
; FriendlyAppName: Explorer falls back to the exe's FileDescription, which
; the Tauri bundler already stamps as "Tervia".
!define TERVIA_APP_KEY "Software\Classes\Applications\TerviaApp.exe"

; App-data dir must match `identifier` in tauri.conf.json. Tauri 2's
; `app_data_dir` resolves to `%APPDATA%\<identifier>\` on Windows. The
; backup lives in %TEMP% so it disappears on reboot even if a restore is
; somehow skipped — never accumulates stale snapshots.
!define TERVIA_DATA_DIR    "$APPDATA\dev.rendy.tervia"
!define TERVIA_DATA_BACKUP "$TEMP\tervia-userdata-backup"

!macro NSIS_HOOK_PREINSTALL
  ; --- snapshot user data --------------------------------------------------
  ; Only snapshot when there's something to save; a fresh install has no
  ; data dir and we don't want to seed an empty backup that the post-hook
  ; would then "restore" over a clean install.
  IfFileExists "${TERVIA_DATA_DIR}\*.*" 0 tervia_preinstall_no_backup
    ; Wipe any previous backup so a re-run starts clean.
    RMDir /r "${TERVIA_DATA_BACKUP}"
    ; xcopy ships with Windows; /E recursive, /I treat target as dir,
    ; /Y silent overwrite, /H copy hidden + system, /K preserve attrs,
    ; /Q quiet. nul redirection suppresses console output during /PASSIVE.
    nsExec::ExecToLog 'cmd /c xcopy "${TERVIA_DATA_DIR}" "${TERVIA_DATA_BACKUP}" /E /I /Y /H /K /Q >nul 2>&1'
    ; nsExec pushes the exit code whether or not you want it. Leaving it on
    ; the stack corrupts whatever the Tauri template pops next.
    Pop $0
  tervia_preinstall_no_backup:
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; --- install tervia.exe (console-subsystem launcher) -----------------------
  ; TerviaApp.exe is `windows_subsystem = "windows"`; PowerShell does not
  ; synchronously wait for GUI-subsystem children, so `tervia --help` output
  ; lands after the next prompt and the cursor ends up mid-line. tervia.exe
  ; is a console-subsystem twin from tervia-cli/src/main.rs that PowerShell
  ; waits for properly. PATHEXT then resolves the user's `tervia` to this
  ; binary instead of the GUI (the GUI is renamed TerviaApp.exe specifically
  ; to keep it off PATHEXT's `tervia.exe` lookup).
  ;
  ; The release workflow builds the stub via an explicit
  ; `cargo build --release -p tervia-cli` step (see
  ; .github/workflows/release.yml), so by the time NSIS runs the file is at
  ; <src-tauri>/target/release/tervia.exe. The Tauri 2.11 NSIS bundler emits
  ; `installer.nsi` at `<src-tauri>/target/release/bundle/nsis/installer.nsi`
  ; (NO per-language subdirectory — earlier versions of this comment claimed
  ; otherwise and shipped `..\..\..\tervia.exe`, which resolved one level too
  ; high to `target/tervia.exe`. `/nonfatal` then swallowed the missing-file
  ; error and the installer silently shipped without the launcher, leaving
  ; the user with "'tervia' is not recognized as an internal or external
  ; command"). Two dots up = bundle/, three dots = the bundle/nsis sibling
  ; level we don't want, two dots is correct: `..\..\` lands at
  ; target/release/.
  ;
  ; Drop /nonfatal so a missing tervia.exe FAILS the installer build instead
  ; of producing a broken installer. The launcher is now load-bearing for
  ; every CLI subcommand (`tervia --help`, `tervia --version`, etc.) so a missing
  ; binary is not a degradation — it is a complete CLI outage.
  SetOutPath "$INSTDIR"
  File "/oname=tervia.exe" "..\..\tervia.exe"

  ; --- ensure install dir is on user PATH ---------------------------------
  ; NEVER read PATH with ReadRegStr. NSIS_MAX_STRLEN is 1024, and on a longer
  ; value ReadRegStr does not return a truncated string - it returns an EMPTY
  ; one plus the error flag. The old code read that as "user has no PATH yet"
  ; and wrote `Path = $INSTDIR`, destroying every entry the user had. Measured
  ; against the NSIS 3.08 the Tauri bundler ships: a 1023-char PATH reads fine,
  ; 1024 comes back empty, and a 1573-char one came back out as 32 chars of
  ; install dir. Any dev machine clears that easily. Just under the
  ; limit the concatenation truncated instead, appending half a directory as a
  ; junk PATH entry. Both failure modes are silent.
  ;
  ; .NET's RegistryKey has no length limit, so the whole read-modify-write
  ; runs in PowerShell. DoNotExpandEnvironmentNames keeps `%VAR%` entries
  ; literal so they are written back unexpanded, -Type ExpandString preserves
  ; REG_EXPAND_SZ, and -notcontains is a literal case-insensitive element
  ; compare so reinstalls don't pile up dupes and a `[` in a path can't be
  ; read as a wildcard. Set-ItemProperty creates the value when absent.
  ;
  ; $INSTDIR travels in an env var rather than being interpolated into the
  ; script text: the directory page lets the user pick a path containing an
  ; apostrophe, which would otherwise break the PowerShell string literal.
  ;
  ; powershell.exe is invoked by absolute path, not resolved through PATH -
  ; PATH is the one thing this block cannot assume is sane, and an absolute
  ; path also removes the "rogue powershell.exe earlier in PATH" hijack from a
  ; signed installer. $SYSDIR is WOW64-redirected to SysWOW64 for the 32-bit
  ; NSIS stub, which carries its own copy. No -ExecutionPolicy: it governs
  ; script FILES, not -Command (verified under both Restricted and AllSigned),
  ; and `-ExecutionPolicy Bypass` in an installer is a stock AV heuristic.
  ; ErrorActionPreference Stop means any failure exits non-zero having written
  ; nothing - Tervia not being on PATH beats corrupting it - and -NonInteractive
  ; keeps an unattended auto-update from ever blocking on a prompt.
  ;
  ; `exit 3` marks "PATH actually changed" so the broadcast below stays
  ; conditional; auto-update re-runs this hook on every release and
  ; HWND_BROADCAST blocks on each unresponsive top-level window.
  System::Call 'kernel32::SetEnvironmentVariable(t "TERVIA_INSTDIR", t "$INSTDIR") i'
  nsExec::ExecToLog `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$$ErrorActionPreference = 'Stop'; $$k = Get-Item -LiteralPath '${TERVIA_ENV_REG_PS}'; $$p = [string]$$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); $$d = $$env:TERVIA_INSTDIR; if ($$d -and (($$p -split ';') -notcontains $$d)) { $$n = if ($$p -eq '') { $$d } else { $$p.TrimEnd(';') + ';' + $$d }; Set-ItemProperty -LiteralPath '${TERVIA_ENV_REG_PS}' -Name Path -Value $$n -Type ExpandString; exit 3 }"`
  Pop $1
  ${If} $1 == 3
    SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000
  ${EndIf}

  ; --- "Open with Tervia" context-menu entries -------------------------------
  ; See the TerviaWriteVerb definition above for why there are four roots and
  ; why the command targets TerviaApp.exe rather than the tervia.exe stub.
  !insertmacro TerviaWriteVerb "Directory" "%V"
  !insertmacro TerviaWriteVerb "Directory\Background" "%V"
  !insertmacro TerviaWriteVerb "Drive" "%V"
  !insertmacro TerviaWriteVerb "*" "%1"

  ; --- "Open with > Tervia" app-picker entry ---------------------------------
  WriteRegStr HKCU "${TERVIA_APP_KEY}\DefaultIcon" "" '"$INSTDIR\TerviaApp.exe",0'
  WriteRegStr HKCU "${TERVIA_APP_KEY}\shell\open\command" "" '"$INSTDIR\TerviaApp.exe" "%1"'

  ; --- restore user data ---------------------------------------------------
  ; If PREINSTALL took a snapshot, copy it back. Two key files (settings +
  ; sessions) gate the restore — if either is missing post-install we
  ; assume the install flow wiped the dir and replay the snapshot. /Y
  ; forces overwrite so the pre-install state always wins; the new Tervia
  ; hasn't started yet, so nothing in the data dir is worth keeping. On a
  ; clean install the backup never existed and this is a no-op.
  IfFileExists "${TERVIA_DATA_BACKUP}\*.*" 0 tervia_postinstall_no_restore
    StrCpy $5 "0"
    IfFileExists "${TERVIA_DATA_DIR}\tervia-settings.json" +2 0
      StrCpy $5 "1"
    IfFileExists "${TERVIA_DATA_DIR}\tervia-workspaces.json" +2 0
      StrCpy $5 "1"
    ${If} $5 == "1"
      CreateDirectory "${TERVIA_DATA_DIR}"
      nsExec::ExecToLog 'cmd /c xcopy "${TERVIA_DATA_BACKUP}" "${TERVIA_DATA_DIR}" /E /I /Y /H /K /Q >nul 2>&1'
      Pop $0
    ${EndIf}
    RMDir /r "${TERVIA_DATA_BACKUP}"
  tervia_postinstall_no_restore:
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  Delete "$INSTDIR\tervia.exe"

  ; Drop the context-menu verbs. Unlike the PATH entry (deliberately left
  ; behind - see the header note), these are ours alone and point at an
  ; $INSTDIR that is about to stop existing, so leaving them would put a
  ; dead "Open with Tervia" on every folder and file.
  ;
  ; Auto-update runs the old uninstaller in passive mode before the new
  ; install, so this fires on upgrades too - NSIS_HOOK_POSTINSTALL rewrites
  ; the verbs immediately afterwards.
  !insertmacro TerviaDeleteVerb "Directory"
  !insertmacro TerviaDeleteVerb "Directory\Background"
  !insertmacro TerviaDeleteVerb "Drive"
  !insertmacro TerviaDeleteVerb "*"
  DeleteRegKey HKCU "${TERVIA_APP_KEY}"
!macroend
