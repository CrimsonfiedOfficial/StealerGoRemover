# stealergoRemover
## hi star this
thx chatgpt for the readme and kinda forrr some parts of the code cus idk im an idiot thx


`stealergoRemover.py` is a Windows cleanup script made to remove the StealerGo RAT and its common persistence/artifacts based on the malware's source code.

It checks the exact names, install paths, registry values, scheduled tasks, startup links, and dropped helper DLLs used by StealerGo. It also has a conservative safety check for the `System32` DLLs, so it only removes them when the filename and exact embedded size match what the loader drops.

## What it targets

The script checks for and removes these known StealerGo-related items:

- `%APPDATA%\Microsoft\systemhelper.exe`
- `%LOCALAPPDATA%\Microsoft\Windows\Caches\win_ext_cache.exe`
- Startup shortcut `systemhelper.lnk` in the current user's Startup folder
- Startup shortcut `systemhelper.lnk` in the all-users Startup folder
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemHelper`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SystemHelper`
- Scheduled tasks `SystemHelper` and `WindowsCacheSync`
- Dropped loader DLLs in `C:\Windows\System32`:
  - `zlib1.dll`
  - `sqlite3.dll`
  - `libsodium.dll`
  - `libcurl.dll`

It also tries to clean or repair a few system changes the RAT can make:

- `DisableTaskMgr` policy value
- Blank `Winlogon\Shell` value
- Boot flags changed by the malware's boot crash routine
- Optional re-enable of network adapters and USB/HID devices

## Requirements

- Windows
- Python 3
- Administrator privileges recommended

The script can run without admin, but system-level cleanup like `HKLM`, scheduled tasks, `System32`, and some repair steps may fail or be skipped.

## Usage

Run the remover normally:

```powershell
python stealergoRemover.py
```

Scan only mode:

```powershell
python stealergoRemover.py --dry-run
```

`--dry-run` shows what the script would remove without changing anything.

Cleanup plus device repair:

```powershell
python stealergoRemover.py --repair-devices
```

`--repair-devices` runs the normal cleanup and also tries to re-enable network adapters plus USB/HID devices if the RAT disabled them.

JSON output:

```powershell
python stealergoRemover.py --json
```

`--json` prints the results in JSON instead of the normal console summary.

You can also combine flags:

```powershell
python stealergoRemover.py --dry-run --json
python stealergoRemover.py --repair-devices --json
```

## Example output

```text
[removed] dll: C:\Windows\System32\zlib1.dll
[removed] dll: C:\Windows\System32\sqlite3.dll
[removed] dll: C:\Windows\System32\libsodium.dll
[removed] dll: C:\Windows\System32\libcurl.dll

Summary:
  removed: 4
  not_found: 14
```

## Important note

Removing the RAT does not undo data theft.

If StealerGo was executed on the machine, you should assume credentials and secrets may already be exposed. Rotate anything sensitive from a clean device, especially:

- Browser passwords and saved sessions
- Discord tokens/sessions
- Crypto wallet secrets / seed phrases / app passwords
- Telegram bot tokens or API tokens
- Any credentials stored on the infected machine

## Safety notes

- The `System32` DLL cleanup is intentionally strict and only removes DLLs that match the exact embedded sizes from the analyzed StealerGo loader.
- If you want to see exactly what would be touched first, run `--dry-run`.
- This script is focused on known StealerGo indicators from the analyzed source, not every possible modified/repacked variant.

## Disclaimer

Use this only on systems you own or have permission to clean.


```DISCORD @ CS38 FOR INQUIRIES ```
