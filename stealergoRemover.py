# made by cs38 to remove leproxy's "StealerGo" rat based off his code
# this works by checking the same file names install paths reg keys startup links scheduled tasks and dropped dlls his source uses
# it tries to kill the rat if its running then removes the persistence and cleans the files it knows stealergo drops
# for the system32 dlls it only removes them if the file name and exact size match the embedded dlls from his loader so it doesnt just nuke random files


# how 2 use:

# python stealergoRemover.py
# runs the remover for real and deletes whatever stealergo stuff it finds

# python stealergoRemover.py --dry-run
# scan only mode shows what it would remove without actually changing anything

# python stealergoRemover.py --repair-devices
# same cleanup as normal but also tries to re enable network adapters and usb/hid stuff if the rat disabled them


# thx
# leproxy stop ratting
# dork

from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
import winreg


FILE_ATTRIBUTE_NORMAL = 0x80
DELETE_VALUE = 0x0002
KEY_READ_64 = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
KEY_SET_VALUE_64 = winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
KEY_QUERY_VALUE_64 = winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
POLICIES_SYSTEM_KEY = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
WINLOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

RUN_VALUE_CANONICAL = "SystemHelper"
DISABLE_TASKMGR_VALUE = "DisableTaskMgr"
WINLOGON_SHELL_VALUE = "Shell"

SCHEDULED_TASKS = ("SystemHelper", "WindowsCacheSync")
TARGET_PROCESSES = (
    "systemhelper.exe",
    "win_ext_cache.exe",
    "stealer-loader.exe",
    "InputSwitchToastHandler.exe",
)

SYSTEM32_DLL_SIZES = {
    "zlib1.dll": 90624,
    "sqlite3.dll": 1075200,
    "libsodium.dll": 344064,
    "libcurl.dll": 596480,
}


def _kernel32() -> ctypes.WinDLL:
    return ctypes.WinDLL("kernel32", use_last_error=True)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


@dataclass
class ActionResult:
    kind: str
    target: str
    status: str
    detail: str = ""


class StealerGoRemover:
    def __init__(self, dry_run: bool = False, repair_devices: bool = False) -> None:
        self.dry_run = dry_run
        self.repair_devices = repair_devices
        self.results: list[ActionResult] = []

        self.system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        self.appdata = Path(os.environ.get("APPDATA", ""))
        self.local_appdata = Path(os.environ.get("LOCALAPPDATA", ""))
        self.program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        self.system32 = self.system_root / "System32"

        self.known_files = (
            self.appdata / "Microsoft" / "systemhelper.exe",
            self.local_appdata / "Microsoft" / "Windows" / "Caches" / "win_ext_cache.exe",
            self.appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "systemhelper.lnk",
            self.program_data / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp" / "systemhelper.lnk",
        )

    def add(self, kind: str, target: str, status: str, detail: str = "") -> None:
        self.results.append(ActionResult(kind=kind, target=target, status=status, detail=detail))

    def run_command(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace")

    def process_exists(self, image_name: str) -> bool:
        proc = self.run_command(["tasklist", "/FI", f"IMAGENAME eq {image_name}"])
        output = (proc.stdout or "") + (proc.stderr or "")
        return image_name.lower() in output.lower()

    def task_exists(self, task_name: str) -> tuple[bool, str]:
        proc = self.run_command(["schtasks", "/Query", "/TN", task_name])
        output = ((proc.stdout or "") + (proc.stderr or "")).strip()
        if proc.returncode == 0:
            return True, output
        if "cannot find" in output.lower():
            return False, output
        return False, output

    def set_normal_attributes(self, path: Path) -> None:
        kernel32 = _kernel32()
        kernel32.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
        kernel32.SetFileAttributesW.restype = ctypes.c_int
        kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_NORMAL)

    def remove_file(self, path: Path) -> None:
        target = str(path)
        if not path.exists():
            self.add("file", target, "not_found")
            return

        if self.dry_run:
            self.add("file", target, "would_remove")
            return

        try:
            self.set_normal_attributes(path)
        except Exception:
            pass

        try:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            self.add("file", target, "removed")
        except Exception as exc:
            self.add("file", target, "error", str(exc))

    def remove_if_empty(self, path: Path, stop_at: Path) -> None:
        current = path
        while current != stop_at and current.exists():
            try:
                current.rmdir()
                self.add("directory", str(current), "removed_empty")
                current = current.parent
            except OSError:
                break

    def kill_processes(self) -> None:
        for image_name in TARGET_PROCESSES:
            if not self.process_exists(image_name):
                self.add("process", image_name, "not_found")
                continue

            if self.dry_run:
                self.add("process", image_name, "would_kill")
                continue

            proc = self.run_command(["taskkill", "/F", "/IM", image_name])
            output = ((proc.stdout or "") + (proc.stderr or "")).strip()
            if proc.returncode == 0:
                self.add("process", image_name, "killed", output)
            else:
                self.add("process", image_name, "error", output or f"taskkill exited with {proc.returncode}")

    def _registry_matches(self, hive: int, subkey: str, expected_name_lower: str) -> list[str]:
        matches: list[str] = []
        try:
            with winreg.OpenKey(hive, subkey, 0, KEY_QUERY_VALUE_64) as key:
                value_count = winreg.QueryInfoKey(key)[1]
                for index in range(value_count):
                    value_name, _, _ = winreg.EnumValue(key, index)
                    if value_name.lower() == expected_name_lower:
                        matches.append(value_name)
        except FileNotFoundError:
            return []
        except OSError:
            return []
        return matches

    def _delete_registry_value(self, hive: int, subkey: str, value_name: str, label: str) -> None:
        target = f"{label}\\{subkey}\\{value_name}"
        matches = self._registry_matches(hive, subkey, value_name.lower())
        if not matches:
            self.add("registry", target, "not_found")
            return

        if self.dry_run:
            self.add("registry", target, "would_remove", f"matched values: {', '.join(matches)}")
            return

        try:
            with winreg.OpenKey(hive, subkey, 0, KEY_SET_VALUE_64 | DELETE_VALUE) as key:
                for actual_name in matches:
                    winreg.DeleteValue(key, actual_name)
            self.add("registry", target, "removed", f"removed values: {', '.join(matches)}")
        except PermissionError as exc:
            self.add("registry", target, "error", f"permission denied: {exc}")
        except OSError as exc:
            self.add("registry", target, "error", str(exc))

    def remove_run_values(self) -> None:
        for hive, label in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
            self._delete_registry_value(hive, RUN_KEY, RUN_VALUE_CANONICAL, label)

    def repair_taskmgr_policy(self) -> None:
        for hive, label in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
            self._delete_registry_value(hive, POLICIES_SYSTEM_KEY, DISABLE_TASKMGR_VALUE, label)

    def repair_winlogon_shell(self) -> None:
        target = f"HKLM\\{WINLOGON_KEY}\\{WINLOGON_SHELL_VALUE}"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WINLOGON_KEY, 0, KEY_READ_64) as key:
                shell_value, _ = winreg.QueryValueEx(key, WINLOGON_SHELL_VALUE)
        except FileNotFoundError:
            self.add("registry", target, "not_found")
            return
        except PermissionError as exc:
            self.add("registry", target, "error", f"permission denied while reading: {exc}")
            return
        except OSError as exc:
            self.add("registry", target, "error", str(exc))
            return

        if isinstance(shell_value, str) and shell_value.strip():
            self.add("registry", target, "unchanged", f"current value: {shell_value}")
            return

        if self.dry_run:
            self.add("registry", target, "would_repair", "blank shell would be reset to explorer.exe")
            return

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WINLOGON_KEY, 0, KEY_SET_VALUE_64) as key:
                winreg.SetValueEx(key, WINLOGON_SHELL_VALUE, 0, winreg.REG_SZ, "explorer.exe")
            self.add("registry", target, "repaired", "restored explorer.exe")
        except PermissionError as exc:
            self.add("registry", target, "error", f"permission denied while writing: {exc}")
        except OSError as exc:
            self.add("registry", target, "error", str(exc))

    def remove_scheduled_tasks(self) -> None:
        for task_name in SCHEDULED_TASKS:
            exists, detail = self.task_exists(task_name)
            if not exists and "access is denied" not in detail.lower():
                self.add("task", task_name, "not_found")
                continue

            if self.dry_run:
                self.add("task", task_name, "would_remove", detail)
                continue

            proc = self.run_command(["schtasks", "/Delete", "/TN", task_name, "/F"])
            output = ((proc.stdout or "") + (proc.stderr or "")).strip()
            if proc.returncode == 0:
                self.add("task", task_name, "removed", output)
            else:
                self.add("task", task_name, "error", output or f"schtasks exited with {proc.returncode}")

    def remove_known_files(self) -> None:
        for path in self.known_files:
            self.remove_file(path)

        self.remove_if_empty(self.local_appdata / "Microsoft" / "Windows" / "Caches", self.local_appdata / "Microsoft")

    def remove_loader_system32_dlls(self) -> None:
        for filename, expected_size in SYSTEM32_DLL_SIZES.items():
            path = self.system32 / filename
            target = str(path)
            if not path.exists():
                self.add("dll", target, "not_found")
                continue

            try:
                actual_size = path.stat().st_size
            except OSError as exc:
                self.add("dll", target, "error", str(exc))
                continue

            if actual_size != expected_size:
                self.add(
                    "dll",
                    target,
                    "skipped",
                    f"size {actual_size} does not match StealerGo embedded size {expected_size}",
                )
                continue

            if self.dry_run:
                self.add("dll", target, "would_remove", f"matched embedded size {expected_size}")
                continue

            try:
                self.set_normal_attributes(path)
            except Exception:
                pass

            try:
                path.unlink()
                self.add("dll", target, "removed", f"matched embedded size {expected_size}")
            except Exception as exc:
                self.add("dll", target, "error", str(exc))

    def repair_boot_flags(self) -> None:
        target = ""
        output = ""
        for identifier in ("{default}", "{current}"):
            proc = self.run_command(["bcdedit", "/enum", identifier])
            candidate = ((proc.stdout or "") + (proc.stderr or "")).strip()
            if proc.returncode == 0:
                target = f"BCDEdit {identifier}"
                output = candidate
                break
            output = candidate

        if not target:
            self.add("boot", "BCDEdit", "skipped", output or "unable to query boot configuration")
            return

        output_lower = output.lower()
        need_recovery_fix = "recoveryenabled" in output_lower and "recoveryenabled          no" in output_lower
        need_bootstatus_fix = "bootstatuspolicy" in output_lower and "displayallfailures" in output_lower

        if not need_recovery_fix and not need_bootstatus_fix:
            self.add("boot", target, "unchanged")
            return

        if self.dry_run:
            detail_parts = []
            if need_recovery_fix:
                detail_parts.append("would set recoveryenabled to Yes")
            if need_bootstatus_fix:
                detail_parts.append("would delete bootstatuspolicy")
            self.add("boot", target, "would_repair", "; ".join(detail_parts))
            return

        if need_recovery_fix:
            identifier = target.split()[-1]
            repair = self.run_command(["bcdedit", "/set", identifier, "recoveryenabled", "Yes"])
            repair_output = ((repair.stdout or "") + (repair.stderr or "")).strip()
            if repair.returncode == 0:
                self.add("boot", target, "repaired", "set recoveryenabled to Yes")
            else:
                self.add("boot", target, "error", repair_output or "failed to set recoveryenabled")

        if need_bootstatus_fix:
            identifier = target.split()[-1]
            repair = self.run_command(["bcdedit", "/deletevalue", identifier, "bootstatuspolicy"])
            repair_output = ((repair.stdout or "") + (repair.stderr or "")).strip()
            if repair.returncode == 0:
                self.add("boot", target, "repaired", "deleted bootstatuspolicy")
            else:
                self.add("boot", target, "error", repair_output or "failed to delete bootstatuspolicy")

    def repair_devices_if_requested(self) -> None:
        if not self.repair_devices:
            return

        ps_network = (
            "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Status -eq 'Disabled' } | "
            "Enable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue"
        )
        ps_pnp = (
            "Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Status -ne 'OK' -and $_.Class -in @('USB','HIDClass','Keyboard','Mouse') } | "
            "Enable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue"
        )

        for label, script in (
            ("network adapters", ps_network),
            ("USB/HID devices", ps_pnp),
        ):
            if self.dry_run:
                self.add("repair", label, "would_run", script)
                continue

            proc = self.run_command(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script])
            output = ((proc.stdout or "") + (proc.stderr or "")).strip()
            if proc.returncode == 0:
                self.add("repair", label, "completed", output)
            else:
                self.add("repair", label, "error", output or f"PowerShell exited with {proc.returncode}")

    def execute(self) -> list[ActionResult]:
        if not is_admin():
            self.add(
                "warning",
                "privileges",
                "limited",
                "Not running as administrator. HKLM, System32, scheduled task, BCDEdit, and some process cleanup may fail.",
            )

        self.kill_processes()
        self.remove_scheduled_tasks()
        self.remove_run_values()
        self.repair_taskmgr_policy()
        self.repair_winlogon_shell()
        self.repair_boot_flags()
        self.remove_known_files()
        self.remove_loader_system32_dlls()
        self.repair_devices_if_requested()
        return self.results


def summarize(results: Iterable[ActionResult]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for result in results:
        summary[result.status] = summary.get(result.status, 0) + 1
    return summary


def print_results(results: list[ActionResult], as_json: bool) -> int:
    if as_json:
        print(json.dumps([asdict(result) for result in results], indent=2))
    else:
        for result in results:
            line = f"[{result.status}] {result.kind}: {result.target}"
            if result.detail:
                line += f" :: {result.detail}"
            print(line)

        counts = summarize(results)
        print()
        print("Summary:")
        for status in sorted(counts):
            print(f"  {status}: {counts[status]}")

    return 1 if any(result.status == "error" for result in results) else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Remove StealerGo persistence and common artifacts.")
    parser.add_argument(
        "--dry-run",
        "--scan-only",
        action="store_true",
        dest="dry_run",
        help="Report what would be removed without changing the system.",
    )
    parser.add_argument(
        "--repair-devices",
        action="store_true",
        help="Also try to re-enable disabled network adapters and USB/HID devices.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit results as JSON.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    remover = StealerGoRemover(dry_run=args.dry_run, repair_devices=args.repair_devices)
    results = remover.execute()
    return print_results(results, as_json=args.json)


if __name__ == "__main__":
    sys.exit(main())
