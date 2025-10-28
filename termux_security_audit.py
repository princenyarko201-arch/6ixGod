#!/usr/bin/env python3
"""
termux_security_audit.py

A defensive, non-destructive Termux audit helper:
- Lists installed packages (pkg/dpkg)
- Checks for listening TCP ports
- Finds setuid files under common prefixes
- Looks for suspicious shell startup lines (curl|wget piping to sh)
- Lists SSH keys in $HOME/.ssh
- Reports world-writable files under the user's home directory

Designed for inspection and hardening, not for exploitation.
Run in Termux on a device you own or have permission to test.

Example:
  python3 termux_security_audit.py
"""
from __future__ import annotations
import os
import shutil
import subprocess
import sys
from pathlib import Path
import argparse
import re

HOME = Path(os.environ.get("HOME", "/data/data/com.termux/files/home"))
PREFIX = Path(os.environ.get("PREFIX", "/data/data/com.termux/files/usr"))

def run_cmd(cmd, timeout=8):
    try:
        completed = subprocess.run(cmd, shell=True, check=False, capture_output=True, text=True, timeout=timeout)
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except Exception as e:
        return 1, "", str(e)

def list_installed_packages():
    print("== Installed packages ==")
    # Prefer 'pkg list-installed' but fall back to dpkg -l if available
    if shutil.which("pkg"):
        code, out, err = run_cmd("pkg list-installed")
        if out:
            print(out)
            return
    if shutil.which("dpkg"):
        code, out, err = run_cmd("dpkg -l")
        if out:
            print(out.splitlines()[:200] if len(out.splitlines())>200 else out.splitlines())
            return
    print("Could not list packages. 'pkg' or 'dpkg' not found in PATH.\n")

def list_listening_ports():
    print("\n== Listening TCP ports ==")
    # Use ss or netstat if available
    if shutil.which("ss"):
        code, out, err = run_cmd("ss -ltn")
        if out:
            print(out)
            return
    if shutil.which("netstat"):
        code, out, err = run_cmd("netstat -ltn")
        if out:
            print(out)
            return
    print("Neither 'ss' nor 'netstat' found. Skipping port check.\n")

def find_setuid_files():
    print("\n== setuid files under common prefixes ==")
    candidates = [PREFIX, Path("/system/bin"), Path("/system/xbin"), Path("/sbin"), Path("/bin"), HOME]
    seen = set()
    for p in candidates:
        if p.exists() and p not in seen:
            seen.add(p)
            # Use find if present
            if shutil.which("find"):
                cmd = f"find {str(p)} -xdev -type f -perm -4000 -ls 2>/dev/null | head -n 50"
                code, out, err = run_cmd(cmd)
                if out:
                    print(f"setuid files under {p}:")
                    print(out)
            else:
                # Python fallback (may be slow)
                try:
                    found = []
                    for root, dirs, files in os.walk(p):
                        for name in files:
                            fp = Path(root) / name
                            try:
                                if fp.is_file():
                                    st = fp.stat()
                                    if st.st_mode & 0o4000:
                                        found.append(str(fp))
                                        if len(found) >= 50:
                                            break
                            except Exception:
                                continue
                        if len(found) >= 50:
                            break
                    if found:
                        print(f"setuid files under {p}:")
                        print("\n".join(found))
                except Exception:
                    pass

def scan_startup_for_pipe_feedback():
    print("\n== Suspicious shell startup lines (looking for 'curl|wget ... | sh') ==")
    files = [HOME / ".bashrc", HOME / ".profile", HOME / ".bash_profile", HOME / ".zshrc"]
    pattern = re.compile(r"(curl|wget|fetch).*\|\s*(sh|bash)\b", re.IGNORECASE)
    found_any = False
    for f in files:
        if f.exists():
            try:
                text = f.read_text(errors="ignore")
            except Exception:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if pattern.search(line):
                    print(f"{f}:{i}: {line.strip()}")
                    found_any = True
    if not found_any:
        print("No obvious 'curl/wget | sh' lines found in common startup files.\n")

def list_ssh_keys():
    print("\n== SSH keys in ~/.ssh ==")
    sshdir = HOME / ".ssh"
    if sshdir.exists() and sshdir.is_dir():
        keys = sorted(list(sshdir.glob("*")) , key=str)
        if keys:
            for k in keys:
                print(k)
        else:
            print("No files found in ~/.ssh")
    else:
        print("~/.ssh not present")

def find_world_writable_files(limit=100):
    print("\n== World-writable files under HOME (may be insecure) ==")
    # Use find if available
    if shutil.which("find"):
        cmd = f"find {str(HOME)} -xdev -type f -perm -002 -print 2>/dev/null | head -n {limit}"
        code, out, err = run_cmd(cmd, timeout=20)
        if out:
            print(out)
            return
        else:
            print("No world-writable files found or 'find' returned empty.")
            return
    # Python fallback (may be slow)
    found = []
    for root, dirs, files in os.walk(HOME):
        for name in files:
            fp = Path(root) / name
            try:
                st = fp.stat()
                if st.st_mode & 0o0002:
                    found.append(str(fp))
                    if len(found) >= limit:
                        break
            except Exception:
                continue
        if len(found) >= limit:
            break
    if found:
        print("\n".join(found))
    else:
        print("No world-writable files found under HOME.")

def quick_checks():
    print("Performing quick Termux environment checks...")
    # Check PATH, important env vars
    print("\n== Environment snapshot ==")
    print("HOME:", HOME)
    print("PREFIX:", PREFIX)
    print("PATH:", os.environ.get("PATH", ""))
    # Check for some suspicious binaries present in PATH
    suspects = ["nc", "ncat", "msfconsole", "meterpreter", "netcat", "adb"]
    found = []
    for s in suspects:
        if shutil.which(s):
            found.append(s)
    if found:
        print("\nFound potentially powerful network/debugging binaries in PATH (for info only):", ", ".join(found))
    else:
        print("\nNo common suspect binaries found in PATH.")

def main():
    parser = argparse.ArgumentParser(description="Termux defensive audit helper (non-destructive). Run on your own device or with permission.")
    parser.add_argument("--no-ports", action="store_true", help="skip listening ports check")
    parser.add_argument("--no-setuid", action="store_true", help="skip setuid check")
    args = parser.parse_args()

    print("Termux Security Audit (defensive)")
    print("Scan root:", HOME)
    list_installed_packages()
    if not args.no_ports:
        list_listening_ports()
    if not args.no_setuid:
        find_setuid_files()
    scan_startup_for_pipe_feedback()
    list_ssh_keys()
    find_world_writable_files()
    quick_checks()
    print("\nDone. Recommendations:")
    print("- If you find 'curl|wget | sh' lines in startup files, inspect them carefully; avoid piping remote scripts to sh.")
    print("- Remove or secure unexpected SSH keys in ~/.ssh.")
    print("- Investigate unexpected listening ports or unexpected installed packages.")
    print("- Keep Termux & packages updated: pkg update && pkg upgrade (only on trusted networks).")
    print("- For formal testing, obtain written permission and use dedicated tooling and lab environments.")

if __name__ == "__main__":
    main()