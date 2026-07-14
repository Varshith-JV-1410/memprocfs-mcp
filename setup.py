#!/usr/bin/env python3
"""
MemProcFS MCP Server - Setup Script
Automatically checks dependencies, verifies MemProcFS installation,
and provides MCP configuration for VS Code and Claude Desktop.
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path


# ─── Colors ────────────────────────────────────────────────────────────────────

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def print_colored(text, color='white', style='normal'):
    colors = {
        'green': Colors.GREEN,
        'red': Colors.RED,
        'yellow': Colors.YELLOW,
        'cyan': Colors.CYAN,
    }
    styles = {'bold': Colors.BOLD, 'normal': ''}
    print(f"{styles.get(style, '')}{colors.get(color, '')}{text}{Colors.RESET}")


def print_header(text):
    print_colored(f"\n{'=' * 70}", 'cyan')
    print_colored(f"  {text}", 'cyan', 'bold')
    print_colored(f"{'=' * 70}", 'cyan')


def print_step(num, text):
    print_colored(f"\n[{num}] {text}", 'yellow', 'bold')


def print_ok(text):
    print_colored(f"  ✓ {text}", 'green')


def print_fail(text):
    print_colored(f"  ✗ {text}", 'red')


def print_warn(text):
    print_colored(f"  ⚠ {text}", 'yellow')


def print_info(text):
    print_colored(f"  → {text}", 'cyan')


# ─── Helpers ───────────────────────────────────────────────────────────────────

def run_command(command, shell=True):
    try:
        result = subprocess.run(
            command, shell=shell, capture_output=True, text=True, timeout=30
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def get_python_executable():
    """Get the best Python 3.10+ executable."""
    # Try py launcher first
    ok, out, _ = run_command("py --list")
    if ok:
        versions = []
        for line in out.split("\n"):
            line = line.strip()
            if "-V:" in line:
                parts = line.split()
                ver_str = parts[0].replace("-V:", "")
                try:
                    major, minor = ver_str.split(".")[:2]
                    versions.append((int(major), int(minor), ver_str))
                except:
                    pass
        # Sort by version, highest first
        versions.sort(reverse=True)
        for major, minor, ver_str in versions:
            if major == 3 and minor >= 10:
                return f"py -{major}.{minor}", f"Python {ver_str}"
    
    # Try python3
    ok, out, _ = run_command("python3 --version")
    if ok and "3." in out:
        version = out.replace("Python ", "")
        major, minor = version.split(".")[:2]
        if int(major) == 3 and int(minor) >= 10:
            return "python3", f"Python {version}"
    
    # Try python
    ok, out, _ = run_command("python --version")
    if ok and "3." in out:
        version = out.replace("Python ", "")
        major, minor = version.split(".")[:2]
        if int(major) == 3 and int(minor) >= 10:
            return "python", f"Python {version}"
    
    return None, None


def find_memprocfs():
    """Find MemProcFS installation."""
    script_dir = Path(__file__).parent
    
    # Check local memprocfs folder
    local_memprocfs = script_dir / "memprocfs"
    exe_name = "MemProcFS.exe" if platform.system() == "Windows" else "memprocfs"
    
    if local_memprocfs.exists():
        exe = local_memprocfs / exe_name
        if exe.exists():
            return str(local_memprocfs)
    
    # Check PATH
    found = shutil.which(exe_name)
    if found:
        return str(Path(found).parent)
    
    # Check common locations
    common_paths = [
        Path.home() / "memprocfs",
        Path.home() / "tools" / "memprocfs",
        Path("C:/memprocfs"),
        Path("C:/tools/memprocfs"),
    ]
    for p in common_paths:
        if (p / exe_name).exists():
            return str(p)
    
    return None


def check_dependencies(python_cmd):
    """Check and install dependencies from requirements.txt."""
    print_step(2, "Checking Dependencies")
    
    requirements_file = Path(__file__).parent / "requirements.txt"
    if not requirements_file.exists():
        print_fail(f"requirements.txt not found at: {requirements_file}")
        return False
    
    # Install from requirements.txt
    print_info(f"Installing from {requirements_file.name}...")
    ok, out, err = run_command(f'{python_cmd} -m pip install -r "{requirements_file}"')
    if ok:
        print_ok("All dependencies installed successfully")
        return True
    else:
        print_fail(f"Failed to install dependencies: {err}")
        return False


# ─── Main Setup ────────────────────────────────────────────────────────────────

def main():
    print_header("MemProcFS MCP Server - Setup")
    
    # Step 1: Check Python
    print_step(1, "Checking Python Version")
    python_cmd, python_info = get_python_executable()
    
    if not python_cmd:
        print_fail("Python 3.10+ not found!")
        print_info("Please install Python 3.10 or later from https://python.org")
        print_info("Or install the py launcher from https://github.com/nicktimko/python-launcher")
        return False
    
    print_ok(f"Found {python_info} ({python_cmd})")
    
    # Step 2: Check/Install Dependencies
    if not check_dependencies(python_cmd):
        print_fail("Dependency installation failed!")
        return False
    
    # Step 3: Check MemProcFS
    print_step(3, "Checking MemProcFS Installation")
    memprocfs_path = find_memprocfs()
    
    if memprocfs_path:
        print_ok(f"MemProcFS found at: {memprocfs_path}")
    else:
        print_fail("MemProcFS not found!")
        print_info("")
        print_info("MemProcFS is required for memory forensics analysis.")
        print_info("")
        print_info("Options:")
        print_info("  1. Download from: https://github.com/ufrisk/MemProcFS/releases/latest")
        print_info("  2. Extract to: " + str(Path(__file__).parent / "memprocfs"))
        print_info("  3. Or add the MemProcFS folder to your PATH")
        print_info("")
        
        # Ask for path
        try:
            path_input = input("Enter MemProcFS path (or press Enter to skip): ").strip()
            if path_input:
                path = Path(path_input)
                if path.exists():
                    memprocfs_path = str(path)
                    print_ok(f"Using MemProcFS from: {memprocfs_path}")
                    
                    # Create symlink/copy to local folder
                    local_dir = Path(__file__).parent / "memprocfs"
                    local_dir.mkdir(exist_ok=True)
                    
                    # Copy exe files
                    for f in path.glob("*.exe"):
                        shutil.copy2(f, local_dir / f.name)
                        print_ok(f"Copied {f.name}")
                    for f in path.glob("*.dll"):
                        shutil.copy2(f, local_dir / f.name)
                        print_ok(f"Copied {f.name}")
                    
                    print_ok("MemProcFS files copied to local directory")
                else:
                    print_fail(f"Path does not exist: {path_input}")
                    memprocfs_path = None
        except (EOFError, KeyboardInterrupt):
            print_info("Skipping MemProcFS setup")
            memprocfs_path = None
    
    # Step 4: Generate MCP Configuration
    print_step(4, "MCP Configuration")
    
    script_path = Path(__file__).parent / "server.py"
    if not script_path.exists():
        print_fail(f"server.py not found at: {script_path}")
        return False
    
    # Convert to absolute path
    script_path = script_path.resolve()
    
    print_colored("\n" + "=" * 70, 'cyan')
    print_colored("  Add the following to your MCP configuration:", 'cyan', 'bold')
    print_colored("=" * 70, 'cyan')
    
    # VS Code configuration
    print_colored("\n  📋 VS Code (mcp.json):", 'yellow', 'bold')
    print_colored("  " + "-" * 50, 'yellow')
    
    vscode_config = f'''{{
    "memprocfs-mcp": {{
        "command": "{python_cmd.split()[0]}",
        "args": [
            {f'"{python_cmd.split()[1]}", ' if len(python_cmd.split()) > 1 else ""}"{script_path}"
        ],
        "type": "stdio",
        "env": {{
            "PYTHONPATH": "{script_path.parent}"
        }}
    }}
}}'''
    print_colored(vscode_config, 'green')
    
    # Claude Desktop configuration
    print_colored("\n  📋 Claude Desktop (claude_desktop_config.json):", 'yellow', 'bold')
    print_colored("  " + "-" * 50, 'yellow')
    
    claude_config = f'''{{
    "memprocfs-mcp": {{
        "command": "{python_cmd.split()[0]}",
        "args": [
            {f'"{python_cmd.split()[1]}", ' if len(python_cmd.split()) > 1 else ""}"{script_path}"
        ],
        "env": {{
            "PYTHONPATH": "{script_path.parent}"
        }}
    }}
}}'''
    print_colored(claude_config, 'green')
    
    # Step 5: Summary
    print_step(5, "Setup Complete!")
    
    print_ok("MemProcFS MCP Server is ready to use!")
    print_info("")
    print_info("Available tools:")
    print_info("  • load_memory_image - Load a memory dump file")
    print_info("  • list_processes - List all processes")
    print_info("  • analyze_process - Analyze a specific process")
    print_info("  • get_network_map - Get network connections")
    print_info("  • get_memory_map - Get physical memory map")
    print_info("  • read_physical_memory - Read memory at address")
    print_info("  • get_registry_hives - List registry hives")
    print_info("  • get_drivers - List loaded drivers")
    print_info("  • get_analysis_context - Get session state")
    print_info("  • save_report - Save analysis report")
    print_info("  • exec_command - Execute advanced commands")
    print_info("")
    print_info("To test: Restart VS Code/Claude and ask to load a memory image")
    
    return True


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print_colored("\n\nSetup cancelled.", 'yellow')
        sys.exit(1)