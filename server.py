#!/usr/bin/env python3
"""
MemProcFS MCP Server
A Model Context Protocol server for memory forensics analysis using MemProcFS.
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("memprocfs-mcp")

# Add MemProcFS to path
MEMPROCFS_DIR = Path(__file__).parent / "memprocfs"
if MEMPROCFS_DIR.exists():
    os.add_dll_directory(str(MEMPROCFS_DIR))
    sys.path.insert(0, str(MEMPROCFS_DIR))

# Try to import memprocfs
try:
    import memprocfs
    MEMPROCFS_AVAILABLE = True
except ImportError:
    MEMPROCFS_AVAILABLE = False
    logger.warning("MemProcFS not available. Server will run in demo mode.")


class MemProcFSManager:
    """Manages MemProcFS VMM instances."""
    
    def __init__(self):
        self.vmm = None
        self.current_image = None
        self.analysis_history = []
        
    def load_image(self, image_path: str) -> Dict[str, Any]:
        """Load a memory image and return system information."""
        if not MEMPROCFS_AVAILABLE:
            return {"error": "MemProcFS not available"}
        
        try:
            # Close existing VMM if any
            if self.vmm:
                self.vmm.close()
            
            # Load new image
            logger.info(f"Loading memory image: {image_path}")
            self.vmm = memprocfs.Vmm(['-device', image_path])
            self.current_image = image_path
            
            # Get basic info
            processes = self.vmm.process_list()
            
            result = {
                "status": "success",
                "image_path": image_path,
                "process_count": len(processes),
                "message": f"Successfully loaded {image_path}"
            }
            
            self.analysis_history.append({
                "action": "load_image",
                "image": image_path,
                "result": result
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Error loading image: {e}")
            return {"error": str(e)}
    
    def list_processes(self) -> List[Dict[str, Any]]:
        """List all processes in the memory image."""
        if not self.vmm:
            return [{"error": "No memory image loaded"}]
        
        try:
            processes = self.vmm.process_list()
            return [{"pid": p.pid, "name": p.name} for p in processes]
        except Exception as e:
            return [{"error": str(e)}]
    
    def get_network_map(self) -> List[Dict[str, Any]]:
        """Get network connections."""
        if not self.vmm:
            return [{"error": "No memory image loaded"}]
        
        try:
            net_map = self.vmm.maps.net()
            return net_map
        except Exception as e:
            return [{"error": str(e)}]
    
    def get_memory_map(self) -> List[Dict[str, Any]]:
        """Get physical memory map."""
        if not self.vmm:
            return [{"error": "No memory image loaded"}]
        
        try:
            memmap = self.vmm.maps.memmap()
            return [{"base": m[0], "size": m[1]} for m in memmap]
        except Exception as e:
            return [{"error": str(e)}]
    
    def read_physical_memory(self, address: int, size: int) -> Dict[str, Any]:
        """Read physical memory at specified address."""
        if not self.vmm:
            return {"error": "No memory image loaded"}
        
        try:
            data = self.vmm.memory.read(address, size)
            return {
                "address": hex(address),
                "size": len(data),
                "hex": data.hex()
            }
        except Exception as e:
            return {"error": str(e)}
    
    def get_registry_hives(self) -> List[Dict[str, Any]]:
        """List registry hives."""
        if not self.vmm:
            return [{"error": "No memory image loaded"}]
        
        try:
            hives = self.vmm.reg_hive_list()
            return [{"name": h.name} for h in hives]
        except Exception as e:
            return [{"error": str(e)}]
    
    def get_drivers(self) -> List[Dict[str, Any]]:
        """List loaded drivers."""
        if not self.vmm:
            return [{"error": "No memory image loaded"}]
        
        try:
            drivers = self.vmm.maps.kdriver()
            return [{"name": d.get("name", ""), "path": d.get("path", "")} for d in drivers]
        except Exception as e:
            return [{"error": str(e)}]
    
    def analyze_process(self, pid: int) -> Dict[str, Any]:
        """Analyze a specific process."""
        if not self.vmm:
            return {"error": "No memory image loaded"}
        
        try:
            processes = self.vmm.process_list()
            target = None
            for p in processes:
                if p.pid == pid:
                    target = p
                    break
            
            if not target:
                return {"error": f"Process {pid} not found"}
            
            result = {
                "pid": target.pid,
                "name": target.name,
                "path_kernel": target.pathkernel,
                "path_user": target.pathuser,
                "ppid": target.ppid,
                "dtb": hex(target.dtb),
                "session": target.session
            }
            
            # Try to get command line
            try:
                result["cmdline"] = target.cmdline
            except:
                result["cmdline"] = "N/A"
            
            # Get modules
            try:
                modules = target.module_list()
                result["modules"] = [m.name for m in modules[:10]]
            except:
                result["modules"] = []
            
            # Get network connections for this process
            try:
                net_map = self.vmm.maps.net()
                connections = [e for e in net_map if e.get("pid") == pid]
                result["network_connections"] = connections
            except:
                result["network_connections"] = []
            
            return result
            
        except Exception as e:
            return {"error": str(e)}
    
    def close(self):
        """Close the VMM instance."""
        if self.vmm:
            try:
                self.vmm.close()
            except:
                pass
            self.vmm = None
            self.current_image = None


# Create MCP server
mcp = FastMCP(
    "memprocfs-mcp",
    instructions="MCP Server for MemProcFS memory forensics analysis. Load memory dumps and analyze processes, network connections, and system artifacts."
)

# Global manager instance
manager = MemProcFSManager()


@mcp.tool()
def load_memory_image(image_path: str) -> str:
    """
    Load a memory dump file for analysis.
    
    Args:
        image_path: Absolute path to the memory dump file (.mem, .raw, .dmp, etc.)
    
    Returns:
        JSON string with load status and basic system information.
    """
    result = manager.load_image(image_path)
    return json.dumps(result, indent=2)


@mcp.tool()
def list_processes() -> str:
    """
    List all processes in the loaded memory image.
    
    Returns:
        JSON string with list of processes (PID and name).
    """
    result = manager.list_processes()
    return json.dumps(result, indent=2)


@mcp.tool()
def analyze_process(pid: int) -> str:
    """
    Analyze a specific process by PID.
    
    Args:
        pid: Process ID to analyze
    
    Returns:
        JSON string with detailed process information including:
        - Path, parent PID, DTB
        - Command line
        - Loaded modules
        - Network connections
    """
    result = manager.analyze_process(pid)
    return json.dumps(result, indent=2)


@mcp.tool()
def get_network_map() -> str:
    """
    Get all network connections from the memory image.
    
    Returns:
        JSON string with network connection details including:
        - Source/destination IPs and ports
        - Connection state
        - Associated process IDs
    """
    result = manager.get_network_map()
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
def get_memory_map() -> str:
    """
    Get the physical memory map.
    
    Returns:
        JSON string with memory regions (base address and size).
    """
    result = manager.get_memory_map()
    return json.dumps(result, indent=2)


@mcp.tool()
def read_physical_memory(address: str, size: int = 64) -> str:
    """
    Read physical memory at a specified address.
    
    Args:
        address: Hex address to read from (e.g., "0x1000")
        size: Number of bytes to read (default: 64)
    
    Returns:
        JSON string with hex dump of memory contents.
    """
    # Parse hex address
    try:
        addr = int(address, 16) if address.startswith("0x") else int(address)
    except ValueError:
        return json.dumps({"error": f"Invalid address: {address}"})
    
    result = manager.read_physical_memory(addr, size)
    return json.dumps(result, indent=2)


@mcp.tool()
def get_registry_hives() -> str:
    """
    List all registry hives in the memory image.
    
    Returns:
        JSON string with registry hive names.
    """
    result = manager.get_registry_hives()
    return json.dumps(result, indent=2)


@mcp.tool()
def get_drivers() -> str:
    """
    List all loaded kernel drivers.
    
    Returns:
        JSON string with driver names and paths.
    """
    result = manager.get_drivers()
    return json.dumps(result, indent=2)


@mcp.tool()
def get_analysis_context() -> str:
    """
    Get the current analysis context and session state.
    
    Returns:
        JSON string with session information including:
        - Current image path
        - Analysis history
        - Summary statistics
    """
    return json.dumps({
        "current_image": manager.current_image,
        "history": manager.analysis_history,
        "memprocfs_available": MEMPROCFS_AVAILABLE
    }, indent=2)


@mcp.tool()
def save_report(content: str, filename: str = None) -> str:
    """
    Save an analysis report to the reports directory.
    
    Args:
        content: Report content in Markdown format
        filename: Optional filename (auto-generated if not provided)
    
    Returns:
        Path to the saved report file.
    """
    reports_dir = Path(__file__).parent / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    if not filename:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        image_tag = Path(manager.current_image).stem if manager.current_image else "session"
        filename = f"report_{image_tag}_{timestamp}.md"
    
    filepath = reports_dir / filename
    filepath.write_text(content, encoding="utf-8")
    
    return json.dumps({
        "status": "success",
        "path": str(filepath),
        "size": len(content)
    })


@mcp.tool()
def exec_command(command: str, path: str = "", pid: int = 0, detail: str = "", addresses: str = "") -> str:
    """
    Execute advanced MemProcFS commands not covered by other tools.
    
    Use this tool for:
    - VFS operations (list, read files from virtual file system)
    - Service enumeration
    - User enumeration
    - Kernel object inspection
    - Pool tag analysis
    - Process details (cmdline, integrity, session, SID)
    - Kernel build info
    
    Args:
        command: The command to execute. Options:
            - "vfs_list": List VFS directory (optional param: path)
            - "vfs_read": Read VFS file (required param: path)
            - "list_services": List Windows services
            - "list_users": List user accounts
            - "list_kernel_objects": List kernel objects
            - "get_process_details": Get detailed process info (required param: pid, optional: detail=cmdline|integrity|session|sid|eprocess|is_wow64|all)
            - "get_kernel_build": Get kernel build number
            - "list_vfs_files": List files in VFS path (optional param: path)
        path: Path for VFS operations (default: "\\")
        pid: Process ID for get_process_details (default: 0)
        detail: Process detail type for get_process_details (default: "all")
        addresses: Comma-separated hex addresses for scatter read (e.g. "0x1000,0x2000")
    
    Returns:
        JSON string with command results.
    """
    if not manager.vmm:
        return json.dumps({"error": "No memory image loaded"})
    
    try:
        if command == "vfs_list":
            p = path.replace("\\", "/").replace("//", "/") if path else "/"
            if not p.startswith("/"):
                p = "/" + p
            result = manager.vmm.vfs.list(p)
            # VFS list can return dict, list, or other types
            if isinstance(result, dict):
                items = list(result.keys())
            elif isinstance(result, (list, tuple)):
                items = [item if isinstance(item, str) else getattr(item, "name", str(item)) for item in result]
            else:
                items = [str(result)]
            return json.dumps({"items": items}, indent=2)
        
        elif command == "vfs_read":
            if not path:
                return json.dumps({"error": "Path parameter required"})
            # Normalize path: convert backslashes to forward slashes
            vfs_path = path.replace("\\", "/").replace("//", "/")
            if not vfs_path.startswith("/"):
                vfs_path = "/" + vfs_path
            result = manager.vmm.vfs.read(vfs_path)
            if isinstance(result, bytes):
                return json.dumps({"content": result.decode('utf-8', errors='replace')}, indent=2)
            return json.dumps({"content": str(result)}, indent=2)
        
        elif command == "list_services":
            services = manager.vmm.maps.service()
            return json.dumps({"services": services}, indent=2, default=str)
        
        elif command == "list_users":
            users = manager.vmm.maps.user()
            return json.dumps({"users": users}, indent=2, default=str)
        
        elif command == "list_kernel_objects":
            kobjects = manager.vmm.maps.kobject()
            return json.dumps({"kernel_objects": kobjects}, indent=2, default=str)
        
        elif command == "list_pool_tags":
            import threading
            result = [None]
            error = [None]
            
            def _get_pool():
                try:
                    result[0] = manager.vmm.maps.pool()
                except Exception as e:
                    error[0] = str(e)
            
            t = threading.Thread(target=_get_pool)
            t.start()
            t.join(timeout=30)
            
            if t.is_alive():
                return json.dumps({"error": "list_pool_tags timed out after 30s - too many pool entries to enumerate interactively"})
            if error[0]:
                return json.dumps({"error": error[0]})
            
            pool = result[0]
            if isinstance(pool, dict):
                # Summarize by tag
                tag_summary = {}
                for va, entry in pool.items():
                    tag = entry.get("tag", "????")
                    if tag not in tag_summary:
                        tag_summary[tag] = {"count": 0, "total_bytes": 0, "allocated": 0, "freed": 0}
                    tag_summary[tag]["count"] += 1
                    tag_summary[tag]["total_bytes"] += entry.get("cb", 0)
                    if entry.get("alloc"):
                        tag_summary[tag]["allocated"] += 1
                    else:
                        tag_summary[tag]["freed"] += 1
                
                summary = [{"tag": t, **info} for t, info in sorted(tag_summary.items(), key=lambda x: -x[1]["total_bytes"])]
                return json.dumps({"total_entries": len(pool), "unique_tags": len(summary), "top_tags": summary[:50]}, indent=2)
            return json.dumps({"pool": pool}, indent=2, default=str)
        
        elif command == "get_process_details":
            if pid == 0:
                return json.dumps({"error": "PID parameter required"})
            
            d = detail if detail else "all"
            
            processes = manager.vmm.process_list()
            target = None
            for p in processes:
                if p.pid == pid:
                    target = p
                    break
            
            if not target:
                return json.dumps({"error": f"Process {pid} not found"})
            
            if d == "cmdline":
                return json.dumps({"pid": pid, "cmdline": target.cmdline}, indent=2)
            elif d == "integrity":
                return json.dumps({"pid": pid, "integrity": target.integrity}, indent=2)
            elif d == "session":
                return json.dumps({"pid": pid, "session": target.session}, indent=2)
            elif d == "sid":
                return json.dumps({"pid": pid, "sid": target.sid}, indent=2)
            elif d == "eprocess":
                return json.dumps({"pid": pid, "eprocess": hex(target.eprocess) if target.eprocess else None}, indent=2)
            elif d == "is_wow64":
                return json.dumps({"pid": pid, "is_wow64": target.is_wow64}, indent=2)
            elif d == "all":
                return json.dumps({
                    "pid": target.pid,
                    "name": target.name,
                    "cmdline": target.cmdline,
                    "integrity": target.integrity,
                    "session": target.session,
                    "sid": target.sid,
                    "eprocess": hex(target.eprocess) if target.eprocess else None,
                    "is_wow64": target.is_wow64,
                    "path_kernel": target.pathkernel,
                    "path_user": target.pathuser,
                    "ppid": target.ppid
                }, indent=2)
            else:
                return json.dumps({"error": f"Unknown detail: {d}. Use: cmdline, integrity, session, sid, eprocess, is_wow64, all"})
        
        elif command == "get_kernel_build":
            return json.dumps({"kernel_build": manager.vmm.kernel.build}, indent=2)
        
        elif command == "list_vfs_files":
            p = path.replace("\\", "/").replace("//", "/") if path else "/"
            if not p.startswith("/"):
                p = "/" + p
            files = manager.vmm.vfs.list(p)
            # VFS list can return dict, list, or other types
            if isinstance(files, dict):
                items = [{"name": k, "is_dir": v.get("f_isdir", False), "size": v.get("size", 0)} for k, v in files.items()]
            elif isinstance(files, (list, tuple)):
                items = [{"name": f if isinstance(f, str) else getattr(f, "name", str(f))} for f in files]
            else:
                items = [{"name": str(files)}]
            return json.dumps({"path": p, "files": items}, indent=2)
        
        else:
            return json.dumps({
                "error": f"Unknown command: {command}",
                "available_commands": [
                    "vfs_list", "vfs_read", "list_services", "list_users",
                    "list_kernel_objects", "list_pool_tags", "get_process_details",
                    "get_kernel_build", "list_vfs_files"
                ]
            })
    
    except Exception as e:
        return json.dumps({"error": str(e)})


def main():
    """Main entry point."""
    # Run the MCP server
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()