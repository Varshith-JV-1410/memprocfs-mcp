# MemProcFS MCP Server

A Model Context Protocol (MCP) server for memory forensics analysis using MemProcFS.

## Features

- **Load Memory Images**: Analyze memory dumps (.mem, .raw, .dmp)
- **Process Analysis**: List and analyze processes
- **Network Analysis**: View network connections
- **Memory Reading**: Read physical memory at any address
- **Registry Analysis**: List registry hives
- **Driver Enumeration**: List loaded kernel drivers
- **VFS Navigation**: Browse MemProcFS virtual file system
- **Advanced Commands**: Execute any MemProcFS operation via exec_command

## Installation

### Prerequisites

- Python 3.10+
- MemProcFS binaries (download separately)

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/Varshith-JV-1410/memprocfs-mcp.git
cd memprocfs-mcp

# Run the setup script (automatically installs dependencies)
python setup.py
```

The setup script will:
1. Check Python version (requires 3.10+)
2. Install dependencies from `requirements.txt`
3. Verify MemProcFS installation
4. Provide exact MCP configuration for VS Code and Claude Desktop

### Manual Setup

```bash
# Install dependencies from requirements.txt
pip install -r requirements.txt

# Download MemProcFS from:
# https://github.com/ufrisk/MemProcFS/releases/latest
# Extract to memprocfs/ folder
```

## Usage

```bash
python server.py
```

## MCP Configuration

### For VS Code (GitHub Copilot)

Add to your VS Code settings (`mcp.json`):

```json
{
  "memprocfs-mcp": {
    "command": "python",
    "args": ["/path/to/memprocfs-mcp/server.py"],
    "type": "stdio",
    "env": {
      "PYTHONPATH": "/path/to/memprocfs-mcp"
    }
  }
}
```

### For Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "memprocfs-mcp": {
    "command": "python",
    "args": ["/path/to/memprocfs-mcp/server.py"],
    "env": {
      "PYTHONPATH": "/path/to/memprocfs-mcp"
    }
  }
}
```

> Replace `/path/to/memprocfs-mcp/` with the actual path to this project. Run `python setup.py` to get the exact configuration for your system.

## Available Tools

| Tool | Description |
|------|-------------|
| `load_memory_image` | Load a memory dump file for analysis |
| `list_processes` | List all processes in the memory image |
| `analyze_process` | Analyze a specific process by PID |
| `get_network_map` | Get all network connections |
| `get_memory_map` | Get physical memory map |
| `read_physical_memory` | Read physical memory at address |
| `get_registry_hives` | List registry hives |
| `get_drivers` | List loaded kernel drivers |
| `get_analysis_context` | Get session state |
| `save_report` | Save analysis report |
| `exec_command` | Execute advanced commands |

## exec_command Sub-Commands

| Command | Description | Parameters |
|---------|-------------|------------|
| `vfs_list` | List VFS directory | `path` (optional) |
| `vfs_read` | Read VFS file | `path` (required) |
| `list_services` | List Windows services | - |
| `list_users` | List user accounts | - |
| `list_kernel_objects` | List kernel objects | - |
| `list_pool_tags` | List pool tags (30s timeout) | - |
| `get_process_details` | Get detailed process info | `pid` (required), `detail` (optional: cmdline, integrity, session, sid, eprocess, is_wow64, all) |
| `get_kernel_build` | Get kernel build number | - |
| `list_vfs_files` | List VFS files with details | `path` (optional) |

## License

[GNU Affero General Public License v3.0](LICENSE)