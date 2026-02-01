"""
MCP Server for Terraform code execution
支持生成、验证和执行 Terraform 配置
充分利用远程服务器的所有 API 端点
"""

import json
import logging
import os
import time
import uuid
import hashlib
import subprocess
import re
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv(override=True)

import anyio
import httpx
from fastapi import FastAPI
from starlette.routing import Mount
from mcp.server import Server
from mcp.server.streamable_http import StreamableHTTPServerTransport
from mcp.types import TextContent, Tool

# ---------- Logging --------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("terraform_executor_mcp")

# ---------- Config --------
def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()

EXECUTION_MODE = _env("EXECUTION_MODE", "local").lower()
LINUX_SERVER_URL = _env("LINUX_SERVER_URL", "http://127.0.0.1:5000")
TERRAFORM_DIR = _env("TERRAFORM_DIR", "/tmp/terraform")

MCP_HOST = _env("MCP_HOST", "0.0.0.0")
MCP_PORT = int(_env("MCP_PORT", "8000"))
AUDIT_LOG = Path(_env("MCP_AUDIT_LOG", "/tmp/mcp-terraform-audit.jsonl"))
DEFAULT_TIMEOUT = int(_env("MCP_DEFAULT_TIMEOUT", "30"))
MAX_TIMEOUT = int(_env("MCP_MAX_TIMEOUT", "300"))
MAX_OUTPUT_BYTES = int(_env("MCP_MAX_OUTPUT_BYTES", "500000"))

if EXECUTION_MODE not in ("local", "http"):
    raise ValueError(f"Invalid EXECUTION_MODE: {EXECUTION_MODE}")

# ---------- Utilities --------
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _truncate(s: str, max_bytes: int) -> str:
    b = s.encode("utf-8", errors="replace")
    if len(b) <= max_bytes:
        return s
    return b[:max_bytes].decode("utf-8", errors="replace") + "\n...[truncated]"

def _validate_workspace_name(workspace: str) -> bool:
    """验证工作空间名称（严格的允许列表正则）"""
    # 只允许字母、数字、下划线和连字符，长度 1-64
    if not workspace or len(workspace) > 64:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', workspace))

def _validate_filename(filename: str) -> bool:
    """验证文件名安全性（严格的允许列表正则）"""
    # 只允许字母、数字、下划线、连字符和点，长度 1-128
    if not filename or len(filename) > 128:
        return False
    # 不允许以点开头或包含路径遍历
    if filename.startswith('.') or '..' in filename:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_.-]+$', filename))

def _clamp_timeout(timeout: int | None, default: int = DEFAULT_TIMEOUT) -> int:
    """Clamp timeout to configured maximum"""
    if timeout is None:
        return default
    return min(max(1, int(timeout)), MAX_TIMEOUT)

def audit_log(entry: dict[str, Any]) -> None:
    """Append a JSONL audit record"""
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        logger.exception("Failed to write audit log")

# ---------- Terraform Utilities --------
def _validate_hcl_syntax(code: str) -> tuple[bool, list[str]]:
    """基础的 HCL 语法检查"""
    errors = []
    lines = code.split('\n')
    
    brace_count = 0
    paren_count = 0
    bracket_count = 0
    in_string = False
    escape_next = False
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        if not stripped or stripped.startswith('#'):
            continue
        
        for char in line:
            if escape_next:
                escape_next = False
                continue
            if char == '\\':
                escape_next = True
                continue
            if char == '"' and not in_string:
                in_string = True
            elif char == '"' and in_string:
                in_string = False
            elif not in_string:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                elif char == '(':
                    paren_count += 1
                elif char == ')':
                    paren_count -= 1
                elif char == '[':
                    bracket_count += 1
                elif char == ']':
                    bracket_count -= 1
    
    if brace_count != 0:
        errors.append(f"Unbalanced braces: {brace_count}")
    if paren_count != 0:
        errors.append(f"Unbalanced parentheses: {paren_count}")
    if bracket_count != 0:
        errors.append(f"Unbalanced brackets: {bracket_count}")
    
    return len(errors) == 0, errors

def _parse_terraform_plan(output: str) -> dict[str, Any]:
    """从 terraform plan 输出中提取信息"""
    summary = {
        "to_add": 0,
        "to_change": 0,
        "to_destroy": 0,
        "resources": []
    }
    
    lines = output.strip().split('\n')
    for line in lines:
        if ' add' in line:
            match = re.search(r'(\d+) to add', line)
            if match:
                summary["to_add"] = int(match.group(1))
        if ' change' in line:
            match = re.search(r'(\d+) to change', line)
            if match:
                summary["to_change"] = int(match.group(1))
        if ' destroy' in line:
            match = re.search(r'(\d+) to destroy', line)
            if match:
                summary["to_destroy"] = int(match.group(1))
    
    for line in lines:
        if line.startswith('#'):
            continue
        stripped = line.strip()
        if stripped.startswith('+') or stripped.startswith('~') or stripped.startswith('-'):
            summary["resources"].append(stripped)
    
    return summary

def _parse_terraform_apply(output: str) -> dict[str, Any]:
    """从 terraform apply 输出中提取信息"""
    summary = {
        "apply_complete": "Apply complete!" in output,
        "resources_created": [],
        "resources_updated": [],
        "resources_destroyed": [],
    }
    
    lines = output.split('\n')
    for line in lines:
        stripped = line.strip()
        if ' created' in stripped or stripped.startswith('+'):
            summary["resources_created"].append(stripped)
        elif ' updated' in stripped or stripped.startswith('~'):
            summary["resources_updated"].append(stripped)
        elif ' destroyed' in stripped or stripped.startswith('-'):
            summary["resources_destroyed"].append(stripped)
    
    return summary

# ---------- Local Execution --------
async def _execute_terraform_local(
    cmd_parts: list[str],
    workspace: str,
    timeout: int,
) -> dict[str, Any]:
    """在本地执行 Terraform 命令"""
    try:
        work_dir = f"{TERRAFORM_DIR}/{workspace}"
        
        result = await anyio.to_thread.run_sync(
            subprocess.run,
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=work_dir,
            check=False,
        )
        
        return {
            "ok": result.returncode == 0,
            "status": 200 if result.returncode == 0 else 400,
            "data": {
                "output": result.stdout,
                "error": result.stderr,
                "return_code": result.returncode,
            },
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "status": 408,
            "data": {
                "output": "",
                "error": f"Timeout after {timeout}s",
                "return_code": 124,
            },
        }
    except Exception as e:
        return {
            "ok": False,
            "status": 500,
            "data": {
                "output": "",
                "error": str(e),
                "return_code": 1,
            },
        }

def _upload_terraform_local(filename: str, content: str, workspace: str) -> dict[str, Any]:
    """在本地保存 Terraform 配置文件"""
    try:
        # Validate workspace and filename
        if not _validate_workspace_name(workspace):
            return {
                "ok": False,
                "status": 400,
                "data": {
                    "success": False,
                    "error": "Invalid workspace name",
                },
            }
        
        if not _validate_filename(filename):
            return {
                "ok": False,
                "status": 400,
                "data": {
                    "success": False,
                    "error": "Invalid filename",
                },
            }
        
        work_dir = Path(TERRAFORM_DIR) / workspace
        work_dir.mkdir(parents=True, exist_ok=True)
        
        code_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        
        if not filename.endswith('.tf'):
            filename = f"{filename}.tf"
        
        file_path = work_dir / filename
        file_path.write_text(content, encoding='utf-8')
        
        return {
            "ok": True,
            "status": 200,
            "data": {
                "success": True,
                "path": str(file_path),
                "hash": code_hash,
                "workspace": workspace,
            },
        }
    except Exception as e:
        return {
            "ok": False,
            "status": 500,
            "data": {
                "success": False,
                "error": str(e),
            },
        }

# ---------- Remote HTTP Request Helper --------
async def _remote_request(
    path: str,
    method: str = "POST",
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """向远程服务器发送 HTTP 请求"""
    url = LINUX_SERVER_URL.rstrip("/") + path
    headers = {"accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                json=body,
            )

        text = resp.text
        data = None
        try:
            data = resp.json()
        except Exception:
            data = text

        return {
            "ok": 200 <= resp.status_code < 300,
            "status": resp.status_code,
            "url": str(resp.request.url),
            "data": data,
            "text": text,
        }
    except Exception as e:
        return {
            "ok": False,
            "status": 0,
            "url": url,
            "data": None,
            "text": str(e),
            "error": str(e),
        }

# ---------- MCP Server --------
mcp_server = Server("terraform_executor_mcp")

@mcp_server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="upload_terraform",
            description="将生成的 Terraform 配置文件上传到服务器",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Terraform 配置内容（HCL 格式）"
                    },
                    "filename": {
                        "type": "string",
                        "description": "文件的基础名称，例如 'main' 或 'variables'（会自动添加 .tf 扩展名）"
                    },
                    "workspace": {
                        "type": "string",
                        "description": "Terraform 工作空间名称（默认 'default'）"
                    },
                },
                "required": ["code", "filename"],
            },
        ),
        Tool(
            name="check_terraform_syntax",
            description="检查 Terraform 配置文件的语法和格式是否正确",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Terraform 配置代码内容"
                    },
                },
                "required": ["code"],
            },
        ),
        Tool(
            name="list_files",
            description="列出工作空间中的所有 Terraform 配置文件",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "工作空间名称（默认 'default'）"
                    },
                },
            },
        ),
        Tool(
            name="get_file",
            description="获取工作空间中的 Terraform 文件内容",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "工作空间名称（默认 'default'）"
                    },
                    "filename": {
                        "type": "string",
                        "description": "要获取的文件名（包括 .tf 扩展名）"
                    },
                },
                "required": ["filename"],
            },
        ),
        Tool(
            name="delete_file",
            description="删除工作空间中的 Terraform 文件",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "工作空间名称（默认 'default'）"
                    },
                    "filename": {
                        "type": "string",
                        "description": "要删除的文件名（包括 .tf 扩展名）"
                    },
                },
                "required": ["filename"],
            },
        ),
        Tool(
            name="list_workspaces",
            description="列出所有已创建的 Terraform 工作空间",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="create_workspace",
            description="创建新的 Terraform 工作空间",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "新工作空间的名称"
                    },
                },
                "required": ["workspace"],
            },
        ),
        Tool(
            name="delete_workspace",
            description="删除工作空间及其所有文件。⚠️ 此操作不可逆",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "要删除的工作空间名称"
                    },
                },
                "required": ["workspace"],
            },
        ),
        Tool(
            name="terraform_init",
            description="初始化 Terraform 工作目录（terraform init）",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "工作空间名称（默认 'default'）"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "执行超时时间（秒），默认 30，最大 300"
                    },
                },
            },
        ),
        Tool(
            name="terraform_validate",
            description="验证 Terraform 配置是否可被加载（terraform validate）",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "工作空间名称（默认 'default'）"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "执行超时时间（秒），默认 30，最大 300"
                    },
                },
            },
        ),
        Tool(
            name="terraform_plan",
            description="生成 Terraform 执行计划（terraform plan）",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "工作空间名称（默认 'default'）"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "执行超时时间（秒），默认 60，最大 300"
                    },
                },
            },
        ),
        Tool(
            name="terraform_apply",
            description="应用 Terraform 配置（terraform apply）",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "工作空间名称（默认 'default'）"
                    },
                    "auto_approve": {
                        "type": "boolean",
                        "description": "是否自动批准应用（默认 false）"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "执行超时时间（秒），默认 120，最大 300"
                    },
                },
            },
        ),
        Tool(
            name="terraform_destroy",
            description="销毁由 Terraform 管理的资源（terraform destroy）。⚠️ 此操作会删除真实资源",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "工作空间名称（默认 'default'）"
                    },
                    "auto_approve": {
                        "type": "boolean",
                        "description": "是否自动批准销毁（默认 false）"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "执行超时时间（秒），默认 120，最大 300"
                    },
                },
            },
        ),
        Tool(
            name="terraform_state",
            description="查看 Terraform 状态文件信息",
            inputSchema={
                "type": "object",
                "properties": {
                    "workspace": {
                        "type": "string",
                        "description": "工作空间名称（默认 'default'）"
                    },
                    "command": {
                        "type": "string",
                        "enum": ["list", "show"],
                        "description": "状态命令 'list' 或 'show'（默认 'list'）"
                    },
                },
            },
        ),
    ]

@mcp_server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    req_id = uuid.uuid4().hex
    workspace = str(arguments.get("workspace", "default")).strip() or "default"
    
    # Validate workspace name
    if not _validate_workspace_name(workspace):
        error_msg = f"Invalid workspace name: {workspace}"
        audit_log({
            "ts": _now_iso(),
            "req_id": req_id,
            "tool": name,
            "mode": EXECUTION_MODE,
            "workspace": workspace,
            "blocked": True,
            "reason": error_msg
        })
        resp = {"success": False, "error": error_msg}
        return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]
    
    audit_base = {
        "ts": _now_iso(),
        "req_id": req_id,
        "tool": name,
        "mode": EXECUTION_MODE,
        "workspace": workspace,
    }

    if name == "upload_terraform":
        code = str(arguments.get("code", ""))
        filename = str(arguments.get("filename", ""))

        if not code or not filename:
            error_msg = "Missing or empty 'code' or 'filename'"
            audit_log({**audit_base, "blocked": True, "reason": error_msg})
            resp = {"success": False, "error": error_msg}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]
        
        # Validate filename
        if not _validate_filename(filename):
            error_msg = f"Invalid filename: {filename}"
            audit_log({**audit_base, "blocked": True, "reason": error_msg})
            resp = {"success": False, "error": error_msg}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        try:
            if EXECUTION_MODE == "local":
                result = _upload_terraform_local(filename, code, workspace)
            else:
                code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
                result = await _remote_request(
                    path="/upload_terraform",
                    method="POST",
                    body={"filename": filename, "content": code, "workspace": workspace},
                )

            if not result["ok"]:
                audit_log({
                    **audit_base,
                    "status": result["status"],
                    "error": result.get("text") or result.get("data", {}).get("error"),
                })
                resp = {"success": False, "error": f"Upload failed", "status": result["status"]}
                return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

            data = result.get("data", {})
            audit_log({**audit_base, "success": True, "path": data.get("path")})

            resp = {
                "success": True,
                "path": data.get("path"),
                "file_hash": data.get("hash"),
                "message": "Terraform file uploaded successfully",
            }
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        except Exception as e:
            audit_log({**audit_base, "error": str(e)})
            resp = {"success": False, "error": str(e)}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

    elif name == "check_terraform_syntax":
        code = str(arguments.get("code", ""))

        if not code:
            error_msg = "Missing or empty 'code'"
            audit_log({**audit_base, "blocked": True, "reason": error_msg})
            resp = {"success": False, "error": error_msg}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        try:
            valid, errors = _validate_hcl_syntax(code)
            
            audit_log({**audit_base, "valid": valid, "errors": errors})
            
            resp = {
                "valid": valid,
                "errors": errors,
                "message": "Syntax check complete" if valid else "Syntax errors found"
            }
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        except Exception as e:
            audit_log({**audit_base, "error": str(e)})
            resp = {"valid": False, "error": str(e)}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

    elif name == "list_files":
        audit_base["operation"] = "list_files"

        try:
            if EXECUTION_MODE == "local":
                work_dir = Path(TERRAFORM_DIR) / workspace
                if not work_dir.exists():
                    files = []
                else:
                    files = [
                        {
                            "name": f.name,
                            "size": f.stat().st_size,
                            "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                        }
                        for f in work_dir.glob("*.tf")
                        if f.is_file()
                    ]
                
                result = {
                    "ok": True,
                    "status": 200,
                    "data": {
                        "workspace": workspace,
                        "files": sorted(files, key=lambda x: x["name"]),
                        "total": len(files),
                    }
                }
            else:
                result = await _remote_request(
                    path=f"/terraform/files/{workspace}",
                    method="GET",
                )

            if not result["ok"]:
                audit_log({**audit_base, "status": result["status"], "error": result.get("text")})
                resp = {"success": False, "error": "Failed to list files"}
                return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

            data = result.get("data", {})
            audit_log({**audit_base, "success": True, "file_count": data.get("total", 0)})

            resp = {
                "success": True,
                "workspace": workspace,
                "files": data.get("files", []),
                "total": data.get("total", 0),
            }
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        except Exception as e:
            audit_log({**audit_base, "error": str(e)})
            resp = {"success": False, "error": str(e)}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

    elif name == "get_file":
        filename = str(arguments.get("filename", ""))
        audit_base["operation"] = "get_file"
        audit_base["filename"] = filename

        if not filename:
            error_msg = "Missing 'filename'"
            audit_log({**audit_base, "blocked": True, "reason": error_msg})
            resp = {"success": False, "error": error_msg}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]
        
        # Validate filename
        if not _validate_filename(filename):
            error_msg = f"Invalid filename: {filename}"
            audit_log({**audit_base, "blocked": True, "reason": error_msg})
            resp = {"success": False, "error": error_msg}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        try:
            if EXECUTION_MODE == "local":
                file_path = Path(TERRAFORM_DIR) / workspace / filename
                if not file_path.exists():
                    return [TextContent(type="text", text=json.dumps({
                        "success": False,
                        "error": f"File not found: {filename}"
                    }, ensure_ascii=False, indent=2))]
                
                content = file_path.read_text(encoding="utf-8")
                result = {
                    "ok": True,
                    "status": 200,
                    "data": {
                        "workspace": workspace,
                        "filename": filename,
                        "content": content,
                        "size": len(content),
                    }
                }
            else:
                result = await _remote_request(
                    path=f"/terraform/file/{workspace}/{filename}",
                    method="GET",
                )

            if not result["ok"]:
                audit_log({**audit_base, "status": result["status"], "error": result.get("text")})
                resp = {"success": False, "error": "Failed to get file"}
                return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

            data = result.get("data", {})
            audit_log({**audit_base, "success": True, "size": data.get("size", 0)})

            resp = {
                "success": True,
                "workspace": workspace,
                "filename": filename,
                "content": data.get("content", ""),
                "size": data.get("size", 0),
            }
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        except Exception as e:
            audit_log({**audit_base, "error": str(e)})
            resp = {"success": False, "error": str(e)}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

    elif name == "delete_file":
        filename = str(arguments.get("filename", ""))
        audit_base["operation"] = "delete_file"
        audit_base["filename"] = filename

        if not filename:
            error_msg = "Missing 'filename'"
            audit_log({**audit_base, "blocked": True, "reason": error_msg})
            resp = {"success": False, "error": error_msg}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]
        
        # Validate filename
        if not _validate_filename(filename):
            error_msg = f"Invalid filename: {filename}"
            audit_log({**audit_base, "blocked": True, "reason": error_msg})
            resp = {"success": False, "error": error_msg}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        try:
            if EXECUTION_MODE == "local":
                file_path = Path(TERRAFORM_DIR) / workspace / filename
                if not file_path.exists():
                    return [TextContent(type="text", text=json.dumps({
                        "success": False,
                        "error": f"File not found: {filename}"
                    }, ensure_ascii=False, indent=2))]
                
                file_path.unlink()
                result = {"ok": True, "status": 200, "data": {"success": True}}
            else:
                result = await _remote_request(
                    path=f"/terraform/file/{workspace}/{filename}",
                    method="DELETE",
                )

            if not result["ok"]:
                audit_log({**audit_base, "status": result["status"], "error": result.get("text")})
                resp = {"success": False, "error": "Failed to delete file"}
                return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

            audit_log({**audit_base, "success": True})

            resp = {
                "success": True,
                "message": f"File deleted: {filename}",
            }
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        except Exception as e:
            audit_log({**audit_base, "error": str(e)})
            resp = {"success": False, "error": str(e)}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

    elif name == "list_workspaces":
        audit_base["operation"] = "list_workspaces"

        try:
            if EXECUTION_MODE == "local":
                terraform_root = Path(TERRAFORM_DIR)
                if not terraform_root.exists():
                    workspaces = []
                else:
                    workspaces = []
                    for d in terraform_root.iterdir():
                        if d.is_dir() and not d.name.startswith("."):
                            tf_files = list(d.glob("*.tf"))
                            workspaces.append({
                                "name": d.name,
                                "file_count": len(tf_files),
                                "created_at": datetime.fromtimestamp(d.stat().st_ctime).isoformat(),
                            })
                    workspaces = sorted(workspaces, key=lambda x: x["name"])
                
                result = {
                    "ok": True,
                    "status": 200,
                    "data": {
                        "workspaces": workspaces,
                        "total": len(workspaces),
                    }
                }
            else:
                result = await _remote_request(
                    path="/terraform/workspace",
                    method="GET",
                )

            if not result["ok"]:
                audit_log({**audit_base, "status": result["status"], "error": result.get("text")})
                resp = {"success": False, "error": "Failed to list workspaces"}
                return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

            data = result.get("data", {})
            audit_log({**audit_base, "success": True, "count": data.get("total", 0)})

            resp = {
                "success": True,
                "workspaces": data.get("workspaces", []),
                "total": data.get("total", 0),
            }
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        except Exception as e:
            audit_log({**audit_base, "error": str(e)})
            resp = {"success": False, "error": str(e)}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

    elif name == "create_workspace":
        new_workspace = str(arguments.get("workspace", ""))
        audit_base["operation"] = "create_workspace"
        audit_base["new_workspace"] = new_workspace

        if not new_workspace:
            error_msg = "Missing 'workspace'"
            audit_log({**audit_base, "blocked": True, "reason": error_msg})
            resp = {"success": False, "error": error_msg}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        try:
            if EXECUTION_MODE == "local":
                workspace_dir = Path(TERRAFORM_DIR) / new_workspace
                workspace_dir.mkdir(parents=True, exist_ok=True)
                result = {"ok": True, "status": 201, "data": {"success": True}}
            else:
                result = await _remote_request(
                    path="/terraform/workspace",
                    method="POST",
                    body={"workspace": new_workspace},
                )

            if not result["ok"]:
                audit_log({**audit_base, "status": result["status"], "error": result.get("text")})
                resp = {"success": False, "error": "Failed to create workspace"}
                return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

            audit_log({**audit_base, "success": True})

            resp = {
                "success": True,
                "message": f"Workspace '{new_workspace}' created successfully",
            }
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        except Exception as e:
            audit_log({**audit_base, "error": str(e)})
            resp = {"success": False, "error": str(e)}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

    elif name == "delete_workspace":
        delete_workspace = str(arguments.get("workspace", ""))
        audit_base["operation"] = "delete_workspace"
        audit_base["delete_workspace"] = delete_workspace

        if not delete_workspace:
            error_msg = "Missing 'workspace'"
            audit_log({**audit_base, "blocked": True, "reason": error_msg})
            resp = {"success": False, "error": error_msg}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        try:
            if EXECUTION_MODE == "local":
                import shutil
                workspace_dir = Path(TERRAFORM_DIR) / delete_workspace
                if workspace_dir.exists():
                    shutil.rmtree(workspace_dir)
                result = {"ok": True, "status": 200, "data": {"success": True}}
            else:
                result = await _remote_request(
                    path=f"/terraform/workspace/{delete_workspace}",
                    method="DELETE",
                )

            if not result["ok"]:
                audit_log({**audit_base, "status": result["status"], "error": result.get("text")})
                resp = {"success": False, "error": "Failed to delete workspace"}
                return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

            audit_log({**audit_base, "success": True, "warning": "Workspace deleted"})

            resp = {
                "success": True,
                "message": f"Workspace '{delete_workspace}' and all contents deleted",
                "warning": "⚠️ This operation cannot be undone",
            }
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        except Exception as e:
            audit_log({**audit_base, "error": str(e)})
            resp = {"success": False, "error": str(e)}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

    elif name == "terraform_init":
        timeout = _clamp_timeout(arguments.get("timeout"), DEFAULT_TIMEOUT)
        audit_base["operation"] = "init"
        audit_base["timeout"] = timeout

        try:
            if EXECUTION_MODE == "local":
                result = await _execute_terraform_local(["terraform", "init"], workspace, timeout)
            else:
                result = await _remote_request(
                    path="/terraform",
                    method="POST",
                    body={"command": "init", "workspace": workspace, "timeout": timeout},
                )

            data = result.get("data", {})
            output = data.get("output", "")
            error = data.get("error", "")

            audit_log({**audit_base, "success": result["ok"], "status": result["status"]})

            resp = {
                "success": result["ok"],
                "output": _truncate(output, MAX_OUTPUT_BYTES),
                "error": _truncate(error, MAX_OUTPUT_BYTES) if error else "",
                "message": "Terraform initialized successfully" if result["ok"] else "Initialization failed",
            }
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        except Exception as e:
            audit_log({**audit_base, "error": str(e)})
            resp = {"success": False, "error": str(e)}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

    elif name == "terraform_validate":
        timeout = _clamp_timeout(arguments.get("timeout"), DEFAULT_TIMEOUT)
        audit_base["operation"] = "validate"
        audit_base["timeout"] = timeout

        try:
            if EXECUTION_MODE == "local":
                result = await _execute_terraform_local(["terraform", "validate"], workspace, timeout)
            else:
                result = await _remote_request(
                    path="/terraform",
                    method="POST",
                    body={"command": "validate", "workspace": workspace, "timeout": timeout},
                )

            data = result.get("data", {})
            output = data.get("output", "")
            error = data.get("error", "")

            audit_log({**audit_base, "success": result["ok"], "status": result["status"]})

            resp = {
                "success": result["ok"],
                "output": _truncate(output, MAX_OUTPUT_BYTES),
                "error": _truncate(error, MAX_OUTPUT_BYTES) if error else "",
                "message": "Terraform configuration is valid" if result["ok"] else "Validation failed",
            }
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        except Exception as e:
            audit_log({**audit_base, "error": str(e)})
            resp = {"success": False, "error": str(e)}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

    elif name == "terraform_plan":
        timeout = _clamp_timeout(arguments.get("timeout"), 60)
        audit_base["operation"] = "plan"
        audit_base["timeout"] = timeout

        try:
            if EXECUTION_MODE == "local":
                result = await _execute_terraform_local(["terraform", "plan"], workspace, timeout)
            else:
                result = await _remote_request(
                    path="/terraform",
                    method="POST",
                    body={"command": "plan", "workspace": workspace, "timeout": timeout},
                )

            data = result.get("data", {})
            output = data.get("output", "")
            error = data.get("error", "")

            plan_summary = _parse_terraform_plan(output)
            
            audit_log({**audit_base, "success": result["ok"], "plan_summary": plan_summary})

            resp = {
                "success": result["ok"],
                "output": _truncate(output, MAX_OUTPUT_BYTES),
                "error": _truncate(error, MAX_OUTPUT_BYTES) if error else "",
                "plan_summary": plan_summary,
                "message": "Plan generated successfully" if result["ok"] else "Plan generation failed",
            }
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        except Exception as e:
            audit_log({**audit_base, "error": str(e)})
            resp = {"success": False, "error": str(e)}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

    elif name == "terraform_apply":
        auto_approve = arguments.get("auto_approve", False)
        timeout = _clamp_timeout(arguments.get("timeout"), 120)
        audit_base["operation"] = "apply"
        audit_base["auto_approve"] = auto_approve
        audit_base["timeout"] = timeout

        try:
            cmd = ["terraform", "apply"]
            if auto_approve:
                cmd.append("-auto-approve")
            
            if EXECUTION_MODE == "local":
                result = await _execute_terraform_local(cmd, workspace, timeout)
            else:
                result = await _remote_request(
                    path="/terraform",
                    method="POST",
                    body={"command": "apply", "auto_approve": auto_approve, "workspace": workspace, "timeout": timeout},
                )

            data = result.get("data", {})
            output = data.get("output", "")
            error = data.get("error", "")

            apply_summary = _parse_terraform_apply(output)
            
            audit_log({**audit_base, "success": result["ok"], "apply_summary": apply_summary})

            resp = {
                "success": result["ok"],
                "output": _truncate(output, MAX_OUTPUT_BYTES),
                "error": _truncate(error, MAX_OUTPUT_BYTES) if error else "",
                "apply_summary": apply_summary,
                "message": "Configuration applied successfully" if result["ok"] else "Apply failed",
            }
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        except Exception as e:
            audit_log({**audit_base, "error": str(e)})
            resp = {"success": False, "error": str(e)}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

    elif name == "terraform_destroy":
        auto_approve = arguments.get("auto_approve", False)
        timeout = _clamp_timeout(arguments.get("timeout"), 120)
        audit_base["operation"] = "destroy"
        audit_base["auto_approve"] = auto_approve
        audit_base["timeout"] = timeout

        try:
            cmd = ["terraform", "destroy"]
            if auto_approve:
                cmd.append("-auto-approve")
            
            if EXECUTION_MODE == "local":
                result = await _execute_terraform_local(cmd, workspace, timeout)
            else:
                result = await _remote_request(
                    path="/terraform",
                    method="POST",
                    body={"command": "destroy", "auto_approve": auto_approve, "workspace": workspace, "timeout": timeout},
                )

            data = result.get("data", {})
            output = data.get("output", "")
            error = data.get("error", "")

            audit_log({**audit_base, "success": result["ok"]})

            resp = {
                "success": result["ok"],
                "output": _truncate(output, MAX_OUTPUT_BYTES),
                "error": _truncate(error, MAX_OUTPUT_BYTES) if error else "",
                "message": "Resources destroyed successfully" if result["ok"] else "Destroy failed",
                "warning": "⚠️ Resources have been destroyed" if result["ok"] else "",
            }
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        except Exception as e:
            audit_log({**audit_base, "error": str(e)})
            resp = {"success": False, "error": str(e)}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

    elif name == "terraform_state":
        command = str(arguments.get("command", "list")).lower()
        audit_base["operation"] = "state"
        audit_base["command"] = command

        if command not in ("list", "show"):
            command = "list"

        try:
            terraform_cmd = ["terraform", "state", command]
            
            if EXECUTION_MODE == "local":
                result = await _execute_terraform_local(terraform_cmd, workspace, DEFAULT_TIMEOUT)
            else:
                result = await _remote_request(
                    path="/terraform",
                    method="POST",
                    body={"command": f"state_{command}", "workspace": workspace, "timeout": DEFAULT_TIMEOUT},
                )

            data = result.get("data", {})
            output = data.get("output", "")
            error = data.get("error", "")

            audit_log({**audit_base, "success": result["ok"]})

            resp = {
                "success": result["ok"],
                "output": _truncate(output, MAX_OUTPUT_BYTES),
                "error": _truncate(error, MAX_OUTPUT_BYTES) if error else "",
                "message": f"State {command} completed successfully" if result["ok"] else "State command failed",
            }
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

        except Exception as e:
            audit_log({**audit_base, "error": str(e)})
            resp = {"success": False, "error": str(e)}
            return [TextContent(type="text", text=json.dumps(resp, ensure_ascii=False, indent=2))]

    else:
        audit_log({**audit_base, "error": f"Unknown tool: {name}"})
        raise ValueError(f"Unknown tool: {name}")

# ---------- Streamable HTTP Transport --------
transport = StreamableHTTPServerTransport(
    mcp_session_id=None,
    is_json_response_enabled=False,
    event_store=None,
    security_settings=None,
    retry_interval=None,
)

class MCPASGIApp:
    def __init__(self, transport: StreamableHTTPServerTransport):
        self.transport = transport

    async def __call__(self, scope, receive, send):
        return await self.transport.handle_request(scope, receive, send)

mcp_asgi_app = MCPASGIApp(transport)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Terraform Executor MCP server...")
    logger.info("MCP mounted at /mcp")
    logger.info("Listening on http://%s:%s", MCP_HOST, MCP_PORT)
    logger.info("Execution mode: %s", EXECUTION_MODE.upper())
    if EXECUTION_MODE == "local":
        logger.info("Terraform directory: %s", TERRAFORM_DIR)
    else:
        logger.info("Remote server: %s", LINUX_SERVER_URL)
    logger.info("Audit log: %s", str(AUDIT_LOG))

    async with transport.connect() as (read_stream, write_stream):
        async with anyio.create_task_group() as tg:

            async def _runner():
                await mcp_server.run(
                    read_stream,
                    write_stream,
                    mcp_server.create_initialization_options(),
                )

            tg.start_soon(_runner)

            try:
                yield
            finally:
                try:
                    await transport.terminate()
                except Exception:
                    logger.exception("Error while terminating transport")

http_app = FastAPI(lifespan=lifespan)

http_app.router.routes.append(Mount("/mcp", app=mcp_asgi_app))

@http_app.get("/healthz")
async def healthz():
    return {
        "ok": True,
        "mode": EXECUTION_MODE,
        "terraform_dir": TERRAFORM_DIR if EXECUTION_MODE == "local" else None,
        "remote_server": LINUX_SERVER_URL if EXECUTION_MODE == "http" else None,
        "audit_log": str(AUDIT_LOG),
    }

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        http_app,
        host=MCP_HOST,
        port=MCP_PORT,
        reload=False,
    )