"""
远程 Terraform 执行服务器 - v11 版本
完全兼容 MCP Terraform Executor Server
支持所有 Terraform 命令和工作空间管理
"""

import os
import json
import subprocess
import shutil
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List
import hashlib

from flask import Flask, request, jsonify
from dotenv import load_dotenv

load_dotenv()

# ---------- Configuration --------
TERRAFORM_DIR = os.getenv("TERRAFORM_DIR", "/opt/terraform")
TERRAFORM_BIN = os.getenv("TERRAFORM_BIN", "terraform")
LOG_DIR = Path(os.getenv("LOG_DIR", "/var/log/terraform-executor"))
DEFAULT_TIMEOUT = int(os.getenv("DEFAULT_TIMEOUT", "30"))
MAX_TIMEOUT = int(os.getenv("MAX_TIMEOUT", "300"))
MAX_OUTPUT_BYTES = int(os.getenv("MAX_OUTPUT_BYTES", "500000"))
ALLOW_UNSAFE_OPS = os.getenv("ALLOW_UNSAFE_OPS", "false").lower() in {"1", "true", "yes"}

# 创建日志目录
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ---------- Logging --------
import logging
from logging.handlers import RotatingFileHandler

def _setup_logger():
    logger = logging.getLogger("terraform_remote_server")
    logger.setLevel(logging.INFO)
    
    if logger.handlers:
        for h in logger.handlers[:]:
            logger.removeHandler(h)
    
    handler = RotatingFileHandler(
        LOG_DIR / "terraform-server.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8"
    )
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

logger = _setup_logger()

# ---------- Utilities --------
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _truncate(s: str, max_bytes: int) -> str:
    """截断输出到指定字节数"""
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

def _clamp_timeout(timeout: int) -> int:
    """Clamp timeout to configured bounds (>=1 and <=MAX_TIMEOUT)"""
    return min(max(1, int(timeout)), MAX_TIMEOUT)

def _ensure_workspace_dir(workspace: str, create_if_missing: bool = True) -> Path:
    """确保工作空间目录存在或返回其路径"""
    # 验证工作空间名称（防止路径遍历攻击）
    if not _validate_workspace_name(workspace):
        raise ValueError(f"Invalid workspace name: {workspace}")
    
    workspace_dir = Path(TERRAFORM_DIR) / workspace
    
    if create_if_missing:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    
    return workspace_dir

def _log_operation(operation: str, workspace: str, data: Dict[str, Any]) -> None:
    """记录操作日志"""
    try:
        log_file = LOG_DIR / "operations.jsonl"
        entry = {
            "ts": _now_iso(),
            "operation": operation,
            "workspace": workspace,
            **data
        }
        with log_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.exception(f"Failed to log operation: {e}")

def _extract_plan_summary(output: str) -> Dict[str, Any]:
    """从 plan 输出提取摘要"""
    summary = {
        "to_add": 0,
        "to_change": 0,
        "to_destroy": 0,
    }
    
    import re
    
    # 查找最后一行的摘要
    lines = output.strip().split('\n')
    for line in reversed(lines):
        if 'to add' in line:
            match = re.search(r'(\d+) to add', line)
            if match:
                summary["to_add"] = int(match.group(1))
        if 'to change' in line:
            match = re.search(r'(\d+) to change', line)
            if match:
                summary["to_change"] = int(match.group(1))
        if 'to destroy' in line:
            match = re.search(r'(\d+) to destroy', line)
            if match:
                summary["to_destroy"] = int(match.group(1))
    
    return summary

def _extract_apply_summary(output: str) -> Dict[str, Any]:
    """从 apply 输出提取摘要"""
    summary = {
        "apply_complete": "Apply complete!" in output,
    }
    
    import re
    
    # 提取资源变更统计
    lines = output.split('\n')
    for line in reversed(lines):
        if 'Apply complete!' in line:
            # 通常格式是 "Apply complete! Resources: X added, Y changed, Z destroyed."
            match = re.search(r'Resources: (\d+) added, (\d+) changed, (\d+) destroyed', line)
            if match:
                summary["resources_added"] = int(match.group(1))
                summary["resources_changed"] = int(match.group(2))
                summary["resources_destroyed"] = int(match.group(3))
            break
    
    return summary

# ---------- Flask App --------
app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

# ---------- Health & Status Routes --------

@app.route("/healthz", methods=["GET"])
def healthz():
    """健康检查"""
    try:
        # 检查 terraform 是否可用
        result = subprocess.run(
            [TERRAFORM_BIN, "version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        terraform_version = result.stdout.split('\n')[0] if result.returncode == 0 else "unknown"
    except Exception as e:
        terraform_version = f"error: {str(e)}"
    
    return jsonify({
        "ok": True,
        "timestamp": _now_iso(),
        "terraform_dir": TERRAFORM_DIR,
        "terraform_bin": TERRAFORM_BIN,
        "terraform_version": terraform_version,
        "log_dir": str(LOG_DIR),
        "mode": "safe" if not ALLOW_UNSAFE_OPS else "unsafe",
    }), 200

@app.route("/status", methods=["GET"])
def status():
    """服务状态和统计"""
    try:
        terraform_root = Path(TERRAFORM_DIR)
        
        workspaces = []
        total_files = 0
        
        if terraform_root.exists():
            for workspace_dir in terraform_root.iterdir():
                if workspace_dir.is_dir() and not workspace_dir.name.startswith("."):
                    tf_files = list(workspace_dir.glob("*.tf"))
                    workspaces.append({
                        "name": workspace_dir.name,
                        "file_count": len(tf_files),
                    })
                    total_files += len(tf_files)
        
        return jsonify({
            "ok": True,
            "timestamp": _now_iso(),
            "workspaces": sorted(workspaces, key=lambda x: x["name"]),
            "total_workspaces": len(workspaces),
            "total_files": total_files,
            "terraform_dir": TERRAFORM_DIR,
        }), 200
    
    except Exception as e:
        logger.exception(f"Failed to get status: {e}")
        return jsonify({
            "ok": False,
            "error": str(e)
        }), 500

# ---------- File Upload Route --------

@app.route("/upload_terraform", methods=["POST"])
def upload_terraform():
    """
    上传 Terraform 配置文件
    
    请求体:
    {
        "filename": "main.tf",
        "content": "resource \"aws_instance\" \"example\" { ... }",
        "workspace": "default"
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "error": "Request body is empty"
            }), 400
        
        filename = data.get("filename")
        content = data.get("content")
        workspace = data.get("workspace", "default")
        
        # 验证输入
        if not filename or not isinstance(filename, str):
            return jsonify({
                "success": False,
                "error": "Missing or invalid 'filename'"
            }), 400
        
        if content is None or not isinstance(content, str):
            return jsonify({
                "success": False,
                "error": "Missing or invalid 'content'"
            }), 400
        
        # 验证文件名
        if not _validate_filename(filename):
            return jsonify({
                "success": False,
                "error": "Invalid filename (contains invalid characters or path traversal)"
            }), 400
        
        # 确保工作空间目录存在
        workspace_dir = _ensure_workspace_dir(workspace)
        
        # 确保文件有 .tf 扩展名
        if not filename.endswith(".tf"):
            filename = f"{filename}.tf"
        
        file_path = workspace_dir / filename
        
        # 计算内容哈希
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        
        # 写入文件
        file_path.write_text(content, encoding="utf-8")
        logger.info(f"Uploaded {filename} to {workspace_dir}")
        
        _log_operation("upload_terraform", workspace, {
            "filename": filename,
            "size": len(content),
            "hash": content_hash,
            "success": True
        })
        
        return jsonify({
            "success": True,
            "message": f"File uploaded: {filename}",
            "path": str(file_path),
            "workspace": workspace,
            "hash": content_hash,
        }), 200
    
    except Exception as e:
        logger.exception(f"Upload failed: {e}")
        _log_operation("upload_terraform", data.get("workspace", "unknown") if data else "unknown", {
            "error": str(e),
            "success": False
        })
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ---------- Terraform Execution Route --------

@app.route("/terraform", methods=["POST"])
def terraform_execute():
    """
    执行 Terraform 命令
    
    请求体:
    {
        "command": "init" | "validate" | "plan" | "apply" | "destroy" | "state_list" | "state_show",
        "workspace": "default",
        "auto_approve": false,
        "timeout": 30
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "error": "Request body is empty"
            }), 400
        
        command = data.get("command")
        workspace = data.get("workspace", "default")
        auto_approve = data.get("auto_approve", False)
        timeout = _clamp_timeout(data.get("timeout", DEFAULT_TIMEOUT))
        
        # 验证输入
        valid_commands = {
            "init", "validate", "plan", "apply", "destroy",
            "state_list", "state_show", "output"
        }
        
        if command not in valid_commands:
            return jsonify({
                "success": False,
                "error": f"Invalid command: {command}. Must be one of: {', '.join(valid_commands)}"
            }), 400
        
        # 安全检查：destroy 命令需要特殊权限
        if command == "destroy" and not ALLOW_UNSAFE_OPS and not auto_approve:
            return jsonify({
                "success": False,
                "error": "Destroy command requires auto_approve=true or ALLOW_UNSAFE_OPS=true"
            }), 403
        
        # 确保工作空间目录存在
        try:
            workspace_dir = _ensure_workspace_dir(workspace)
        except ValueError as e:
            logger.error(f"Workspace validation failed: {e}")
            return jsonify({
                "success": False,
                "error": str(e)
            }), 400
        
        # 构建命令
        terraform_cmd = _build_terraform_command(command, auto_approve)
        
        logger.info(f"Executing: {terraform_cmd} in {workspace_dir}")
        
        # 执行命令
        result = subprocess.run(
            terraform_cmd,
            cwd=str(workspace_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        
        output = result.stdout
        error = result.stderr
        return_code = result.returncode
        
        success = return_code == 0
        
        logger.info(f"Command {command} completed with return code {return_code}")
        
        # 解析摘要
        summary = {}
        if command == "plan":
            summary = _extract_plan_summary(output)
        elif command == "apply":
            summary = _extract_apply_summary(output)
        
        _log_operation("terraform", workspace, {
            "command": command,
            "success": success,
            "return_code": return_code,
            "output_size": len(output),
            "error_size": len(error),
        })
        
        return jsonify({
            "success": success,
            "command": command,
            "output": _truncate(output, MAX_OUTPUT_BYTES),
            "error": _truncate(error, MAX_OUTPUT_BYTES),
            "return_code": return_code,
            "workspace": workspace,
            "summary": summary if summary else None,
        }), 200
    
    except subprocess.TimeoutExpired:
        logger.error(f"Command timeout after {timeout}s")
        _log_operation("terraform", workspace, {
            "command": command,
            "error": "Timeout",
            "success": False
        })
        return jsonify({
            "success": False,
            "error": f"Command execution timeout (>{timeout}s)",
            "return_code": 124,
        }), 408
    
    except Exception as e:
        logger.exception(f"Terraform execution failed: {e}")
        _log_operation("terraform", workspace, {
            "command": command,
            "error": str(e),
            "success": False
        })
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ---------- Workspace Management Routes --------

@app.route("/terraform/workspace", methods=["POST"])
def create_workspace():
    """
    创建新的 Terraform 工作空间
    
    请求体:
    {
        "workspace": "production"
    }
    """
    try:
        data = request.get_json()
        workspace = data.get("workspace")
        
        if not workspace or not isinstance(workspace, str):
            return jsonify({
                "success": False,
                "error": "Missing or invalid 'workspace'"
            }), 400
        
        # 验证工作空间名称
        if not _validate_workspace_name(workspace):
            return jsonify({
                "success": False,
                "error": "Invalid workspace name"
            }), 400
        
        workspace_dir = _ensure_workspace_dir(workspace)
        
        logger.info(f"Workspace created: {workspace}")
        
        _log_operation("create_workspace", workspace, {
            "success": True
        })
        
        return jsonify({
            "success": True,
            "message": f"Workspace '{workspace}' created",
            "path": str(workspace_dir),
        }), 201
    
    except Exception as e:
        logger.exception(f"Failed to create workspace: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/terraform/workspace", methods=["GET"])
def list_workspaces():
    """
    列出所有工作空间
    """
    try:
        terraform_root = Path(TERRAFORM_DIR)
        
        if not terraform_root.exists():
            return jsonify({
                "success": True,
                "workspaces": [],
                "total": 0,
                "message": "No workspaces found"
            }), 200
        
        workspaces = []
        for workspace_dir in terraform_root.iterdir():
            if workspace_dir.is_dir() and not workspace_dir.name.startswith("."):
                tf_files = list(workspace_dir.glob("*.tf"))
                workspaces.append({
                    "name": workspace_dir.name,
                    "file_count": len(tf_files),
                    "created_at": datetime.fromtimestamp(workspace_dir.stat().st_ctime).isoformat(),
                })
        
        return jsonify({
            "success": True,
            "workspaces": sorted(workspaces, key=lambda x: x["name"]),
            "total": len(workspaces),
        }), 200
    
    except Exception as e:
        logger.exception(f"Failed to list workspaces: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/terraform/workspace/<workspace>", methods=["DELETE"])
def delete_workspace(workspace: str):
    """
    删除工作空间及其所有文件
    
    ⚠️ 谨慎操作，此操作会删除工作空间中的所有文件和状态
    """
    try:
        # 验证工作空间名称
        if not _validate_workspace_name(workspace):
            return jsonify({
                "success": False,
                "error": "Invalid workspace name"
            }), 400
        
        workspace_dir = Path(TERRAFORM_DIR) / workspace
        
        if not workspace_dir.exists():
            return jsonify({
                "success": False,
                "error": f"Workspace '{workspace}' does not exist"
            }), 404
        
        # 删除工作空间目录
        shutil.rmtree(workspace_dir)
        
        logger.warning(f"Workspace deleted: {workspace}")
        
        _log_operation("delete_workspace", workspace, {
            "success": True,
            "warning": "Workspace and all contents deleted"
        })
        
        return jsonify({
            "success": True,
            "message": f"Workspace '{workspace}' deleted",
            "warning": "⚠️ Workspace and all contents have been deleted",
        }), 200
    
    except Exception as e:
        logger.exception(f"Failed to delete workspace: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ---------- File Management Routes --------

@app.route("/terraform/files/<workspace>", methods=["GET"])
def list_files(workspace: str):
    """
    列出工作空间中的所有 Terraform 文件
    """
    try:
        try:
            workspace_dir = _ensure_workspace_dir(workspace, create_if_missing=False)
        except ValueError as e:
            logger.error(f"Workspace validation failed: {e}")
            return jsonify({
                "success": False,
                "error": str(e)
            }), 400
        
        files = []
        if workspace_dir.exists():
            for f in workspace_dir.glob("*.tf"):
                if f.is_file():
                    stat = f.stat()
                    files.append({
                        "name": f.name,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "path": str(f),
                    })
        
        return jsonify({
            "success": True,
            "workspace": workspace,
            "files": sorted(files, key=lambda x: x["name"]),
            "total": len(files),
        }), 200
    
    except Exception as e:
        logger.exception(f"Failed to list files: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/terraform/file/<workspace>/<filename>", methods=["GET"])
def get_file(workspace: str, filename: str):
    """
    获取工作空间中的 Terraform 文件内容
    """
    try:
        # 验证文件名
        if not _validate_filename(filename):
            return jsonify({
                "success": False,
                "error": "Invalid filename"
            }), 400
        
        try:
            workspace_dir = _ensure_workspace_dir(workspace, create_if_missing=False)
        except ValueError as e:
            logger.error(f"Workspace validation failed: {e}")
            return jsonify({
                "success": False,
                "error": str(e)
            }), 400
        file_path = workspace_dir / filename
        
        if not file_path.exists():
            return jsonify({
                "success": False,
                "error": f"File not found: {filename}"
            }), 404
        
        if not file_path.is_file():
            return jsonify({
                "success": False,
                "error": f"Not a file: {filename}"
            }), 400
        
        content = file_path.read_text(encoding="utf-8")
        stat = file_path.stat()
        
        return jsonify({
            "success": True,
            "workspace": workspace,
            "filename": filename,
            "content": content,
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        }), 200
    
    except Exception as e:
        logger.exception(f"Failed to get file: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/terraform/file/<workspace>/<filename>", methods=["DELETE"])
def delete_file(workspace: str, filename: str):
    """
    删除工作空间中的 Terraform 文件
    """
    try:
        # 验证文件名
        if not _validate_filename(filename):
            return jsonify({
                "success": False,
                "error": "Invalid filename"
            }), 400
        
        try:
            workspace_dir = _ensure_workspace_dir(workspace)
        except ValueError as e:
            logger.error(f"Workspace validation failed: {e}")
            return jsonify({
                "success": False,
                "error": str(e)
            }), 400
        file_path = workspace_dir / filename
        
        if not file_path.exists():
            return jsonify({
                "success": False,
                "error": f"File not found: {filename}"
            }), 404
        
        file_path.unlink()
        
        logger.info(f"File deleted: {filename} from {workspace}")
        
        _log_operation("delete_file", workspace, {
            "filename": filename,
            "success": True
        })
        
        return jsonify({
            "success": True,
            "message": f"File deleted: {filename}",
        }), 200
    
    except Exception as e:
        logger.exception(f"Failed to delete file: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ---------- Output Route --------

@app.route("/terraform/output/<workspace>", methods=["GET"])
def get_output(workspace: str):
    """
    获取 Terraform outputs
    """
    try:
        # Validate workspace name first
        if not _validate_workspace_name(workspace):
            return jsonify({
                "success": False,
                "error": f"Invalid workspace name: {workspace}"
            }), 400
        
        # Get timeout from query parameter
        timeout = _clamp_timeout(request.args.get("timeout", type=int, default=DEFAULT_TIMEOUT))
        
        workspace_dir = _ensure_workspace_dir(workspace, create_if_missing=False)
        
        if not workspace_dir.exists():
            return jsonify({
                "success": False,
                "error": f"Workspace not found: {workspace}"
            }), 404
        
        result = subprocess.run(
            [TERRAFORM_BIN, "output", "-json"],
            cwd=str(workspace_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        
        if result.returncode == 0:
            try:
                outputs = json.loads(result.stdout)
            except json.JSONDecodeError:
                outputs = {}
        else:
            outputs = {}
        
        return jsonify({
            "success": result.returncode == 0,
            "workspace": workspace,
            "outputs": outputs,
            "error": result.stderr if result.returncode != 0 else None,
        }), 200
    
    except ValueError as e:
        # Handle validation errors
        logger.error(f"Validation error: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400
    except Exception as e:
        logger.exception(f"Failed to get output: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ---------- Logs Route --------

@app.route("/logs/operations", methods=["GET"])
def get_operation_logs():
    """
    获取操作日志
    
    查询参数:
    - workspace: 工作空间名称（可选）
    - limit: 返回的最大记录数（默认 100）
    """
    try:
        workspace = request.args.get("workspace")
        limit = int(request.args.get("limit", 100))
        
        log_file = LOG_DIR / "operations.jsonl"
        
        if not log_file.exists():
            return jsonify({
                "success": True,
                "logs": [],
                "total": 0,
            }), 200
        
        logs = []
        with log_file.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    if workspace and entry.get("workspace") != workspace:
                        continue
                    logs.append(entry)
                except json.JSONDecodeError:
                    continue
        
        # 返回最后的 limit 条记录
        logs = logs[-limit:]
        
        return jsonify({
            "success": True,
            "logs": logs,
            "total": len(logs),
            "workspace_filter": workspace,
        }), 200
    
    except Exception as e:
        logger.exception(f"Failed to get logs: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ---------- Helper Functions --------

def _build_terraform_command(command: str, auto_approve: bool = False) -> List[str]:
    """
    构建 Terraform 命令（返回 argv 列表）
    """
    if command == "init":
        return [TERRAFORM_BIN, "init"]
    elif command == "validate":
        return [TERRAFORM_BIN, "validate"]
    elif command == "plan":
        return [TERRAFORM_BIN, "plan"]
    elif command == "apply":
        cmd = [TERRAFORM_BIN, "apply"]
        if auto_approve:
            cmd.append("-auto-approve")
        return cmd
    elif command == "destroy":
        cmd = [TERRAFORM_BIN, "destroy"]
        if auto_approve:
            cmd.append("-auto-approve")
        return cmd
    elif command == "state_list":
        return [TERRAFORM_BIN, "state", "list"]
    elif command == "state_show":
        return [TERRAFORM_BIN, "state", "show"]
    elif command == "output":
        return [TERRAFORM_BIN, "output", "-json"]
    else:
        raise ValueError(f"Unknown command: {command}")

# ---------- Error Handlers --------

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Not found",
        "path": request.path,
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        "success": False,
        "error": "Method not allowed",
        "method": request.method,
        "path": request.path,
    }), 405

@app.errorhandler(500)
def internal_error(error):
    logger.exception(f"Internal server error: {error}")
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500

# ---------- Main --------

if __name__ == "__main__":
    import sys
    
    host = os.getenv("SERVER_HOST", "0.0.0.0")
    port = int(os.getenv("SERVER_PORT", "5000"))
    debug = os.getenv("DEBUG", "false").lower() in {"1", "true", "yes"}
    
    logger.info("=" * 60)
    logger.info("Starting Terraform Remote Server - v11")
    logger.info("=" * 60)
    logger.info(f"Listening on {host}:{port}")
    logger.info(f"Terraform directory: {TERRAFORM_DIR}")
    logger.info(f"Terraform binary: {TERRAFORM_BIN}")
    logger.info(f"Log directory: {LOG_DIR}")
    logger.info(f"Debug mode: {debug}")
    logger.info(f"Allow unsafe operations: {ALLOW_UNSAFE_OPS}")
    logger.info("=" * 60)
    
    try:
        app.run(host=host, port=port, debug=debug, threaded=True)
    except KeyboardInterrupt:
        logger.info("Server shutdown")
        sys.exit(0)