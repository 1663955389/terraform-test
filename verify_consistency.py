#!/usr/bin/env python3
"""
Manual verification script for final consistency cleanups.
This script performs lightweight sanity checks to ensure:
1. Servers can start
2. Core endpoints behave correctly
3. Error responses include workspace field consistently
"""

import os
import sys
import tempfile
import json
from pathlib import Path

# Set up temporary directories
temp_log_dir = tempfile.mkdtemp(prefix='verify-log-')
temp_terraform_dir = tempfile.mkdtemp(prefix='verify-terraform-')
temp_audit_log_fd, temp_audit_log = tempfile.mkstemp(suffix='.jsonl', prefix='verify-audit-')
os.close(temp_audit_log_fd)  # Close the file descriptor, we only need the path

os.environ['LOG_DIR'] = temp_log_dir
os.environ['TERRAFORM_DIR'] = temp_terraform_dir
os.environ['MCP_AUDIT_LOG'] = temp_audit_log
os.environ['EXECUTION_MODE'] = 'local'

# Import modules after setting environment
sys.path.insert(0, str(Path(__file__).parent))
import remote_server
import server

print("=" * 70)
print("MANUAL VERIFICATION SCRIPT")
print("=" * 70)

# Test 1: Module imports successful
print("\n✓ Test 1: Module imports successful")
print(f"  - remote_server module loaded")
print(f"  - server module loaded")

# Test 2: Remote server Flask app created
print("\n✓ Test 2: Remote server Flask app created")
print(f"  - Flask app name: {remote_server.app.name}")
print(f"  - Terraform dir: {remote_server.TERRAFORM_DIR}")

# Test 3: MCP server created
print("\n✓ Test 3: MCP server created")
print(f"  - Server name: {server.mcp_server.name}")
print(f"  - Execution mode: {server.EXECUTION_MODE}")

# Test 4: Test remote_server error responses include workspace field
print("\n✓ Test 4: Remote server error responses include workspace field")
client = remote_server.app.test_client()

# Test /terraform/output with invalid workspace
response = client.get('/terraform/output/invalid@workspace')
data = json.loads(response.data)
assert response.status_code == 400
assert "workspace" in data, "Missing workspace field in /terraform/output error response"
assert data["workspace"] == "invalid@workspace"
print(f"  - /terraform/output invalid workspace: includes workspace field ✓")

# Test /terraform/output with nonexistent workspace
response = client.get('/terraform/output/nonexistent')
data = json.loads(response.data)
assert response.status_code == 404
assert "workspace" in data, "Missing workspace field in /terraform/output 404 response"
assert data["workspace"] == "nonexistent"
print(f"  - /terraform/output nonexistent workspace: includes workspace field ✓")

# Test /terraform with nonexistent workspace
response = client.post('/terraform', json={"command": "init", "workspace": "nonexistent"})
data = json.loads(response.data)
assert response.status_code == 404
assert "workspace" in data, "Missing workspace field in /terraform 404 response"
assert data["workspace"] == "nonexistent"
print(f"  - /terraform nonexistent workspace: includes workspace field ✓")

# Test 5: Test server.py local file operations
print("\n✓ Test 5: Server local file operations workspace-not-found errors")
import asyncio

async def test_get_file():
    result = await server.call_tool(
        name="get_file",
        arguments={"workspace": "nonexistent", "filename": "main.tf"}
    )
    response = json.loads(result[0].text)
    assert response["success"] is False
    assert "workspace" in response, "Missing workspace field in get_file error"
    assert "Workspace not found" in response["error"]
    return "get_file"

async def test_delete_file():
    result = await server.call_tool(
        name="delete_file",
        arguments={"workspace": "nonexistent", "filename": "main.tf"}
    )
    response = json.loads(result[0].text)
    assert response["success"] is False
    assert "workspace" in response, "Missing workspace field in delete_file error"
    assert "Workspace not found" in response["error"]
    return "delete_file"

asyncio.run(test_get_file())
print(f"  - get_file nonexistent workspace: workspace-not-found error ✓")

asyncio.run(test_delete_file())
print(f"  - delete_file nonexistent workspace: workspace-not-found error ✓")

# Test 6: Verify file-not-found vs workspace-not-found distinction
print("\n✓ Test 6: File-not-found vs workspace-not-found distinction")

# Create a workspace
workspace_dir = Path(temp_terraform_dir) / "test-workspace"
workspace_dir.mkdir(parents=True, exist_ok=True)

async def test_file_not_found():
    result = await server.call_tool(
        name="get_file",
        arguments={"workspace": "test-workspace", "filename": "missing.tf"}
    )
    response = json.loads(result[0].text)
    assert response["success"] is False
    assert "File not found" in response["error"]
    assert "Workspace not found" not in response["error"]
    return "file_not_found"

asyncio.run(test_file_not_found())
print(f"  - get_file existing workspace, missing file: file-not-found error ✓")

# Cleanup
import shutil
shutil.rmtree(temp_log_dir, ignore_errors=True)
shutil.rmtree(temp_terraform_dir, ignore_errors=True)
os.unlink(temp_audit_log)

print("\n" + "=" * 70)
print("ALL VERIFICATION CHECKS PASSED ✓")
print("=" * 70)
print("\nSummary:")
print("  - Modules import successfully")
print("  - Remote server app created")
print("  - MCP server created")
print("  - All error responses include workspace field consistently")
print("  - Workspace-not-found errors used when appropriate")
print("  - File-not-found errors used when workspace exists but file doesn't")
print("\n✅ Runtime behavior verified successfully!")
