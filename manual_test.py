#!/usr/bin/env python
"""
Manual verification script for consistency polish changes
"""
import json
import tempfile
import os
from pathlib import Path

# Set up temporary environment
temp_dir = tempfile.mkdtemp()
os.environ['TERRAFORM_DIR'] = temp_dir
os.environ['LOG_DIR'] = temp_dir

print("=" * 60)
print("Manual Verification of Consistency Polish Changes")
print("=" * 60)

# Test 1: remote_server.py - terraform_execute with non-existent workspace
print("\n1. Testing terraform_execute with non-existent workspace...")
print("-" * 60)

from remote_server import app
app.config['TESTING'] = True
client = app.test_client()

response = client.post(
    '/terraform',
    json={
        "command": "init",
        "workspace": "nonexistent"
    },
    content_type='application/json'
)

print(f"Status Code: {response.status_code}")
data = json.loads(response.data)
print(f"Response: {json.dumps(data, indent=2)}")
assert response.status_code == 404, "Expected 404 for non-existent workspace"
assert "Workspace not found" in data["error"], "Expected workspace not found error"
print("✓ PASSED: Returns 404 for non-existent workspace")

# Test 2: remote_server.py - /terraform/output with invalid workspace
print("\n2. Testing /terraform/output with invalid workspace...")
print("-" * 60)

response = client.get('/terraform/output/invalid@workspace')

print(f"Status Code: {response.status_code}")
data = json.loads(response.data)
print(f"Response: {json.dumps(data, indent=2)}")
assert response.status_code == 400, "Expected 400 for invalid workspace"
assert "workspace" in data, "Expected workspace field in error response"
assert data["workspace"] == "invalid@workspace", "Expected workspace field to match input"
print("✓ PASSED: Returns 400 with workspace field for invalid workspace")

# Test 3: remote_server.py - /terraform/output with non-existent workspace
print("\n3. Testing /terraform/output with non-existent workspace...")
print("-" * 60)

response = client.get('/terraform/output/nonexistent')

print(f"Status Code: {response.status_code}")
data = json.loads(response.data)
print(f"Response: {json.dumps(data, indent=2)}")
assert response.status_code == 404, "Expected 404 for non-existent workspace"
assert "workspace" in data, "Expected workspace field in error response"
assert data["workspace"] == "nonexistent", "Expected workspace field to match input"
print("✓ PASSED: Returns 404 with workspace field for non-existent workspace")

# Test 4: Verify terraform_execute does not create workspace
print("\n4. Testing terraform_execute does not create workspace...")
print("-" * 60)

workspace_dir = Path(temp_dir) / "should-not-exist"
print(f"Workspace directory before request: {workspace_dir.exists()}")

response = client.post(
    '/terraform',
    json={
        "command": "init",
        "workspace": "should-not-exist"
    },
    content_type='application/json'
)

print(f"Status Code: {response.status_code}")
print(f"Workspace directory after request: {workspace_dir.exists()}")
assert not workspace_dir.exists(), "Workspace should not have been created"
print("✓ PASSED: terraform_execute does not implicitly create workspace")

# Clean up
import shutil
shutil.rmtree(temp_dir, ignore_errors=True)

print("\n" + "=" * 60)
print("All manual verifications PASSED!")
print("=" * 60)
