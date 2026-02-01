"""
Test suite for consistency polish changes
Tests workspace validation in list_files, workspace existence check in terraform_execute,
and workspace field in error responses
"""

import pytest
import json
import tempfile
import shutil
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys

# Set up environment variables before importing modules
_temp_log_dir = tempfile.mkdtemp()
_temp_terraform_dir = tempfile.mkdtemp()
_temp_audit_log = os.path.join(tempfile.gettempdir(), 'test-consistency-audit.jsonl')

os.environ['LOG_DIR'] = _temp_log_dir
os.environ['TERRAFORM_DIR'] = _temp_terraform_dir
os.environ['MCP_AUDIT_LOG'] = _temp_audit_log

# Import the modules to test
sys.path.insert(0, str(Path(__file__).parent))
import remote_server
import server


def cleanup_test_environment():
    """Clean up test environment files and directories"""
    # Clean up temp directories
    for dir_path in [_temp_log_dir, _temp_terraform_dir]:
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path, ignore_errors=True)
    
    # Clean up audit log file
    if os.path.exists(_temp_audit_log):
        os.unlink(_temp_audit_log)


# Register cleanup to run at exit
import atexit
atexit.register(cleanup_test_environment)


class TestServerListFilesValidation:
    """Test server.py list_files workspace validation in local mode"""
    
    def setup_method(self):
        """Set up test fixtures"""
        # Clean audit log before each test
        if os.path.exists(_temp_audit_log):
            os.unlink(_temp_audit_log)
    
    def test_list_files_invalid_workspace_local_mode(self):
        """Test that list_files validates workspace name and returns 400 with audit log in local mode"""
        import asyncio
        from server import call_tool
        
        # Temporarily override mode
        original_mode = server.EXECUTION_MODE
        server.EXECUTION_MODE = "local"
        
        try:
            async def test_call():
                result = await call_tool(
                    name="list_files",
                    arguments={"workspace": "../invalid"}
                )
                return result
            
            result = asyncio.run(test_call())
            assert len(result) == 1
            
            response = json.loads(result[0].text)
            assert response["success"] is False
            assert "Invalid workspace name" in response["error"]
            
            # Verify audit log was written with blocked=true
            # Note: The validation happens at the top-level call_tool function,
            # so the tool name in the audit log will be "list_files" but the
            # operation field may not be set since it happens before the handler
            audit_log_path = server.AUDIT_LOG
            assert audit_log_path.exists()
            
            with audit_log_path.open('r') as f:
                logs = [json.loads(line) for line in f if line.strip()]
            
            # Should have at least one log entry
            assert len(logs) >= 1
            
            # Find the blocked entry - it should have tool="list_files"
            blocked_entry = None
            for log in logs:
                if log.get("blocked") is True and log.get("tool") == "list_files":
                    blocked_entry = log
                    break
            
            assert blocked_entry is not None, "No blocked entry found in audit log"
            assert "Invalid workspace name" in blocked_entry["reason"]
            assert blocked_entry["workspace"] == "../invalid"
            
        finally:
            server.EXECUTION_MODE = original_mode
    
    def test_list_files_various_invalid_workspaces(self):
        """Test that list_files rejects various invalid workspace names"""
        import asyncio
        from server import call_tool
        
        original_mode = server.EXECUTION_MODE
        server.EXECUTION_MODE = "local"
        
        invalid_workspaces = [
            "../etc/passwd",  # Path traversal
            "workspace@bad",  # Invalid character
            "workspace with spaces",  # Spaces
            "a" * 65,  # Too long
            # Note: Empty string gets converted to "default" at the top level (line 621 in server.py)
        ]
        
        try:
            for workspace in invalid_workspaces:
                async def test_call():
                    result = await call_tool(
                        name="list_files",
                        arguments={"workspace": workspace}
                    )
                    return result
                
                result = asyncio.run(test_call())
                response = json.loads(result[0].text)
                
                assert response["success"] is False, f"Expected failure for workspace: {workspace}"
                assert "Invalid workspace name" in response["error"]
                
                # Verify audit log exists and has the blocked entry
                audit_log_path = server.AUDIT_LOG
                assert audit_log_path.exists()
                
                with audit_log_path.open('r') as f:
                    logs = [json.loads(line) for line in f if line.strip()]
                
                # Find a blocked entry for this specific workspace
                blocked_entry = next((log for log in logs if log.get("blocked") is True and log.get("workspace") == workspace), None)
                assert blocked_entry is not None, f"No blocked entry for workspace: {workspace}"
                
        finally:
            server.EXECUTION_MODE = original_mode


class TestRemoteServerTerraformExecuteWorkspaceCheck:
    """Test remote_server.py terraform_execute workspace existence check"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.app = remote_server.app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        
        # Create a temporary directory
        self.temp_dir = tempfile.mkdtemp()
        remote_server.TERRAFORM_DIR = self.temp_dir
    
    def teardown_method(self):
        """Clean up test fixtures"""
        if hasattr(self, 'temp_dir') and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def test_terraform_execute_nonexistent_workspace_returns_404(self):
        """Test that terraform_execute returns 404 for non-existent workspace"""
        response = self.client.post(
            '/terraform',
            json={
                "command": "init",
                "workspace": "nonexistent"
            },
            content_type='application/json'
        )
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert data["success"] is False
        assert "Workspace not found" in data["error"]
    
    def test_terraform_execute_existing_workspace_proceeds(self):
        """Test that terraform_execute proceeds for existing workspace"""
        # Create workspace directory
        workspace_dir = Path(self.temp_dir) / "test-workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)
        
        with patch('remote_server.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='Terraform initialized',
                stderr=''
            )
            
            response = self.client.post(
                '/terraform',
                json={
                    "command": "init",
                    "workspace": "test-workspace"
                },
                content_type='application/json'
            )
            
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["success"] is True
            
            # Verify subprocess.run was called (i.e., command was executed)
            mock_run.assert_called_once()
    
    def test_terraform_execute_does_not_create_workspace(self):
        """Test that terraform_execute does not implicitly create workspace"""
        response = self.client.post(
            '/terraform',
            json={
                "command": "init",
                "workspace": "auto-created"
            },
            content_type='application/json'
        )
        
        # Should return 404
        assert response.status_code == 404
        
        # Verify workspace was NOT created
        workspace_dir = Path(self.temp_dir) / "auto-created"
        assert not workspace_dir.exists(), "Workspace should not have been created"


class TestRemoteServerOutputWorkspaceField:
    """Test remote_server.py /terraform/output includes workspace field in error responses"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.app = remote_server.app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        
        # Create a temporary directory
        self.temp_dir = tempfile.mkdtemp()
        remote_server.TERRAFORM_DIR = self.temp_dir
    
    def teardown_method(self):
        """Clean up test fixtures"""
        if hasattr(self, 'temp_dir') and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def test_output_invalid_workspace_includes_workspace_field(self):
        """Test that output endpoint includes workspace field for invalid workspace"""
        invalid_workspace = "workspace@bad"
        
        response = self.client.get(f'/terraform/output/{invalid_workspace}')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["success"] is False
        assert "workspace" in data
        assert data["workspace"] == invalid_workspace
        assert "Invalid workspace name" in data["error"]
    
    def test_output_nonexistent_workspace_includes_workspace_field(self):
        """Test that output endpoint includes workspace field for non-existent workspace"""
        workspace = "nonexistent"
        
        response = self.client.get(f'/terraform/output/{workspace}')
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert data["success"] is False
        assert "workspace" in data
        assert data["workspace"] == workspace
        assert "Workspace not found" in data["error"]
    
    def test_output_success_includes_workspace_field(self):
        """Test that output endpoint includes workspace field on success"""
        # Create workspace directory
        workspace = "test-workspace"
        workspace_dir = Path(self.temp_dir) / workspace
        workspace_dir.mkdir(parents=True, exist_ok=True)
        
        with patch('remote_server.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='{}',
                stderr=''
            )
            
            response = self.client.get(f'/terraform/output/{workspace}')
            
            assert response.status_code == 200
            data = json.loads(response.data)
            assert "workspace" in data
            assert data["workspace"] == workspace


if __name__ == "__main__":
    # Run pytest
    pytest.main([__file__, "-v", "-s"])
