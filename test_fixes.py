"""
Test suite for server.py and remote_server.py fixes
Tests timeout clamping, ValueError handling, audit logging, and list_workspaces consistency
"""

import pytest
import json
import tempfile
import shutil
import os
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock
import sys

# Set up environment variables before importing modules
os.environ['LOG_DIR'] = tempfile.mkdtemp()
os.environ['TERRAFORM_DIR'] = tempfile.mkdtemp()
os.environ['MCP_AUDIT_LOG'] = os.path.join(tempfile.gettempdir(), 'test-audit.jsonl')

# Import the modules to test
sys.path.insert(0, str(Path(__file__).parent))
import remote_server
import server


class TestRemoteServerTimeoutClamping:
    """Test timeout clamping in remote_server.py"""
    
    def test_clamp_timeout_helper_lower_bound(self):
        """Test that timeout is clamped to minimum of 1"""
        assert remote_server._clamp_timeout(0) == 1
        assert remote_server._clamp_timeout(-5) == 1
        assert remote_server._clamp_timeout(-100) == 1
    
    def test_clamp_timeout_helper_upper_bound(self):
        """Test that timeout is clamped to MAX_TIMEOUT"""
        max_timeout = remote_server.MAX_TIMEOUT
        assert remote_server._clamp_timeout(max_timeout + 1) == max_timeout
        assert remote_server._clamp_timeout(max_timeout + 100) == max_timeout
        assert remote_server._clamp_timeout(9999) == max_timeout
    
    def test_clamp_timeout_helper_valid_range(self):
        """Test that valid timeouts are not modified"""
        assert remote_server._clamp_timeout(1) == 1
        assert remote_server._clamp_timeout(30) == 30
        assert remote_server._clamp_timeout(60) == 60
        assert remote_server._clamp_timeout(remote_server.MAX_TIMEOUT) == remote_server.MAX_TIMEOUT


class TestRemoteServerValueError:
    """Test ValueError handling in remote_server.py"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.app = remote_server.app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
    
    def test_terraform_execute_invalid_workspace(self):
        """Test that terraform_execute returns 400 for invalid workspace names"""
        invalid_workspaces = [
            "../etc/passwd",  # Path traversal
            "workspace@bad",  # Invalid character
            "workspace with spaces",  # Spaces
            "a" * 65,  # Too long
            "",  # Empty
        ]
        
        for workspace in invalid_workspaces:
            response = self.client.post(
                '/terraform',
                json={
                    "command": "init",
                    "workspace": workspace
                },
                content_type='application/json'
            )
            assert response.status_code == 400, f"Expected 400 for workspace: {workspace}"
            data = json.loads(response.data)
            assert data["success"] is False
            assert "Invalid workspace name" in data["error"]
    
    def test_list_files_invalid_workspace(self):
        """Test that list_files returns 400 for invalid workspace names"""
        invalid_workspace = "workspace@bad"  # Use invalid character instead of path traversal
        response = self.client.get(f'/terraform/files/{invalid_workspace}')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["success"] is False
        assert "Invalid workspace name" in data["error"]
    
    def test_get_file_invalid_workspace(self):
        """Test that get_file returns 400 for invalid workspace names"""
        invalid_workspace = "workspace@bad"
        response = self.client.get(f'/terraform/file/{invalid_workspace}/main.tf')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["success"] is False
        assert "Invalid workspace name" in data["error"]
    
    def test_delete_file_invalid_workspace(self):
        """Test that delete_file returns 400 for invalid workspace names"""
        invalid_workspace = "workspace with spaces"
        response = self.client.delete(f'/terraform/file/{invalid_workspace}/main.tf')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["success"] is False
        assert "Invalid workspace name" in data["error"]


class TestRemoteServerOutputTimeout:
    """Test output endpoint timeout parameter support"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.app = remote_server.app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        
        # Create a temporary workspace
        self.temp_dir = tempfile.mkdtemp()
        remote_server.TERRAFORM_DIR = self.temp_dir
        workspace_dir = Path(self.temp_dir) / "test-workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)
    
    def teardown_method(self):
        """Clean up test fixtures"""
        if hasattr(self, 'temp_dir') and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    @patch('remote_server.subprocess.run')
    def test_output_endpoint_uses_timeout_parameter(self, mock_run):
        """Test that output endpoint uses timeout parameter from query string"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{}',
            stderr=''
        )
        
        # Test with custom timeout
        response = self.client.get('/terraform/output/test-workspace?timeout=60')
        assert response.status_code == 200
        
        # Verify subprocess.run was called with the clamped timeout
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs['timeout'] == 60
    
    @patch('remote_server.subprocess.run')
    def test_output_endpoint_clamps_timeout(self, mock_run):
        """Test that output endpoint clamps timeout values"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{}',
            stderr=''
        )
        
        # Test with timeout below minimum
        response = self.client.get('/terraform/output/test-workspace?timeout=0')
        assert response.status_code == 200
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs['timeout'] >= 1
        
        # Reset mock
        mock_run.reset_mock()
        
        # Test with timeout above maximum
        response = self.client.get('/terraform/output/test-workspace?timeout=9999')
        assert response.status_code == 200
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs['timeout'] <= remote_server.MAX_TIMEOUT


class TestServerAuditLogging:
    """Test audit logging in server.py"""
    
    def test_audit_log_on_workspace_validation_failure(self):
        """Test that audit log is written when workspace validation fails"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            audit_log_path = Path(f.name)
        
        try:
            # Patch the AUDIT_LOG path
            original_audit_log = server.AUDIT_LOG
            server.AUDIT_LOG = audit_log_path
            
            # Create a mock tool call with invalid workspace
            from server import call_tool
            import asyncio
            
            async def test_call():
                result = await call_tool(
                    name="execute_terraform",
                    arguments={
                        "workspace": "../invalid",
                        "command": "init"
                    }
                )
                return result
            
            # Run the async function
            result = asyncio.run(test_call())
            
            # Verify the response indicates failure
            assert len(result) == 1
            response = json.loads(result[0].text)
            assert response["success"] is False
            assert "Invalid workspace name" in response["error"]
            
            # Verify audit log was written
            assert audit_log_path.exists()
            with audit_log_path.open('r') as f:
                logs = [json.loads(line) for line in f if line.strip()]
            
            # Should have at least one log entry
            assert len(logs) >= 1
            
            # Find the blocked entry
            blocked_entry = None
            for log in logs:
                if log.get("blocked") is True:
                    blocked_entry = log
                    break
            
            assert blocked_entry is not None, "No blocked entry found in audit log"
            assert "Invalid workspace name" in blocked_entry["reason"]
            assert blocked_entry["workspace"] == "../invalid"
            
        finally:
            # Restore original audit log path
            server.AUDIT_LOG = original_audit_log
            # Clean up
            if audit_log_path.exists():
                audit_log_path.unlink()


class TestListWorkspacesConsistency:
    """Test list_workspaces response structure consistency"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test workspaces
        for workspace_name in ["workspace1", "workspace2"]:
            workspace_dir = Path(self.temp_dir) / workspace_name
            workspace_dir.mkdir(parents=True, exist_ok=True)
            
            # Create some .tf files
            (workspace_dir / "main.tf").write_text("# Test")
            (workspace_dir / "variables.tf").write_text("# Test")
    
    def teardown_method(self):
        """Clean up test fixtures"""
        if hasattr(self, 'temp_dir') and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def test_remote_server_list_workspaces_structure(self):
        """Test remote_server list_workspaces returns objects with name, file_count, created_at"""
        app = remote_server.app
        app.config['TESTING'] = True
        client = app.test_client()
        
        # Temporarily override TERRAFORM_DIR
        original_dir = remote_server.TERRAFORM_DIR
        remote_server.TERRAFORM_DIR = self.temp_dir
        
        try:
            response = client.get('/terraform/workspace')
            assert response.status_code == 200
            
            data = json.loads(response.data)
            assert data["success"] is True
            assert "workspaces" in data
            
            workspaces = data["workspaces"]
            assert len(workspaces) == 2
            
            # Verify structure of each workspace
            for workspace in workspaces:
                assert "name" in workspace
                assert "file_count" in workspace
                assert "created_at" in workspace
                assert isinstance(workspace["name"], str)
                assert isinstance(workspace["file_count"], int)
                assert isinstance(workspace["created_at"], str)
                
                # Verify created_at is a valid ISO timestamp
                datetime.fromisoformat(workspace["created_at"])
        
        finally:
            remote_server.TERRAFORM_DIR = original_dir
    
    def test_server_local_mode_list_workspaces_structure(self):
        """Test server.py local mode returns same structure as remote mode"""
        import asyncio
        from server import call_tool
        
        # Temporarily override mode and directory
        original_mode = server.EXECUTION_MODE
        original_dir = server.TERRAFORM_DIR
        server.EXECUTION_MODE = "local"
        server.TERRAFORM_DIR = self.temp_dir
        
        try:
            async def test_call():
                result = await call_tool(
                    name="list_workspaces",
                    arguments={}
                )
                return result
            
            result = asyncio.run(test_call())
            assert len(result) == 1
            
            response = json.loads(result[0].text)
            assert response["success"] is True
            assert "workspaces" in response
            
            workspaces = response["workspaces"]
            assert len(workspaces) == 2
            
            # Verify structure matches remote mode
            for workspace in workspaces:
                assert "name" in workspace
                assert "file_count" in workspace
                assert "created_at" in workspace
                assert isinstance(workspace["name"], str)
                assert isinstance(workspace["file_count"], int)
                assert isinstance(workspace["created_at"], str)
                
                # Verify created_at is a valid ISO timestamp
                datetime.fromisoformat(workspace["created_at"])
                
                # Verify file_count matches
                workspace_dir = Path(self.temp_dir) / workspace["name"]
                expected_count = len(list(workspace_dir.glob("*.tf")))
                assert workspace["file_count"] == expected_count
        
        finally:
            server.EXECUTION_MODE = original_mode
            server.TERRAFORM_DIR = original_dir


if __name__ == "__main__":
    # Run pytest
    pytest.main([__file__, "-v", "-s"])
