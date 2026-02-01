"""
Test suite for final consistency cleanup changes:
- remote_server.py: workspace field in all /terraform/output error responses
- remote_server.py: workspace field in all /terraform error responses  
- server.py: workspace-not-found error in get_file/delete_file when workspace dir missing
"""

import pytest
import json
import tempfile
import shutil
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys
import subprocess

# Set up environment variables before importing modules
_temp_log_dir = tempfile.mkdtemp()
_temp_terraform_dir = tempfile.mkdtemp()
_temp_audit_log = tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False, prefix='test-final-consistency-').name

os.environ['LOG_DIR'] = _temp_log_dir
os.environ['TERRAFORM_DIR'] = _temp_terraform_dir
os.environ['MCP_AUDIT_LOG'] = _temp_audit_log

# Import the modules to test
sys.path.insert(0, str(Path(__file__).parent))
import remote_server
import server


def cleanup_test_environment():
    """Clean up test environment files and directories"""
    for dir_path in [_temp_log_dir, _temp_terraform_dir]:
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path, ignore_errors=True)
    
    if os.path.exists(_temp_audit_log):
        os.unlink(_temp_audit_log)


import atexit
atexit.register(cleanup_test_environment)


class TestRemoteServerOutputErrorResponses:
    """Test that all /terraform/output error responses include workspace field"""
    
    def setup_method(self):
        self.app = remote_server.app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.temp_dir = tempfile.mkdtemp()
        remote_server.TERRAFORM_DIR = self.temp_dir
    
    def teardown_method(self):
        if hasattr(self, 'temp_dir') and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def test_output_exception_includes_workspace(self):
        """Test that general exception handler includes workspace field"""
        workspace = "test-workspace"
        workspace_dir = Path(self.temp_dir) / workspace
        workspace_dir.mkdir(parents=True, exist_ok=True)
        
        # Mock subprocess.run to raise an exception
        with patch('remote_server.subprocess.run') as mock_run:
            mock_run.side_effect = RuntimeError("Simulated error")
            
            response = self.client.get(f'/terraform/output/{workspace}')
            
            assert response.status_code == 500
            data = json.loads(response.data)
            assert data["success"] is False
            assert "workspace" in data, "Exception handler should include workspace field"
            assert data["workspace"] == workspace
            assert "error" in data


class TestRemoteServerTerraformErrorResponses:
    """Test that all /terraform error responses include workspace field"""
    
    def setup_method(self):
        self.app = remote_server.app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.temp_dir = tempfile.mkdtemp()
        remote_server.TERRAFORM_DIR = self.temp_dir
    
    def teardown_method(self):
        if hasattr(self, 'temp_dir') and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def test_terraform_404_includes_workspace(self):
        """Test that 404 response includes workspace field"""
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
        assert "workspace" in data, "404 response should include workspace field"
        assert data["workspace"] == "nonexistent"
        assert "Workspace not found" in data["error"]
    
    def test_terraform_timeout_includes_workspace(self):
        """Test that timeout exception handler includes workspace field"""
        workspace = "test-workspace"
        workspace_dir = Path(self.temp_dir) / workspace
        workspace_dir.mkdir(parents=True, exist_ok=True)
        
        # Mock subprocess.run to raise TimeoutExpired
        with patch('remote_server.subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd=['terraform', 'init'], timeout=5)
            
            response = self.client.post(
                '/terraform',
                json={
                    "command": "init",
                    "workspace": workspace
                },
                content_type='application/json'
            )
            
            assert response.status_code == 408
            data = json.loads(response.data)
            assert data["success"] is False
            assert "workspace" in data, "Timeout handler should include workspace field"
            assert data["workspace"] == workspace
    
    def test_terraform_exception_includes_workspace(self):
        """Test that general exception handler includes workspace field"""
        workspace = "test-workspace"
        workspace_dir = Path(self.temp_dir) / workspace
        workspace_dir.mkdir(parents=True, exist_ok=True)
        
        # Mock subprocess.run to raise an exception
        with patch('remote_server.subprocess.run') as mock_run:
            mock_run.side_effect = RuntimeError("Simulated error")
            
            response = self.client.post(
                '/terraform',
                json={
                    "command": "init",
                    "workspace": workspace
                },
                content_type='application/json'
            )
            
            assert response.status_code == 500
            data = json.loads(response.data)
            assert data["success"] is False
            assert "workspace" in data, "Exception handler should include workspace field"
            assert data["workspace"] == workspace


class TestServerLocalFileOperationsWorkspaceNotFound:
    """Test that server.py get_file and delete_file return workspace-not-found errors"""
    
    def setup_method(self):
        if os.path.exists(_temp_audit_log):
            os.unlink(_temp_audit_log)
    
    def test_get_file_workspace_not_found(self):
        """Test that get_file returns workspace-not-found error when workspace dir missing"""
        import asyncio
        from server import call_tool
        
        original_mode = server.EXECUTION_MODE
        server.EXECUTION_MODE = "local"
        
        try:
            async def test_call():
                result = await call_tool(
                    name="get_file",
                    arguments={
                        "workspace": "nonexistent",
                        "filename": "main.tf"
                    }
                )
                return result
            
            result = asyncio.run(test_call())
            assert len(result) == 1
            
            response = json.loads(result[0].text)
            assert response["success"] is False
            assert "workspace" in response, "Should include workspace field"
            assert response["workspace"] == "nonexistent"
            assert "Workspace not found" in response["error"]
            
        finally:
            server.EXECUTION_MODE = original_mode
    
    def test_delete_file_workspace_not_found(self):
        """Test that delete_file returns workspace-not-found error when workspace dir missing"""
        import asyncio
        from server import call_tool
        
        original_mode = server.EXECUTION_MODE
        server.EXECUTION_MODE = "local"
        
        try:
            async def test_call():
                result = await call_tool(
                    name="delete_file",
                    arguments={
                        "workspace": "nonexistent",
                        "filename": "main.tf"
                    }
                )
                return result
            
            result = asyncio.run(test_call())
            assert len(result) == 1
            
            response = json.loads(result[0].text)
            assert response["success"] is False
            assert "workspace" in response, "Should include workspace field"
            assert response["workspace"] == "nonexistent"
            assert "Workspace not found" in response["error"]
            
        finally:
            server.EXECUTION_MODE = original_mode
    
    def test_get_file_workspace_exists_file_not_found(self):
        """Test that get_file returns file-not-found (not workspace-not-found) when workspace exists"""
        import asyncio
        from server import call_tool
        
        original_mode = server.EXECUTION_MODE
        server.EXECUTION_MODE = "local"
        
        # Create workspace directory
        workspace = "existing-workspace"
        workspace_dir = Path(server.TERRAFORM_DIR) / workspace
        workspace_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            async def test_call():
                result = await call_tool(
                    name="get_file",
                    arguments={
                        "workspace": workspace,
                        "filename": "missing.tf"
                    }
                )
                return result
            
            result = asyncio.run(test_call())
            assert len(result) == 1
            
            response = json.loads(result[0].text)
            assert response["success"] is False
            # Should say "File not found", NOT "Workspace not found"
            assert "File not found" in response["error"]
            assert "Workspace not found" not in response["error"]
            
        finally:
            server.EXECUTION_MODE = original_mode
            if workspace_dir.exists():
                shutil.rmtree(workspace_dir)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
