import unittest
from unittest.mock import patch, MagicMock
import subprocess
import sys
import os
import logging
from pathlib import Path

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from docker_tool.command import run_on_host, run_on_container

class TestCommand(unittest.TestCase):

    def setUp(self):
        """Disable logging for tests."""
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        """Re-enable logging after tests."""
        logging.disable(logging.NOTSET)

    @patch('subprocess.run')
    def test_run_on_host_success_pipe_output(self, mock_subprocess_run):
        """Tests successful command execution with output capturing."""
        # Arrange
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "Command output\n"
        mock_subprocess_run.return_value = mock_process

        # Act
        result = run_on_host(['ls', '-l'], pipe_output=True)

        # Assert
        mock_subprocess_run.assert_called_once_with(
            ['ls', '-l'],
            input=None,
            capture_output=True,
            check=True,
            text=True,
            stderr=None
        )
        self.assertEqual(result, "Command output")

    @patch('subprocess.run')
    def test_run_on_host_no_pipe_output(self, mock_subprocess_run):
        """Tests successful command execution without output capturing."""
        # Arrange
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = None # No output captured
        mock_subprocess_run.return_value = mock_process

        # Act
        result = run_on_host(['echo', 'hello'], pipe_output=False)

        # Assert
        self.assertIsNone(result)

    @patch('sys.exit')
    @patch('subprocess.run')
    def test_run_on_host_called_process_error(self, mock_subprocess_run, mock_sys_exit):
        """Tests that CalledProcessError is caught and sys.exit is called."""
        # Arrange
        mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, ['bad_command'])

        # Act
        run_on_host(['bad_command'], check_error=True)

        # Assert
        mock_sys_exit.assert_called_once_with(1)

    @patch('sys.exit')
    @patch('subprocess.run')
    def test_run_on_host_file_not_found_error(self, mock_subprocess_run, mock_sys_exit):
        """Tests that FileNotFoundError is caught and sys.exit is called."""
        # Arrange
        mock_subprocess_run.side_effect = FileNotFoundError

        # Act
        run_on_host(['non_existent_cmd'])

        # Assert
        mock_sys_exit.assert_called_once_with(1)

    @patch('docker_tool.command.run_on_host')
    def test_run_on_container(self, mock_run_on_host):
        """Tests that run_on_container constructs the correct nsenter command."""
        # Arrange
        container_pid = 12345
        container_root = Path('/var/lib/container/rootfs')
        cmd_to_run = "ip addr show eth0"
        mock_run_on_host.return_value = "Mocked output"

        # Act
        result = run_on_container(container_pid, cmd_to_run, container_root)

        # Assert
        expected_nsenter_cmd = [
            "nsenter",
            "-t",
            str(container_pid),
            "--mount",
            "--net",
            "--uts",
            f"--root={container_root}",
            "/bin/sh",
            "-c",
            cmd_to_run,
        ]
        mock_run_on_host.assert_called_once_with(
            expected_nsenter_cmd, pipe_output=True, check_error=True
        )
        self.assertEqual(result, "Mocked output")

if __name__ == '__main__':
    unittest.main()