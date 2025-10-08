import unittest
from unittest.mock import patch, MagicMock, call, mock_open
import sys
import os
import ipaddress
import logging

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from docker_tool.network import (
    get_used_subnets,
    generate_network_config,
    create as create_network,
    remove as remove_network,
    NetworkGenerationError,
)

class TestNetwork(unittest.TestCase):

    def setUp(self):
        """Disable logging for tests."""
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        """Re-enable logging after tests."""
        logging.disable(logging.NOTSET)

    @patch('docker_tool.command.run_on_host')
    def test_get_used_subnets(self, mock_run_on_host):
        """Tests that used subnets are correctly parsed from 'ip route' output."""
        # Arrange
        mock_output = (
            "172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1\n"
            "192.168.1.0/24 dev wlp2s0 proto kernel scope link src 192.168.1.100\n"
            "invalid line format"
        )
        mock_run_on_host.return_value = mock_output

        # Act
        used_subnets = get_used_subnets()

        # Assert
        expected_subnets = {
            ipaddress.ip_network('172.17.0.0/16'),
            ipaddress.ip_network('192.168.1.0/24'),
        }
        self.assertEqual(used_subnets, expected_subnets)

    @patch('docker_tool.network.get_used_subnets')
    @patch('random.randint')
    def test_generate_network_config_success(self, mock_randint, mock_get_used_subnets):
        """Tests successful generation of a non-conflicting network configuration."""
        # Arrange
        mock_get_used_subnets.return_value = {ipaddress.ip_network('172.17.0.0/16')}
        # Force random.randint to return 18, creating 172.18.0.0/16 which doesn't conflict
        mock_randint.return_value = 18

        # Act
        config = generate_network_config()

        # Assert
        expected_net = ipaddress.ip_network('172.18.0.0/16')
        self.assertEqual(config['container_network'], str(expected_net))
        self.assertEqual(config['bridge_ip'], '172.18.0.1/16')
        self.assertEqual(config['container_ip'], '172.18.0.2/16')

    @patch('docker_tool.network.get_used_subnets')
    @patch('random.randint')
    def test_generate_network_config_failure_after_max_tries(self, mock_randint, mock_get_used_subnets):
        """Tests that an exception is raised if a free subnet cannot be found."""
        # Arrange
        # Simulate that all randomly generated subnets are already in use
        mock_get_used_subnets.return_value = {ipaddress.ip_network('172.18.0.0/16')}
        mock_randint.return_value = 18 # Always generate the conflicting subnet

        # Act & Assert
        with self.assertRaises(NetworkGenerationError):
            generate_network_config()

    @patch('docker_tool.command.run_on_container')
    @patch('docker_tool.command.run_on_host')
    @patch('builtins.open', new_callable=mock_open)
    def test_create_network_calls(self, mock_file, mock_run_on_host, mock_run_on_container):
        """Tests that create() calls the correct host and container commands."""
        # Arrange
        pid = 12345
        bridge = "br-test"
        # Act
        create_network(
            container_pid=pid,
            custom_bridge=bridge,
            container_root=MagicMock(),
            bridge_ip="172.20.0.1/16",
            container_network="172.20.0.0/16",
            container_ip="172.20.0.2/16",
            host_interface="eth0",
        )

        # Assert
        # Check a few key calls to ensure the logic is being followed
        mock_run_on_host.assert_any_call(["ip", "link", "add", "name", bridge, "type", "bridge"], ignore_stderr=True, check_error=False)
        mock_run_on_host.assert_any_call(["ip", "link", "set", bridge, "up"])
        mock_run_on_host.assert_any_call(["ip", "link", "set", f"h{pid}", "master", bridge])
        mock_run_on_host.assert_any_call(["ip", "link", "set", f"c{pid}", "netns", str(pid)])
        mock_run_on_host.assert_any_call(["iptables", "-w", "-t", "nat", "-I", "POSTROUTING", "1", "-s", "172.20.0.0/16", "-o", "eth0", "-j", "MASQUERADE"])
        mock_file.assert_called_once()
        mock_run_on_container.assert_called_once()

    @patch('docker_tool.command.run_on_host')
    def test_remove_network_calls(self, mock_run_on_host):
        """Tests that remove() calls the correct cleanup commands."""
        # Arrange
        bridge = "br-test"
        # Simulate that the bridge exists
        mock_run_on_host.side_effect = ["", "", "", "output", "", "", ""]

        # Act
        remove_network(
            custom_bridge=bridge,
            bridge_ip="172.20.0.1/16",
            container_network="172.20.0.0/16",
            host_interface="eth0",
        )

        # Assert
        mock_run_on_host.assert_any_call(["iptables", "-w", "-t", "nat", "-D", "POSTROUTING", "-s", "172.20.0.0/16", "-o", "eth0", "-j", "MASQUERADE"], check_error=False, ignore_stderr=True)
        mock_run_on_host.assert_any_call(["ip", "link", "set", bridge, "down"], check_error=False, ignore_stderr=True)
        mock_run_on_host.assert_any_call(["ip", "link", "del", bridge], check_error=False, ignore_stderr=True)

if __name__ == '__main__':
    unittest.main()