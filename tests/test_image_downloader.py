
import unittest
from unittest.mock import patch, MagicMock, mock_open, call
import sys
import os
import json
import logging
from pathlib import Path

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

# Now we can import the module
from docker_tool import image_downloader

class TestImageDownloader(unittest.TestCase):

    def setUp(self):
        """Set up common test data and disable logging."""
        logging.disable(logging.CRITICAL)
        self.image = "library/hello-world"
        self.tag = "latest"
        self.architecture = "amd64"
        self.token = "dummy_token"
        self.digest = "sha256:dummy_digest_for_amd64"
        self.config_digest = "sha256:dummy_config_digest"
        self.layer_digests = ["sha256:layer1", "sha256:layer2"]

    def tearDown(self):
        """Re-enable logging after tests."""
        logging.disable(logging.NOTSET)

    @patch('docker_tool.image_downloader.request')
    def test_get_authorization_token_success(self, mock_request):
        """Tests successful retrieval of an authorization token."""
        # Arrange
        mock_response_data = json.dumps({"token": self.token})
        mock_request.return_value = (mock_response_data, 200)

        # Act
        token = image_downloader.get_authorization_token(self.image)

        # Assert
        mock_request.assert_called_once_with(
            "auth.docker.io",
            f"/token?service=registry.docker.io&scope=repository:{self.image}:pull"
        )
        self.assertEqual(token, self.token)

    @patch('docker_tool.image_downloader.request')
    def test_get_authorization_token_failure(self, mock_request):
        """Tests failure to retrieve a token."""
        # Arrange
        mock_request.return_value = ("Error", 401)

        # Act & Assert
        with self.assertRaises(Exception) as context:
            image_downloader.get_authorization_token(self.image)
        self.assertIn("Authentication server did not return a valid response", str(context.exception))

    @patch('docker_tool.image_downloader.request')
    def test_get_manifest_list_and_digest_success(self, mock_request):
        """Tests successful manifest list retrieval and digest extraction."""
        # Arrange
        manifest_list = {
            "manifests": [
                {"platform": {"architecture": "arm64"}, "digest": "sha256:arm_digest"},
                {"platform": {"architecture": "amd64"}, "digest": self.digest}
            ]
        }
        mock_request.return_value = (json.dumps(manifest_list), 200)

        # Act
        digest = image_downloader.get_manifest_list_and_digest(self.image, self.tag, self.architecture, self.token)

        # Assert
        expected_headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.docker.distribution.manifest.list.v2+json",
        }
        mock_request.assert_called_once_with(
            "registry-1.docker.io",
            f"/v2/{self.image}/manifests/{self.tag}",
            headers=expected_headers
        )
        self.assertEqual(digest, self.digest)

    @patch('builtins.open', new_callable=mock_open)
    @patch('docker_tool.image_downloader.request')
    def test_download_manifest_success(self, mock_request, mock_file):
        """Tests successful download and parsing of an image manifest."""
        # Arrange
        manifest_data = {
            "config": {"digest": self.config_digest},
            "layers": [{"digest": d} for d in self.layer_digests]
        }
        mock_request.return_value = (json.dumps(manifest_data), 200)
        mock_build_temp_dir = Path("/tmp/build")

        # Act
        layer_digests, config_digest = image_downloader.download_manifest(
            self.image, self.digest, self.token, mock_build_temp_dir
        )

        # Assert
        self.assertEqual(layer_digests, self.layer_digests)
        self.assertEqual(config_digest, self.config_digest)
        # Check that manifest.json and blobs_list.txt were written
        mock_file.assert_any_call(mock_build_temp_dir / "manifest.json", "w")
        mock_file.assert_any_call(mock_build_temp_dir / "blobs_list.txt", "w")

    @patch('pathlib.Path.mkdir')
    @patch('docker_tool.image_downloader.request')
    def test_download_layers_success(self, mock_request, mock_mkdir):
        """Tests successful download of all layers."""
        # Arrange
        mock_request.return_value = ("File saved", 200)
        mock_layers_dir = Path("/tmp/layers")

        # Act
        result = image_downloader.download_layers(self.token, self.image, self.layer_digests, mock_layers_dir)

        # Assert
        self.assertTrue(result)
        mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
        
        # Verify request was called for each layer
        calls = []
        for digest in self.layer_digests:
            hash_part = digest.split(':', 1)[1]
            layer_path = mock_layers_dir / f"{hash_part}.tar.gz"
            calls.append(call(
                "registry-1.docker.io",
                f"/v2/{self.image}/blobs/{digest}",
                headers={"Authorization": f"Bearer {self.token}"},
                save_path=layer_path
            ))
        mock_request.assert_has_calls(calls, any_order=True)

if __name__ == '__main__':
    unittest.main()
