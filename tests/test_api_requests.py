import unittest
from unittest.mock import patch, MagicMock, mock_open
import sys
import os
import logging

# Add the src directory to the Python path to allow for absolute imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from docker_tool.api_requests import request

class TestApiRequests(unittest.TestCase):

    def setUp(self):
        """Disable logging for tests."""
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        """Re-enable logging after tests."""
        logging.disable(logging.NOTSET)

    @patch('http.client.HTTPSConnection')
    def test_successful_request_200_ok(self, mock_https_connection):
        """Tests a simple, successful GET request that returns 200 OK."""
        # Arrange
        mock_conn_instance = MagicMock()
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"status": "ok"}'
        
        mock_conn_instance.getresponse.return_value = mock_response
        mock_https_connection.return_value = mock_conn_instance

        # Act
        data, status = request('example.com', '/test')

        # Assert
        mock_https_connection.assert_called_once_with('example.com', context=unittest.mock.ANY)
        mock_conn_instance.request.assert_called_once_with('GET', '/test', headers={})
        self.assertEqual(status, 200)
        self.assertEqual(data, '{"status": "ok"}')

    @patch('http.client.HTTPSConnection')
    def test_single_redirect_handling(self, mock_https_connection):
        """Tests that the function correctly follows a 301 redirect."""
        # Arrange
        mock_conn_instance = MagicMock()
        
        # First response (redirect)
        redirect_response = MagicMock()
        redirect_response.status = 301
        redirect_response.getheader.return_value = 'https://new.example.com/redirected'
        
        # Second response (final)
        final_response = MagicMock()
        final_response.status = 200
        final_response.read.return_value = b'final destination'
        
        mock_conn_instance.getresponse.side_effect = [redirect_response, final_response]
        mock_https_connection.return_value = mock_conn_instance

        # Act
        data, status = request('example.com', '/test')

        # Assert
        self.assertEqual(mock_https_connection.call_count, 2)
        mock_https_connection.assert_any_call('example.com', context=unittest.mock.ANY)
        mock_https_connection.assert_called_with('new.example.com', context=unittest.mock.ANY)
        
        self.assertEqual(status, 200)
        self.assertEqual(data, 'final destination')

    @patch('http.client.HTTPSConnection')
    def test_max_redirects_reached(self, mock_https_connection):
        """Tests that the function stops after reaching the maximum redirect limit."""
        # Arrange
        mock_conn_instance = MagicMock()
        
        redirect_response = MagicMock()
        redirect_response.status = 307
        redirect_response.getheader.return_value = 'https://loop.example.com/redirect'
        
        mock_conn_instance.getresponse.return_value = redirect_response
        mock_https_connection.return_value = mock_conn_instance

        # Act
        data, status = request('example.com', '/test')

        # Assert
        self.assertEqual(mock_conn_instance.getresponse.call_count, 5) # MAX_REDIRECTS = 5
        self.assertIsNone(data)
        self.assertIsNone(status)

    @patch('http.client.HTTPSConnection')
    def test_http_error_404(self, mock_https_connection):
        """Tests handling of a client error, e.g., 404 Not Found."""
        # Arrange
        mock_conn_instance = MagicMock()
        mock_response = MagicMock()
        mock_response.status = 404
        mock_response.read.return_value = b'Not Found'
        
        mock_conn_instance.getresponse.return_value = mock_response
        mock_https_connection.return_value = mock_conn_instance

        # Act
        data, status = request('example.com', '/test')

        # Assert
        self.assertEqual(status, 404)
        self.assertEqual(data, 'Not Found')

    @patch('builtins.open', new_callable=mock_open)
    @patch('shutil.copyfileobj')
    @patch('http.client.HTTPSConnection')
    def test_request_with_save_path(self, mock_https_connection, mock_copyfileobj, mock_file_open):
        """Tests that the response is written to a file when save_path is provided."""
        # Arrange
        mock_conn_instance = MagicMock()
        mock_response = MagicMock()
        mock_response.status = 200
        
        mock_conn_instance.getresponse.return_value = mock_response
        mock_https_connection.return_value = mock_conn_instance
        
        save_path = '/tmp/test_download.dat'

        # Act
        data, status = request('example.com', '/test', save_path=save_path)

        # Assert
        mock_file_open.assert_called_once_with(save_path, 'wb')
        mock_copyfileobj.assert_called_once()
        self.assertEqual(status, 200)
        self.assertEqual(data, 'File saved')

if __name__ == '__main__':
    unittest.main()