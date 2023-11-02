from .. import dlauthenticator
import unittest
from unittest.mock import patch, MagicMock, PropertyMock

username = 'anonymous'
password = 'doesnt_matter'


class TestValidLogin(unittest.TestCase):

    def test_base_valid_login(self):
        """ Test that a valid login returns the user name.  We use the 'anonymous'
            account since it has no resources and doesn't require a specific
            password to authenticate correctly.

            SUCCESS: the authenticator returns 'anonymous'
            FAIL:    authenticator returns None
        """
        dlauth = dlauthenticator.BaseDataLabAuthenticator()
        res = dlauth.authenticate(None,
                                  dict(username=username, password=password)).result()

        self.assertEqual(res, username)

    def mock_request_handler(self, headers):
        request = MagicMock()
        type(request).headers = PropertyMock(return_value=headers)
        handler = MagicMock()
        type(handler).request = PropertyMock(return_value=request)
        return handler

    @patch('dl.authClient.isValidToken')
    def test_datalab_valid_login(self, mock_isValidToken):
        mock_isValidToken.return_value = True

        username = "unittestuser"
        uid = "666"
        gid = "666"
        token = "$1$some..fake..but..working.token/"
        mock_headers = {
            "Cookie": f"X-DL-AuthToken = {username}.{uid}.{gid}.{token}"
        }

        # Mocking request
        mock_handler = self.mock_request_handler(mock_headers)

        data = {'username': username}
        dlauth = dlauthenticator.DataLabAuthenticator()
        res = dlauth.authenticate(mock_handler, {'username': data}).result()

        # Assert

        # 1. Check that the return is not None
        self.assertIsNotNone(res)

        # 2. Check that the returned object is a dictionary
        self.assertEqual(res, username)

    def basic_asserts_for_gc_auth(self, res, username, uid, gid, token):
        """
        Helper method for GC authenticator method
        """
        # 1. Check that the return is not None
        self.assertIsNotNone(res)

        # 2. Check that the returned object is a dictionary
        self.assertIsInstance(res, dict)

        # 3 & 4. Check keys and their values
        self.assertEqual(res.get('name'), username)

        # 5. For nested dictionaries, repeat steps 3 and 4
        self.assertIn('auth_state', res)  # Check that the 'auth_state' key exists
        auth_state = res.get('auth_state')

        # Check that the 'auth_state' value is a dictionary
        self.assertIsInstance(auth_state, dict)

        # Check keys and values within 'auth_state'
        self.assertEqual(auth_state.get('uid'), uid)
        self.assertEqual(auth_state.get('gid'), gid)
        self.assertEqual(auth_state.get('token'), token)

    @patch('dl.authClient.isValidToken')
    def test_gc_valid_login(self, mock_isValidToken):
        mock_isValidToken.return_value = True

        username = "unittestuser"
        uid = "666"
        gid = "666"
        hash = '$1$some......fake...........token/'
        token = f"{username}.{uid}.{gid}.{hash}"
        mock_headers = {
            "Cookie": f"X-DL-AuthToken = {token}"
        }

        # Mocking request
        mock_handler = self.mock_request_handler(mock_headers)

        data = {'username': username}
        dlauth = dlauthenticator.GCDataLabAuthenticator()
        res = dlauth.authenticate(mock_handler, {'username': data}).result()
        self.basic_asserts_for_gc_auth(res, username, uid, gid, token)

    def test_dev_gc_valid_login(self):
        dlauth = dlauthenticator.GCDataLabAuthenticatorNoRedirect()

        res = dlauth.authenticate(None,
                                  dict(username=username, password=password)).result()

        self.basic_asserts_for_gc_auth(res, username, '0', '0', 'anonymous.0.0.anon_access')
