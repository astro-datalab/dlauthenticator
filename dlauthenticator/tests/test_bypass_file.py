import os
import getpass
import pytest
from unittest.mock import patch, MagicMock, PropertyMock

from .. import dlauthenticator

username = 'someuserwithloginproblems'
password = 'doesnt_matter'
uid = "666"
gid = "666"
hash = "$1$some..fake..but..working.token/"
token = f"{username}.{uid}.{gid}.{hash}"


def mock_request_handler(headers):
    request = MagicMock()
    type(request).headers = PropertyMock(return_value=headers)
    handler = MagicMock()
    type(handler).request = PropertyMock(return_value=request)
    return handler


mock_handler = mock_request_handler({"Cookie": f"X-DL-AuthToken = {username}.{uid}.{gid}.{hash}"})


@pytest.mark.parametrize("auth_class,handler",
                         [(dlauthenticator.BaseDataLabAuthenticator, None),
                          (dlauthenticator.DataLabAuthenticator, mock_handler),
                          (dlauthenticator.GCDataLabAuthenticator, mock_handler),
                          (dlauthenticator.GCDataLabAuthenticatorNoRedirect, mock_handler)
                          ])
def test_bypass_file(auth_class, handler):
    """ Test that the debug login bypass allows a valid login
        NOTE:  Requires root permission in order to create the path.

        SUCCESS: the file does not exist
        FAIL:    the file exists
    """
    dlauth = auth_class()

    dlauth.set_debug_user_path(f"{os.getcwd()}/some_debug_file")
    dbg_path = dlauth.debug_user_path
    if not os.path.exists(dbg_path):
        with open(dbg_path, 'w') as fd:
            fd.write(username)
            # if handler not None, it means token authentication
            if handler is not None:
                fd.write("\n")
                fd.write(token)

        fut_res = dlauth.authenticate(handler,
                                      dict(username=username, password=password))
        os.unlink(dbg_path)  # clean up and delete the debug file
        res = fut_res.result()
        if isinstance(res, str):
            assert res == username
        else:
            assert res['name'] == username
    else:
        os.unlink(dbg_path)  # clean up and delete the debug file
        assert 0
