import pytest
from .. import dlauthenticator

username = 'demo00'
password = 'doesnt_matter'

# Test the only two classes where password login makes sense

@pytest.mark.parametrize("auth_class", [dlauthenticator.BaseDataLabAuthenticator,
                                        dlauthenticator.DevGCDataLabAuthenticator])
def test_invalid_password(auth_class):
    """ Test that an invalid password fails to login the user.

        SUCCESS: an invalid password returns None
        FAIL:    an invalid password returns the user name
    """
    dlauth = auth_class()  # Instantiating the passed authenticator class
    res = dlauth.authenticate(None,
                              dict(username=username,password=password))
    assert res.result() is None
