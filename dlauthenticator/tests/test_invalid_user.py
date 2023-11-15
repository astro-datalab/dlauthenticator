import pytest
from .. import dlauthenticator

username = 'nosuchuser'
password = 'doesnt_matter'


@pytest.mark.parametrize("auth_class", [dlauthenticator.BaseDataLabAuthenticator,
                                        dlauthenticator.GCDataLabAuthenticatorNoRedirect])
def test_invalid_user(auth_class):
    """ Test that an invalid username fails to login.

        SUCCESS: an invalid username returns None
        FAIL:    an invalid username returns the user name
    """

    dlauth = auth_class()  # Instantiating the passed authenticator class
    res = dlauth.authenticate(None, dict(username=username, password=password))
    assert res.result() is None
