from .. import dlauthenticator

username = 'demo00'
password = 'doesnt_matter'


def test_invalid_password():
    ''' Test that an invalid password fails to login the user.

        SUCCESS: an invalid password returns None
        FAIL:    an invalid password returns the user name
    '''
    dlauth = dlauthenticator.DataLabAuthenticator()
    res = dlauth.authenticate(None, 
                              dict(username=username,password=password))
    assert res.result() is None
