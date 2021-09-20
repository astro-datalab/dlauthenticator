from .. import dlauthenticator

username = 'nosuchuser'
password = 'doesnt_matter'


def test_invalid_user():
    ''' Test that an invalid username fails to login.

        SUCCESS: an invalid username returns None
        FAIL:    an invalid username returns the user name
    '''
    dlauth = dlauthenticator.DataLabAuthenticator()
    res = dlauth.authenticate(None, 
                              dict(username=username,password=password))
    assert res.result() is None
