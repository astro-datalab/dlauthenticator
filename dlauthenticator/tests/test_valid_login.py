from .. import dlauthenticator

username = 'anonymous'
password = 'doesnt_matter'


def test_valid_login():
    ''' Test that a valid login returns the user name.  We use the 'anonymous'
        account since it has no resources and doesn't require a specific
        password to authenticate correctly.

        SUCCESS: the authenticator returns 'anonymous'
        FAIL:    authenticator returns None
    '''
    dlauth = dlauthenticator.DataLabAuthenticator()
    res = dlauth.authenticate(None, 
                              dict(username=username,password=password))
    assert res.result() == username
