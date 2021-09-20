import os
import getpass

from .. import dlauthenticator

username = 'anonymous'
password = 'doesnt_matter'


def test_bypass_file():
    ''' Test that the debug login bypass allows a valid login
        NOTE:  Requires root permission in order to create the path.

        SUCCESS: the file does not exist
        FAIL:    the file exists
        SKIP:    the test is not run with root permissions
    '''
    if getpass.getuser() != 'root':
        import pytest
        pytest.skip('Must run test as root user')
    else:
        dlauth = dlauthenticator.DataLabAuthenticator()


        dbg_path = dlauth.debug_user_path
        #assert not os.path.exists(dbg_path)
        if not os.path.exists(dbg_path):
            with open(dbg_path,'w') as fd:
                fd.write(username)

            res = dlauth.authenticate(None, 
                                      dict(username=username,password=password))
            os.unlink(dbg_path)         # clean up and delete the debug file
            assert res.result() == username
        else:
            assert 0
