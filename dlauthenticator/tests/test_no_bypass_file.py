import os
import getpass

from .. import dlauthenticator

def test_no_bypass_file():
    ''' Test that the debug login bypass does not exist on the machine.
        NOTE:  Requires root permission in order to read the path.

        SUCCESS: the file does not exist
        FAIL:    the file exists
        SKIP:    the test is not run with root permissions
    '''
    if getpass.getuser() != 'root':
        import pytest
        pytest.skip('Must run test as root user')
    else:
        dlauth = dlauthenticator.DataLabAuthenticator()
        assert not os.path.exists(dlauth.debug_user_path)
