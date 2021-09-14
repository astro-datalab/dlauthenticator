
import os
import sys
import socket

from traitlets import List
from jupyterhub.auth import Authenticator
from tornado import gen
from dl import authClient


#  The URL of the AuthManager service to contact.  Allow the service URL
#  for dev/test systems to override the default.
THIS_HOST = socket.gethostname()
if THIS_HOST[:5] == 'dldev':
    DEF_SERVICE_ROOT = "http://dldev.datalab.noao.edu"
elif THIS_HOST[:6] == 'dltest':
    DEF_SERVICE_ROOT = "http://dltest.datalab.noao.edu"
else:
    DEF_SERVICE_ROOT = "https://datalab.noao.edu"

DEF_SERVICE_URL = DEF_SERVICE_ROOT + "/auth"

DEBUG_USER_PATH = '/tmp/dlauth_debug_user'


class DataLabAuthenticator(Authenticator):
    '''Data Lab Jupyter login authenticator.
    '''
    # Set the default user-exclusion list.  Other users can be named in 
    # the jupyterhub_config.py file.
    excluded_users = List(
        ['root', 'datalab'],
        allow_none=True,
        config=True,
        help="""
        List of user names not allowed to access the notebook server.
        """
    )

    # Get the debug username, if any. Make it a runtime file to avoid
    # restarts of the JupyterHub.
    debug_user = []
    if os.path.exists(DEBUG_USER_PATH):
        with open(DEBUG_USER_PATH,'r') as fd:
            debug_user = [ fd.readline().strip() ]

    @gen.coroutine
    def authenticate(self, handler, data):
        username = data["username"]
        password = data["password"]

        # Allow password-less login for specific users. Typically used
	# for upport purposes only to debug a user's environment.
        if username in self.debug_user:
            return username

        # Punt on any attempted login to excluded account names.
        for user in self.excluded_users:
            if user == username:
                self.log.warning("Auth error: %s: Excluded login denied", user)
                return None

        try:
            authClient.set_svc_url(DEF_SERVICE_URL)
            token = authClient.login (username, password)
            if not authClient.isValidToken(token):
                self.log.warning("Invalid token: %s: %s" % (username,token))
                return None
        except Exception as e:
            self.log.error("Exception Auth error: %s: %s" % (username,str(e)))
            return None

        return data['username']


if __name__ == "__main__":
    '''Test Application
    '''
    import getpass

    username = input("Username: ")
    passwd = getpass.getpass()
    data = dict(username=username, password=passwd)

    rs = DataLabAuthenticator().authenticate(None, data)

    print('DLAuth result: ' + str(rs.result()))

