
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

    @gen.coroutine
    def authenticate(self, handler, data):
        username = data["username"]
        password = data["password"]

        # Punt on any attempted login to excluded account names.
        for user in self.excluded_users:
            if user == username:
                self.log.warning("Auth error: %s: Excluded login denied", user)
                return None

        try:
            authClient.set_svc_url(DEF_SERVICE_URL)
            token = authClient.login (username, password)
            if not authClient.isValidToken(token):
                self.log.warning("Auth error: %s: %s", (username,token))
                return None
        except Exception as e:
            self.log.error("Auth error: %s: %s", (username,token))
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

    print('DLAuth result: ' + rs.result())

