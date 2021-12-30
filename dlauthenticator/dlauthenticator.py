#!/bin/env python3
#
# DLAUTHENTICATOR -- JupyterHub authenticator module for Data Lab logins.


__version__ = '0.3.0'
__author__ = 'Mike Fitzpatrick <mjfitzpatrick@gmail.com>'


import os
import sys
import socket
import argparse

from traitlets import List
from jupyterhub.auth import Authenticator
from tornado import gen
from dl import authClient


#  The URL of the AuthManager service to contact.  Allow the service URL
#  for dev/test systems to override the default.
THIS_HOST = socket.gethostname()
if THIS_HOST[:5] == 'dldev':
    DEF_SERVICE_ROOT = "https://dldev.datalab.noirlab.edu"
elif THIS_HOST[:6] == 'dltest':
    DEF_SERVICE_ROOT = "https://dltest.datalab.noirlab.edu"
else:
    DEF_SERVICE_ROOT = "https://datalab.noirlab.edu"

DEF_SERVICE_URL = DEF_SERVICE_ROOT + "/auth"


# Make the runtime path to the debug user file accessible only to somebody
# with admin privs on the machine running the authenticator.
DEBUG_USER_PATH = '/root/dlauth_debug_user'


class DataLabAuthenticator(Authenticator):
    '''Data Lab Jupyter login authenticator.
    '''
    def __init__(self):
        self._debug_user_path = DEBUG_USER_PATH

    @property
    def debug_user_path(self):
        '''A read-only property to hold the debug user path for testing.
        '''
        return self._debug_user_path


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


def parser_arguments():
    '''Create the argument parser.
    '''
    parser = argparse.ArgumentParser(
             description="JupyterHub login authenticator for Data Lab")

    # Optional args
    group = parser.add_argument_group()
    group.add_argument("-u", "--user", action="store",
            default=None, help="Task account username")
    group.add_argument("-p", "--password", action="store",
            default=None, help="Test account password")

    return parser.parse_args()


# ===================================================================
# Program MAIN
# ===================================================================

if __name__ == "__main__":
    '''Test Application
    '''
    import getpass

    # Parse the command-line arguments.
    args = parser_arguments()

    if args.user is None and args.password is None:
        data = dict(username=input('Username: '), password=getpass.getpass())
    else:
        data = dict(username=args.user, password=args.password)

    rs = DataLabAuthenticator().authenticate(None, data)
    if rs.result() is None:
        print(f'Login fails for user: %s' % data['username'])
    else:
        print(f'Login succeeds for user: %s' % data['username'])

