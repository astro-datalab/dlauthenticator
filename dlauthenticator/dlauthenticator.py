#!/bin/env python3
#
# DLAUTHENTICATOR -- JupyterHub authenticator module for Data Lab logins.


__version__ = '0.3.1'
__author__ = 'Mike Fitzpatrick <mjfitzpatrick@gmail.com>'


import os
import sys
import socket
import argparse
import re

from traitlets import List
from jupyterhub.auth import Authenticator
from jupyterhub.handlers.base import BaseHandler
from tornado import gen
from http.cookies import SimpleCookie
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

# configure the auth client
authClient.set_svc_url(DEF_SERVICE_URL)


def get_cookie_from_str(name, cookie_str=""):
    '''
    Parse a cookie string a return the value matching the provided
    cookie name
    '''
    cookie = SimpleCookie()
    cookie.load(cookie_str)
    if cookie == None:
        return None
    cookies = {k: v.value for k, v in cookie.items()}
    return cookies.get(name, None)


class ExternalLogoutHandler(BaseHandler):
    '''
    Handler to work with custom external authenticator, clear the JHUB session
    then route the user to the main Data Lab logout page (configured in
    post_logout_url). This is useful if our login service can't clear the
    session
    '''
    def get(self):
        self.clear_login_cookie()
        self.redirect(self.authenticator.post_logout_url)


class DataLabAuthenticator(Authenticator):
    '''Data Lab Jupyter login authenticator.
    '''
    post_logout_url = f"{DEF_SERVICE_ROOT}/account/logout.html"
    invalid_token_url = f"{DEF_SERVICE_ROOT}/account/login.html?next={DEF_SERVICE_ROOT}/devbooks/"

    def __init__(self, parent=None, db=None, _deprecated_db_session=None):
        self._debug_user_path = DEBUG_USER_PATH
        self.auto_login = True

    @property
    def debug_user_path(self):
        '''A read-only property to hold the debug user path for testing.
        '''
        return self._debug_user_path

    # Set the default user-exclusion list. Other users can be named in
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

    def is_auth_token(self, token):
        """Check if passed in string is an auth token
            Usage:
                is_auth_token(token)
        Parameters
        ----------
        token : str
            A string auth token
            E.g.
            "testuser.3666.3666.$1$PKCFmMzy$OPpZg/ThBmZe/V8LVPvpi/%"
        Returns
        -------
        return: boolean
             True if string is a auth token
        """

        """
        E.g. token "testuser.3666.3666.$1$PKCFmMzy$OPpZg/ThBmZe/V8LVPvpi/%"
        Regex deconstruction and explanation:
        -------------------------------------
        1.   ([^\/\s]+)     any string with no "/" or spaces
        2.   \.             separated by a .
        3.   \d+            followed by any number of digits
        4.   \.             separated by a .
        5.   \d+            followed by any number of digits
        6.   \.             separated by a .
        7.a) (\$1\$\S{22,}) A string that starts with $1$ (that's how a md5 hash
                            starts) and that is followed by any non space
                            characters of 22 chars or longer
        7.b) |              or
        7.c) (\S+_access)   A string that ends in _access. This is a special
                            case for special tokens such as:
                              anonymous.0.0.anon_access
                              dldemo.99999.99999.demo_access
        """

        return re.match(r'([^\/\s]+)\.\d+\.\d+\.((\$1\$\S{22,})|(\S+_access))', 
                        token)

    def parse_token(self, token):
        """
        Break out the various pieces of the token, auth manager can probably
        do this but we really only need the username in this context
        """
        parts = token.split(".")
        username = parts[0]
        return dict(username=username)

    def is_valid_token(self, token=""):
        """
        Validate the provided token with our authClient and return status
        """
        if (token is not None and token != "" and self.is_auth_token(token)):
            return authClient.isValidToken(token)
        return False

    @gen.coroutine
    def authenticate(self, handler, data):
        cookie_header = handler.request.headers.get("Cookie", "")
        dl_token = get_cookie_from_str("X-DL-AuthToken", cookie_header)

        # if we do not have the token then we can just route to login
        if dl_token is None:
            handler.redirect(self.invalid_token_url)
            return None

        # try to parse the token here so we can use it below
        token_data = self.parse_token(dl_token)
        username = token_data.get('username', '')

        # handle each case .. authenticated or not
        if not self.is_valid_token(dl_token):
            # if the user doesn't have a valid token first see if we have any debug
            # configurations for the user otherwise send them to the login page
            if username in self.debug_user:
                return username

            handler.redirect(self.invalid_token_url)
            return None
        else:
            # if the user has a valid token we verify they aren't excluded otherwise
            # pass the authenticated username
            for user in self.excluded_users:
                if user == username:
                    self.log.warning("Auth error: %s: Excluded login denied", user)
                    return None

            # if we reach this point the user is logged in and is permitted to access
            return username

    def logout_url(self, base_url):
        '''on logout, use our custom logout handler instead of default
        '''
        return base_url+"/dl-logout"

    def get_handlers(self, base_url):
        '''instruct the application to serve our custom logout handler
        '''
        return super().get_handlers(self) + [("/dl-logout", ExternalLogoutHandler)]


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