#!/bin/env python3
#
# DLAUTHENTICATOR -- JupyterHub authenticator module for Data Lab logins.
# GCDLAUTHENTICATOR -- GC JupyterHub authenticator - ISS


__version__ = '0.4.0'
__author__ = 'Mike Fitzpatrick <mjfitzpatrick@gmail.com>'


import os
import sys
import socket
import argparse

from traitlets import List
from jupyterhub.auth import Authenticator
from jupyterhub.handlers.base import BaseHandler
from tornado import gen
from http.cookies import SimpleCookie
from dl import authClient, Util


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

# configure the auth client
authClient.set_svc_url(DEF_SERVICE_URL)


def get_cookie_from_str(name, cookie_str=""):
    """
    Parse a cookie string a return the value matching the provided
    cookie name
    """
    cookie = SimpleCookie()
    cookie.load(cookie_str)
    if cookie == None:
        return None
    cookies = {k: v.value for k, v in cookie.items()}
    return cookies.get(name, None)


class ExternalLogoutHandler(BaseHandler):
    """
    Handler to work with custom external authenticator, clear the JHUB session
    then route the user to the main Data Lab logout page (configured in
    post_logout_url). This is useful if our login service can't clear the
    session
    """
    def get(self):
        self.clear_login_cookie()
        self.redirect(self.authenticator.post_logout_url)


class DataLabAuthenticator(Authenticator):
    """
    Data Lab Jupyter login authenticator.
    """
    post_logout_url = f"{DEF_SERVICE_ROOT}/account/logout.html"
    invalid_token_url = f"{DEF_SERVICE_ROOT}/account/login.html?next={DEF_SERVICE_ROOT}/devbooks/"

    DEBUG_USER_PATH = '/root/dlauth_debug_user'

    def __init__(self, parent=None, db=None):
        self.debug_user_info = self.get_debug_user_info()
        self.auto_login = True


    @classmethod
    def parse_token(cls, dl_token):
        return {k: v for k, v in zip(['username', 'uid', 'gid', 'hash'],
                                     Util.split_auth_token(dl_token))}
    @classmethod
    def set_debug_user_path(cls, path):
        cls.DEBUG_USER_PATH = path

    @classmethod
    def get_debug_user_info(cls):
        """Get the debug username, if any. Make it a runtime file to avoid
        restarts of the JupyterHub.
        """
        debug_user_info = {'username': None}
        print("In get_debug_user_info:", debug_user_info)
        if os.path.exists(cls.DEBUG_USER_PATH):
            with open(cls.DEBUG_USER_PATH, 'r') as fd:
                debug_user_info['username'] = fd.readline().strip()
        return debug_user_info

    @property
    def debug_user_path(self):
        """A read-only property to hold the debug user path for testing.
        """
        return self.DEBUG_USER_PATH


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
        #username = data["username"]
        #password = data["password"]

        # Note: this authentication assumes actual login,
        # i.e. doing the authClient.login(username, password) API
        # happens somewhere else. That "somewhere else" will set a cookie
        # which is what this authenticate method uses.

        # TODO what if data["username"] is different from token username?

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
        if not authClient.isValidToken(dl_token):
            # If the user doesn't have a valid token first see if we have any debug
            # configurations for the user otherwise send them to the login page.
            # Allow password-less login for specific users. Typically used
            # for support purposes only to debug a user's environment.
            if self.debug_user_info['username'] and self.debug_user_info['username'] == username:
                self.log.info(f"Using debug user info for user:{username}")
                return self.post_authenticate(handler, self.debug_user_info, None)

            handler.redirect(self.invalid_token_url)
            return None
        else:
            # if the user has a valid token we verify they aren't excluded otherwise
            # pass the authenticated username
            for user in self.excluded_users:
                if user == username:
                    self.log.warning(f"Auth error: {user}: Excluded login denied")
                    return None

            # if we reach this point the user is logged in and is permitted to access
            return self.post_authenticate(handler, {'username': username}, None)

    def post_authenticate(self, handler, data, token):
        """
        An additional method that derived classes can override to perform
        authenticator-specific logic after the initial authentication.
        """
        return data['username']


#
# Google Cloud authenticator class
#
class GCDataLabAuthenticator(DataLabAuthenticator):
    """
    Google Cloud DataLab authenticator
    """
    DataLabAuthenticator.set_debug_user_path('/local/dlauth_debug_user')

    def get_debug_user_info(self):
        debug_user_info = {'username': None,
                           'token': None}
        if os.path.exists(self.DEBUG_USER_PATH):
            with open(self.DEBUG_USER_PATH, 'r') as fd:
                debug_user_info['username'] = fd.readline().strip()  # first line username
                debug_user_info['token'] = fd.readline().strip()  # second line for token
        return debug_user_info

    def post_authenticate(self, handler, data, token):
        # in debug mode, token might be None but a token
        # might be passed down as part of the "data" structure
        if token is None and "token" in data:
            token = data['token']

        # Extract user, uid, gid, hash, etc. from the token and return user_info.
        user, uid, gid, hash = Util.split_auth_token(token)
        self.log.info(f"Valid login for: {user}: {uid}: {gid}")
        if not user or not uid or not gid:
            self.log.warning(f"Login for user [{data['username']}] with token [{token}] failed")
            return None

        user_info = {
            'name': data['username'],
            'auth_state': {'uid': uid, 'gid': gid, 'token': token}
        }
        return user_info

    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        # get_auth_state is a coroutine (async) wait for it with yield
        # make sure the below is set in the config file
        # c.Authenticator.enable_auth_state = True
        # otherwise the below command will return None.
        auth_state = yield spawner.user.get_auth_state()

        # Dev note:
        # print dir(self) or/and dir(spawner) to get attributes on these objects

        user_options = spawner.user_options
        # find the profile the user selected and add info to the log
        matching_profile = next(
            (profile for profile in spawner.profile_list if profile['slug'] == user_options['profile']), None)
        if matching_profile is not None:
            kubespawner_override = matching_profile.get('kubespawner_override', {})
            mem_limit = kubespawner_override.get('mem_limit', "N/A")
            self.log.info(f"user=[{spawner.user.name}] NB=[{user_options['profile']}] mem_limit=[{mem_limit}]")
        else:
            self.log.info(f"user=[{spawner.user.name}] NB=[{user_options['profile']}]")

        # Dev note:
        # these get passed to the c.KubeSpawner.args.
        # if for some reason we wanted make a logic decision and pass
        # an argument to the spawner use, spawner.args.append:
        # e.g.
        # spawner.args.append('--LabApp.collaborative=True')

        spawner.environment = {
            # no need to set MEM_LIMIT here, it is already set in kubespawner_override
            # and pass as env variable when the pod starts
            # see kubespawner/spawner.py line 1861 make_pod ...
            # 'MEM_LIMIT': str(c.KubeSpawner.mem_limit),
            # 'MEM_LIMIT': 2147483648, # the big int value makes it crash
            # 'MEM_LIMIT': '2147483648',
            'UPSTREAM_TOKEN': auth_state['token'],
            'NB_USER': spawner.user.name,
            'NB_UID': auth_state['uid']
        }


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

#    rs = DataLabAuthenticator().authenticate(None, data)
#    if rs.result() is None:
#        print(f'Login fails for user: %s' % data['username'])
#    else:
#        print(f'Login succeeds for user: %s' % data['username'])

    rs = GCDataLabAuthenticator().authenticate(None, data)
    print("GCDataLabAuthenticator:", rs.result())
    if rs.result() is None:
        print(f'Login fails for user: %s' % data['username'])
    else:
        print(f'Login succeeds for user: %s' % data['username'])
