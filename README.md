# Data Lab JupyterHub Authenticator #

Simple authenticator for [JupyterHub](http://github.com/jupyter/jupyterhub/)
that allows all user logins by authenticating with the Data Lab Authorization
Manager.

## Installation ##

```
python setup.py install
    or
pip install dlauthenticator
```

Should install it. It does require the Data Lab client application and API
be installed (http://github.com/noaodatalab/datalab.git).

You can then use this as your authenticator by adding the following line to
your `jupyterhub_config.py`:

```
c.JupyterHub.authenticator_class = 'dlauthenticator.DataLabAuthenticator'
```

### Configuration ###

The only configuration option at present is a List of usernames that are not
permitted to login to the notebook server.  Typically this is done for admin
accounts (e.g. root) or to exclude non-DataLab user accounts on the machine
that would otherwise be able to login through the PAM authenticator.  For
example, the following can be added to the `jupyterhin_config.py` file:

```
c.DataLabAuthenticator.excluded_users = ['root','datalab']
```
