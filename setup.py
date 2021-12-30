from setuptools import setup

setup(
    name='dlauthenticator',
    version='0.3',
    description='Data Lab Authenticator for JupyterHub',
    url='https://github.com/noaodatalab/dlauthenticator',
    author='Mike Fitzpatrick',
    author_email='mike.fitzpatrick@noirlab.edu',
    license='3 Clause BSD',
    packages=['dlauthenticator'],
    install_requires=['noaodatalab'],
    requires=['noaodatalab']
)
