from setuptools import setup

setup(
    name='dlauthenticator',
    version='0.4.2',
    description='Data Lab Authenticator for JupyterHub',
    url='https://github.com/astro-datalab/dlauthenticator',
    author='Mike Fitzpatrick',
    author_email='mike.fitzpatrick@noirlab.edu',
    license='3 Clause BSD',
    packages=['dlauthenticator'],
    install_requires=['astro-datalab']
)
