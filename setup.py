#!/usr/bin/python
from setuptools import setup, find_packages

# Import the module version
from bind9_dns_audit import __version__

# Run the setup
setup(
    name             = 'bind9_dns_audit',
    version          = __version__,
    description      = 'Library for interacting with the Rancher 2 v3 API',
    long_description = open('DESCRIPTION.rst').read(),
    author           = 'David Taylor',
    author_email     = 'djtaylor13@gmail.com',
    url              = 'http://github.com/djtaylor/python-bind9_dns_audit',
    license          = 'GPLv3',
    test_suite       = 'nose.collector',
    tests_require    = ['nose'],
    entry_points     = {
        'console_scripts': ['bind9_dns_audit=bind9_dns_audit:cli_client'],
    },
    packages         = find_packages(),
    keywords         = 'bind bind9 dns zone',
    classifiers      = [
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Natural Language :: English',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Topic :: Software Development :: User Interfaces',
        'Topic :: Terminals',
    ]
)
