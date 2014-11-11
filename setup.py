r'''
Copyright 2014 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import os
from setuptools import setup, find_packages
from nogotofail import __version__

CLASSIFIERS = [
    'Development Status :: 4 - Beta',
    'Environment :: Other Environment',
    'Intended Audience :: Developers',
    'Operating System :: POSIX :: Linux',
    'License :: OSI Approved :: Apache Software License',
    'Programming Language :: Python',
    'Topic :: Internet',
    'Topic :: Utilities',
    'Topic :: Software Development :: Libraries :: Python Modules',
    'Topic :: Security'
]

# read long description
with open(os.path.join(os.path.dirname(__file__), 'README.md')) as f:
    long_description = f.read()

setup(
    name='nogotofail',
    version=__version__,

    description='TLS/SSL network security testing tool',
    long_description=long_description,
    author='Google Inc.',
    author_email='',
    license='Apache License 2.0',
    url='https://github.com/google/nogotofail',

    classifiers=CLASSIFIERS,
    zip_safe=True,
    packages=find_packages(exclude=['docs', 'nogotofail.clients.android']),
    include_package_data=True,

    install_requires=[
        'pyOpenSSL >= 0.13',
        'psutil'
    ],

    entry_points="""
    [console_scripts]
    nogotofail-mitm=nogotofail.mitm.__main__:run
    nogotofail-client-linux=nogotofail.clients.linux.pyblame.__main__:main
    """
)
