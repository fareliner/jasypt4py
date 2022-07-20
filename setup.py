#!/usr/bin/env jython

#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
#

import sys

try:
    from setuptools import setup, Extension
except:
    from distutils.core import setup, Extension

setup(
    name='jasypt4py',

    version='0.0.4',

    url='https://github.com/fareliner/jasypt4py',

    author='Niels Bertram',
    author_email='nielsbne@gmail.com',

    description='Cipher functions that produce Jasypt/Bouncycastle compatible password encryption.',

    license='Apache License 2.0',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'Topic :: System :: Software Distribution',
        'Topic :: System :: Systems Administration',

        # released under Apache 2 License
        'License :: OSI Approved :: Apache Software License',

        # the language used by the author
        'Natural Language :: English',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',

        # works on anything that can run pycrypto
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3'
    ],

    keywords='jasypt bouncycastle AES crypto SHA256',

    install_requires=[
        'pycryptodome'
    ],

    # prepare for testing with nose
    test_suite='nose.collector',
    tests_require=[
        'nose'
    ],

    # manually define packages
    py_modules=[
        'jasypt4py.exceptions',
        'jasypt4py.generator',
        'jasypt4py.encryptor'
    ]

)
