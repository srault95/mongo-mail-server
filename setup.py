# -*- coding: utf-8 -*-

import os
import sys

from setuptools import setup, find_packages

CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))

def get_readme():
    readme_path = os.path.abspath(os.path.join(CURRENT_DIR, 'README.rst'))
    if os.path.exists(readme_path):
        with open(readme_path) as fp:
            return fp.read()
    return ""

setup(
    name='mongo-mail-server',
    version="0.1.1",
    description='Python SMTP server with Gevent for recording messages in MongoDB',
    long_description=get_readme(),
    author='Stéphane RAULT',
    author_email='stephane.rault@radicalspam.org',
    license='BSD',
    classifiers=[
        'Topic :: Communications :: Email',
        'Topic :: Communications :: Email :: Mail Transport Agents',
        'Development Status :: 4 - Beta',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'License :: OSI Approved :: BSD License',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators'
    ],
    
    url='https://github.com/radical-software/mongo-mail-server', 
    include_package_data=True,
    zip_safe=False,
    scripts=['mongo_mail_server.py'],
    install_requires=[
        'python-dateutil',
        'gevent>=1.0',
        'python-decouple',
        'pymongo>=2.8',
    ],
    setup_requires=[
        'nose>=1.0'
    ],
    tests_require=[
        'nose>=1.0'
        'coverage',
    ],
    test_suite='nose.collector',
    entry_points={
        'console_scripts': [
            'mongo-mail-server = mongo_mail_server:main',
            'mongo-mail-reader = mongo_mail_server:main_reader',
        ],
    },    
)
