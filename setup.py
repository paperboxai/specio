#!/usr/bin/env python3

import inspect
import os
import sys

from setuptools import find_packages, setup
from setuptools.command.test import test as TestCommand

__location__ = os.path.join(os.getcwd(), os.path.dirname(inspect.getfile(inspect.currentframe())))


def read_version(package):
    with open(os.path.join(package, '__init__.py')) as fd:
        for line in fd:
            if line.startswith('__version__ = '):
                return line.split()[-1].strip().strip("'")


version = read_version('specio')

install_requires = [
    'clickclick>=1.2,<21',
    'jsonschema>=2.5.1,<5',
    'PyYAML>=5.1,<7',
    'importlib-metadata>=1 ; python_version<"3.8"',
    'packaging>=20',
    'jinja2<=3.1.2'
]

swagger_ui_require = 'swagger-ui-bundle>=0.0.2,<0.1'

tests_require = [
    'decorator>=5,<6',
    'pytest>=6,<7',
    'pytest-cov>=2,<3',
    'testfixtures>=6,<7'
]

tests_require.append('pytest-aiohttp')

docs_require = [
    'sphinx-autoapi==1.8.1'
]


class PyTest(TestCommand):

    user_options = [('cov-html=', None, 'Generate junit html report')]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.cov = None
        self.pytest_args = ['--cov', 'connexion', '--cov-report', 'term-missing', '-v']
        self.cov_html = False

    def finalize_options(self):
        TestCommand.finalize_options(self)
        if self.cov_html:
            self.pytest_args.extend(['--cov-report', 'html'])
        self.pytest_args.extend(['tests'])

    def run_tests(self):
        import pytest

        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


def readme():
    try:
        return open('README.rst', encoding='utf-8').read()
    except TypeError:
        return open('README.rst').read()


setup(
    name='specio',
    packages=find_packages(),
    version=version,
    description='Spec.io - Convert your API specification files to other standards',
    long_description=readme(),
    author='Paperbox.ai',
    url='https://github.com/paperboxai/specio',
    keywords='openapi oai swagger rest api conversion transform',
    license='Apache License Version 2.0',
    setup_requires=['flake8'],
    python_requires=">=3.6",
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={
        'tests': tests_require,
        'docs': docs_require
    },
    cmdclass={'test': PyTest},
    test_suite='tests',
    include_package_data=True,
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
        'Topic :: Software Development :: Libraries :: Application Frameworks'
    ],
    entry_points={'console_scripts': ['specio = specio.cli:main']}
)
