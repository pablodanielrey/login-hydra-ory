"""
    https://packaging.python.org/distributing/
    https://pypi.python.org/pypi?%3Aaction=list_classifiers
    http://semver.org/

    zero or more dev releases (denoted with a ”.devN” suffix)
    zero or more alpha releases (denoted with a ”.aN” suffix)
    zero or more beta releases (denoted with a ”.bN” suffix)
    zero or more release candidates (denoted with a ”.rcN” suffix)
"""

from setuptools import setup, find_packages

setup(name='login-consent',
          version='1.0.0.alpha0',
          description='Aplicación de consent para hydra-ory',
          url='https://github.com/pablodanielrey/login-hydra-ory',
          author='Desarrollo DiTeSi, FCE',
          author_email='ditesi@econo.unlp.edu.ar',
          classifiers=[
            #   3 - Alpha
            #   4 - Beta
            #   5 - Production/Stable
            'Development Status :: 3 - Alpha',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.5'
          ],
          packages=find_packages(exclude=['contrib', 'docs', 'test*']),
          install_requires=['psycopg2',
                            'dateutils',
                            'requests',
                            'redis',
                            'Flask',
                            'flask_jsontools',
                            'Flask-Session',
                            'SQLAlchemy',
                            'httplib2',
                            'pyjwt',
                            'oauthlib',
                            'cryptography',
                            'requests_oauthlib'
                            ],
          entry_points={
            'console_scripts': [
                'flask=login.web.main:main'
            ]
          }

      )
