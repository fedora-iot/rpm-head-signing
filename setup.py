from setuptools import setup

setup(
    name='rpm_head_signing',
    version='0.1',
    packages=['rpm_head_signing'],
    install_requires=[
        'requests',
        'koji',
        'rpm',
        'six',
        'pyxattr',
    ]
)
