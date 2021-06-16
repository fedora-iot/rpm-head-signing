from setuptools import setup, Extension

insertlib = Extension(
    'insertlib',
    libraries = ['rpm', 'rpmio'],
    sources = ['rpm_head_signing/insertlib.c'],
    extra_compile_args = ['-Wall', '-Werror'],
)

setup(
    name='rpm_head_signing',
    version='0.1',
    packages=['rpm_head_signing'],
    ext_package='rpm_head_signing',
    ext_modules=[insertlib],
    install_requires=[
        'requests',
        'koji',
        'rpm',
        'six',
        'pyxattr',
    ]
)
