from setuptools import setup, Extension
import subprocess

rpm_version = subprocess.check_output(["rpm", "--version"])
# Example: RPM version 4.16.90
rpm_version = rpm_version.split(b" ")[2].split(b".")
# Ignore the last bit, which could be e.g. 0-beta1
rpm_version = tuple(map(int, rpm_version[:2]))
if rpm_version[0] != 4:
    raise Exception("RPM version %s is not major version 4" % rpm_version)
ext_defines = []
if rpm_version[1] >= 15:
    ext_defines.append(("RPM_415", None))
elif rpm_version[1] == 14:
    ext_defines.append(("RPM_414", None))
elif rpm_version[1] == 11:
    ext_defines.append(("RPM_411", None))
else:
    raise Exception("Unsupported RPM version %s" % rpm_version)

insertlib = Extension(
    "insertlib",
    libraries=["rpm", "rpmio"],
    sources=["rpm_head_signing/insertlib.c"],
    extra_compile_args=["-Wall", "-Werror"],
    define_macros=ext_defines,
)

setup(
    name="rpm_head_signing",
    version="1.4",
    packages=["rpm_head_signing"],
    ext_package="rpm_head_signing",
    ext_modules=[insertlib],
    install_requires=[
        "requests",
        "koji",
        "rpm",
        "pyxattr",
    ],
    entry_points={
        "console_scripts": [
            "verify-rpm-ima-signatures=rpm_head_signing.verify_rpm:__main__",
        ],
    },
)
