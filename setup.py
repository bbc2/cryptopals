import os
import sys

from setuptools import setup

base_dir = os.path.dirname(__file__)
src_dir = os.path.join(base_dir, "src")
sys.path.insert(0, src_dir)


if __name__ == "__main__":
    setup(
        name="cryptopals",
        description="Attempt to solve the Cryptopals challenges",
        license="MIT",
        version="0.0.1",
        author="Bertrand Bonnefoy-Claudet",
        author_email="bertrand@bertrandbc.com",
        maintainer="Bertrand Bonnefoy-Claudet",
        maintainer_email="bertrand@bertrandbc.com",
        package_dir={"": "src"},
        python_requires=">=3.7",
        include_package_data=True,
    )
