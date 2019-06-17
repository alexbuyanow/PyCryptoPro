from setuptools import find_packages, setup
from .api import __version__

setup(
    name='pycryptopro',
    version=__version__,
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
)
