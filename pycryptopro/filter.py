"""
    PyCryptoPro

    Lists filters
"""

from __future__ import annotations
from abc import abstractmethod, ABCMeta
from typing import List


class CertFilterInterface(metaclass=ABCMeta):
    """
    Certificate or CRL list filter interface
    """

    @abstractmethod
    def search(self) -> List[str]:
        """
        Gets substring for search in DN section
        """

    @abstractmethod
    def limit(self) -> int:
        """
        Gets list records limit
        """

    @abstractmethod
    def offset(self) -> int:
        """
        Gets first record of list
        """


class CertFilter(CertFilterInterface):
    """
    Certificate or CRL list filter
    """

    def __init__(self, search: str = '', limit: int = 0, offset: int = 0):
        self.__search = search.split(' ')
        self.__limit = limit if limit > 0 else 0
        self.__offset = offset if offset > 0 else 0

    @property
    def search(self) -> List[str]:
        """
        Gets substring for search in DN section
        """
        return self.__search

    @property
    def limit(self) -> int:
        """
        Gets list records limit
        """
        return self.__limit

    @property
    def offset(self) -> int:
        """
        Gets first record of list
        """
        return self.__offset
