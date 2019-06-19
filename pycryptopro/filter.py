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
        limit = int(limit or 0)
        offset = int(offset or 0)

        self.__search = list(set(search.split(' '))) if search else []
        self.__limit = limit if limit and limit > 0 else 0
        self.__offset = offset if offset and offset > 0 else 0

    def search(self) -> List[str]:
        """
        Gets substring for search in DN section
        """
        return self.__search

    def limit(self) -> int:
        """
        Gets list records limit
        """
        return self.__limit

    def offset(self) -> int:
        """
        Gets first record of list
        """
        return self.__offset
