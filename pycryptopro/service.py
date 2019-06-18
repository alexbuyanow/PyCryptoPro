"""
    PyCryptoPro

    CryptoPro wrapper
"""

from __future__ import annotations
from hashlib import md5
from pathlib import Path
from typing import List, Optional
from .entity import Certificate, CRL, Config
from .exception import (
    CryptoProException,
    CryptoProviderException,
    ValidationFailedException
)
from .provider import CryptoProviderInterface


class CryptoProService:
    """
    CryptoPro service
    """

    def __init__(
            self,
            data_provider: CryptoProviderInterface,
            config: Config
    ):
        self.__data_provider = data_provider
        self.__temp_path = config.temp_path
        self.__cert_store = config.storage_name
        self.__sign_store = config.sign_storage_name
        self.__pin = config.sign_storage_pin

    def get_certificate_list(self) -> List[Certificate]:
        """
        Gets certificates list
        """
        try:
            return self.__data_provider.get_certificate_list(self.__cert_store)
        except CryptoProviderException as exception:
            raise CryptoProException(exception.code, exception.message)

    def get_certificate(self, cert_id: str) -> Optional[Certificate]:
        """
        Gets certificate by identifier
        """
        try:
            return self.__data_provider.get_certificate(
                cert_id,
                self.__cert_store
            )
        except CryptoProviderException as exception:
            raise CryptoProException(exception.code, exception.message)

    def add_certificate(self, file: bytes):
        """
        Adds certificate into store
        """
        path = self.__save_file(file)

        try:
            self.__data_provider.add_certificate(path, self.__cert_store)
        except CryptoProviderException as exception:
            raise CryptoProException(exception.code, exception.message)
        finally:
            self.__remove_file(path)

    def remove_certificate(self, cert_id: str):
        """
        Removes certificate from store
        """
        try:
            self.__data_provider.remove_certificate(cert_id, self.__cert_store)
        except CryptoProviderException as exception:
            raise CryptoProException(exception.code, exception.message)

    def get_crl_list(self) -> List[CRL]:
        """
        Gets CRL list
        """
        try:
            return self.__data_provider.get_crl_list(self.__cert_store)
        except CryptoProviderException as exception:
            raise CryptoProException(exception.code, exception.message)

    def get_crl(self, cert_id: str) -> Optional[CRL]:
        """
        Gets CRL by identifier
        """
        try:
            return self.__data_provider.get_crl(cert_id, self.__cert_store)
        except CryptoProviderException as exception:
            raise CryptoProException(exception.code, exception.message)

    def add_crl(self, file: bytes):
        """
        Adds CRL into store
        """
        path = self.__save_file(file)

        try:
            self.__data_provider.add_crl(path, self.__cert_store)
        except CryptoProviderException as exception:
            raise CryptoProException(exception.code, exception.message)
        finally:
            self.__remove_file(path)

    def remove_crl(self, cert_id: str):
        """
        Removes CRL from store
        """
        try:
            self.__data_provider.remove_crl(cert_id, self.__cert_store)
        except CryptoProviderException as exception:
            raise CryptoProException(exception.code, exception.message)

    def sign_attached(
            self,
            file: bytes,
            no_chain: bool = False,
            no_rev: bool = False
    ) -> bytes:
        """
        Signs file with attached signature
        """
        file = self.__save_file(file)
        sign = Path()
        sign_content = ''

        try:
            sign = self.__data_provider.sign_attached(
                file,
                self.__sign_store,
                self.__pin,
                no_chain,
                no_rev
            )
            sign_content = sign.read_bytes()
        except CryptoProviderException as exception:
            raise CryptoProException(exception.code, exception.message)
        finally:
            if file.is_file():
                self.__remove_file(file)
            if sign.is_file():
                self.__remove_file(sign)

        return sign_content

    def sign_detached(
            self,
            file: bytes,
            no_chain: bool = False,
            no_rev: bool = False
    ) -> bytes:
        """
        Signs file with detached signature
        """
        file = self.__save_file(file)
        sign = Path()
        sign_content = ''

        try:
            sign = self.__data_provider.sign_detached(
                file,
                self.__sign_store,
                self.__pin,
                no_chain,
                no_rev
            )
            sign_content = sign.read_bytes()
        except CryptoProviderException as exception:
            raise CryptoProException(exception.code, exception.message)
        finally:
            if file.is_file():
                self.__remove_file(file)
            if sign.is_file():
                self.__remove_file(sign)

        return sign_content

    def verify_attached(
            self,
            sign: bytes,
            no_chain: bool = False,
            no_rev: bool = False
    ) -> bool:
        """
        Verifies file with attached signature
        """
        sign = self.__save_file(sign)

        try:
            self.__data_provider.verify_attached(
                sign,
                no_chain,
                no_rev
            )
        except ValidationFailedException:
            return False
        except CryptoProviderException as exception:
            raise CryptoProException(exception.code, exception.message)
        finally:
            self.__remove_file(sign)

        return True

    def verify_detached(
            self,
            file: bytes,
            sign: bytes,
            no_chain: bool = False,
            no_rev: bool = False
    ) -> bool:
        """
        Verifies file with detached signature
        """
        file = self.__save_file(file)
        sign_file = Path(str(file) + '.sgn')
        sign_file.write_bytes(sign)

        try:
            self.__data_provider.verify_detached(
                file,
                sign_file,
                no_chain,
                no_rev
            )
        except ValidationFailedException:
            return False
        except CryptoProviderException as exception:
            raise CryptoProException(exception.code, exception.message)
        finally:
            self.__remove_file(file)
            self.__remove_file(sign_file)

        return True

    def __save_file(self, file: bytes) -> Path:
        """
        Saves file on filesystem
        """
        filename = md5(file).hexdigest()
        file_path = Path(self.__temp_path + '/' + filename)

        file_path.touch()
        file_path.write_bytes(file)

        return file_path

    @classmethod
    def __remove_file(cls, path: Path):
        """
        Removes file
        """
        path.unlink()
