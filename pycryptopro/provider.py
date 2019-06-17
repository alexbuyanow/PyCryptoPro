"""
    PyCryptoPro

    CryptoPro data providers
"""

from __future__ import annotations
from abc import abstractmethod, ABCMeta
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from .entity import Certificate, CRL
from .providers.console_provider import (
    ConsoleWrapper,
    CertManagerBuilder,
    CryptoCpBuilder
)


class CryptoProviderInterface(metaclass=ABCMeta):
    """
    CryptoPro providers interface
    """

    @abstractmethod
    def get_certificate_list(self, store: str) -> List[Certificate]:
        """
        Gets certificates list
        """

    @abstractmethod
    def get_certificate(
            self,
            cert_id: str,
            store: str
    ) -> Optional[Certificate]:
        """
        Gets certificate by identifier
        """

    @abstractmethod
    def add_certificate(self, file: Path, store: str):
        """
        Adds certificate into store
        """

    @abstractmethod
    def remove_certificate(self, cert_id: str, store: str):
        """
        Remove certificate from store
        """

    @abstractmethod
    def get_crl_list(self, store: str) -> List[CRL]:
        """
        Gets CRL list
        """

    @abstractmethod
    def get_crl(self, cert_id: str, store: str) -> CRL:
        """
        Gets CRL by identifier
        """

    @abstractmethod
    def add_crl(self, file: Path, store: str):
        """
        Adds CRL into store
        """

    @abstractmethod
    def remove_crl(self, cert_id: str, store: str):
        """
        Remove CRL from store
        """

    @abstractmethod
    def sign_attached(
            self,
            file: Path,
            store: str,
            pin: str,
            nochain: bool = False,
            norev: bool = False
    ) -> Path:
        """
        Signs file with attached signature
        """

    @abstractmethod
    def sign_detached(
            self,
            file: Path,
            store: str,
            pin: str,
            nochain: bool = False,
            norev: bool = False
    ) -> Path:
        """
        Signs file with detached signature
        """

    @abstractmethod
    def verify_attached(
            self,
            sign: Path,
            nochain: bool = False,
            norev: bool = False
    ):
        """
        Verifies file with attached signature
        """

    @abstractmethod
    def verify_detached(
            self,
            file: Path,
            sign: Path,
            nochain: bool = False,
            norev: bool = False
    ):
        """
        Verifies file with detached signature
        """


class ConsoleProvider(CryptoProviderInterface):
    """
    Console CryptoPro providers
    """

    def __init__(
            self,
            cert_manager_path: str,
            cryptocp_path: str,
            temp_dir: str
    ):
        self.__cert_manager_path = cert_manager_path
        self.__cryptocp_path = cryptocp_path
        self.__temp_dir = temp_dir
        self.__wrapper = ConsoleWrapper()

    def get_certificate_list(self, store: str) -> List[Certificate]:
        """
        Gets certificates list
        """
        return self.__get_list(store, CertManagerBuilder.TYPE_CERTIFICATE)

    def get_certificate(
            self,
            cert_id: str,
            store: str
    ) -> Optional[Certificate]:
        """
        Gets certificate by identifier
        """
        return self.___get(cert_id, store, CertManagerBuilder.TYPE_CERTIFICATE)

    def add_certificate(self, file: Path, store: str):
        """
        Adds certificate into store
        """
        self.__add(file, store, CertManagerBuilder.TYPE_CERTIFICATE)

    def remove_certificate(self, cert_id: str, store: str):
        """
        Remove certificate from store
        """
        self.__remove(cert_id, store, CertManagerBuilder.TYPE_CERTIFICATE)

    def get_crl_list(self, store: str) -> List[CRL]:
        """
        Gets CRL list
        """
        return self.__get_list(store, CertManagerBuilder.TYPE_CRL)

    def get_crl(self, cert_id: str, store: str) -> CRL:
        """
        Gets CRL by identifier
        """
        return self.___get(cert_id, store, CertManagerBuilder.TYPE_CRL)

    def add_crl(self, file: Path, store: str):
        """
        Adds CRL into store
        """
        self.__add(file, store, CertManagerBuilder.TYPE_CRL)

    def remove_crl(self, cert_id: str, store: str):
        """
        Remove CRL from store
        """
        self.__remove(cert_id, store, CertManagerBuilder.TYPE_CRL)

    def sign_attached(
            self,
            file: Path,
            store: str,
            pin: str,
            nochain: bool = False,
            norev: bool = False
    ) -> Path:
        """
        Signs file with attached signature
        """
        builder = self.__get_crypto_cp_builder()
        builder.sign_attached().all().sign_store(store).pin(pin).\
            nochain(nochain).norev(norev).work_dir(self.__temp_dir).\
            type(builder.TYPE_CERTIFICATE).work_file(file)

        self.__wrapper.execute(str(builder))
        sign = Path(str(file) + '.sig')
        # sign = file.name + '.sig'
        # sign = file

        return sign

    def sign_detached(
            self,
            file: Path,
            store: str,
            pin: str,
            nochain: bool = False,
            norev: bool = False
    ) -> Path:
        """
        Signs file with detached signature
        """
        builder = self.__get_crypto_cp_builder()
        builder.sign_detached().all().sign_store(store).pin(pin).\
            nochain(nochain).norev(norev).work_dir(self.__temp_dir).\
            type(builder.TYPE_CERTIFICATE).work_file(file)

        self.__wrapper.execute(str(builder))
        sign = Path(str(file) + '.sgn')

        return sign

    def verify_attached(
            self,
            sign: Path,
            nochain: bool = False,
            norev: bool = False
    ):
        """
        Verifies file with attached signature
        """
        builder = self.__get_crypto_cp_builder()
        builder.verify_attached().all().work_dir(self.__temp_dir).\
            nochain(nochain).norev(norev).signature_file(sign).work_file(sign)

        self.__wrapper.execute(str(builder))

    def verify_detached(
            self,
            file: Path,
            sign: Path,
            nochain: bool = False,
            norev: bool = False
    ):
        """
        Verifies file with detached signature
        """
        builder = self.__get_crypto_cp_builder()
        builder.verify_detached().all().work_dir(self.__temp_dir).\
            nochain(nochain).norev(norev).signature_file(sign).work_file(file)

        self.__wrapper.execute(str(builder))

    def __get_list(self, store: str, cert_type: str) -> List[Any]:
        """
        Gets list
        """
        builder = self.__get_cert_manager_builder()
        builder.list().store(store, False).type(cert_type)

        return self.__parse_list(self.__wrapper.execute(str(builder)))

    def ___get(
            self,
            cert_id: str,
            store: str,
            cert_type: str
    ) -> Optional[Any]:
        """
        Gets single entity
        """
        builder = self.__get_cert_manager_builder()
        builder.list().store(store, False).key_id(cert_id).type(cert_type)

        try:
            return self.__parse_list(self.__wrapper.execute(str(builder)))[0]
        except IndexError:
            return None

    def __add(self, file: Path, store: str, cert_type: str):
        """
        Adds into store
        """
        builder = self.__get_cert_manager_builder()
        builder.install().store(store, False).file(str(file)).type(cert_type)

        self.__wrapper.execute(str(builder))

    def __remove(self, cert_id: str, store: str, cert_type: str):
        """
        Remove from store
        """
        builder = self.__get_cert_manager_builder()
        builder.delete().store(store, False).key_id(cert_id).type(cert_type)

        self.__wrapper.execute(str(builder))

    def __parse_list(self, parsed: str) -> List[Certificate]:
        """
        Parses certificates list
        """
        if re.match('=\nEmpty', parsed):
            return []

        certificates = []
        sep = re.compile(r'\d+-{7}')

        for item in sep.split(parsed)[1:]:
            cert_data = {}
            for line in item.split('\n'):
                if line == '' or ':' not in line:
                    continue

                key, val = self._parse_line(line)
                cert_data[key] = val

            certificates.append(self.__create_certificate(cert_data))

        return certificates

    @classmethod
    def _parse_line(cls, line: str) -> Tuple[str, str]:
        """
        Parses line to key:value
        """
        key, val = line.split(':', 1)
        key = key.strip().lower().replace(' ', '_')
        val = val.strip()

        if key in ('sha1_hash', 'serial'):
            val = val.replace('0x', '')

        return key, val

    def __get_cert_manager_builder(self) -> CertManagerBuilder:
        """
        Gets Cert manager builder
        """
        return CertManagerBuilder(self.__cert_manager_path)

    def __get_crypto_cp_builder(self) -> CryptoCpBuilder:
        """
        Gets CryptoCP builder
        """
        return CryptoCpBuilder(self.__cryptocp_path)

    @classmethod
    def __create_certificate(cls, data: Dict[str, str]):
        """
        Creates entity
        """
        if 'subjkeyid' in data:
            return Certificate.from_data(data)

        if 'authkeyid' in data:
            return CRL.from_data(data)

        message = 'Invalid cert data {}'.format(data)
        raise Exception(message)
