"""
    PyCryptoPro

    CryptoPro data providers
"""

from __future__ import annotations
from abc import abstractmethod, ABCMeta
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from .entity import Certificate, CRL, Config
from .exception import ProviderNotFoundException
from .filter import CertFilterInterface
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
    def get_certificate_list(
            self,
            store: str,
            list_filter: CertFilterInterface
    ) -> Tuple[int, List[Certificate]]:
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
    def get_crl_list(
            self,
            store: str,
            list_filter: CertFilterInterface
    ) -> Tuple[int, List[CRL]]:
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


class CryptoProviderFactory:
    """
    CryptoPro providers factory
    """

    __providers: Dict[str, CryptoProviderInterface] = {}

    def __init__(self, config: Config):
        self.add_provider('console', ConsoleProvider(config))

    def get_provider(self, name: str) -> CryptoProviderInterface:
        """
        Gets CryptoPro provider by name
        """
        if name not in self.__providers:
            message = 'Provider "{}" not exists'.format(name)

            raise ProviderNotFoundException(message)

        return self.__providers[name]

    def add_provider(self, name: str, provider: CryptoProviderInterface):
        """
        Adds provider
        """
        self.__providers[name] = provider


class ConsoleProvider(CryptoProviderInterface):
    """
    Console CryptoPro providers
    """

    def __init__(
            self,
            config: Config
    ):
        self.__cert_manager_path = config.cert_manager_path
        self.__cryptocp_path = config.cryptocp_path
        self.__temp_dir = config.temp_path
        self.__wrapper = ConsoleWrapper()

    def get_certificate_list(
            self,
            store: str,
            list_filter: CertFilterInterface
    ) -> Tuple[int, List[Certificate]]:
        """
        Gets certificates list
        """
        return self.__get_list(
            store,
            list_filter,
            CertManagerBuilder.TYPE_CERTIFICATE
        )

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

    def get_crl_list(
            self,
            store: str,
            list_filter: CertFilterInterface
    ) -> Tuple[int, List[CRL]]:
        """
        Gets CRL list
        """
        return self.__get_list(store, list_filter, CertManagerBuilder.TYPE_CRL)

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

    def __get_list(
            self,
            store: str,
            list_filter: CertFilterInterface,
            cert_type: str
    ) -> Tuple[int, List[Any]]:
        """
        Gets list
        """
        builder = self.__get_cert_manager_builder()
        builder.list().store(store, False).type(cert_type)

        self.__filter_list(builder, list_filter)
        items_list = self.__parse_list(self.__wrapper.execute(str(builder)))

        return len(items_list), self.__limit_list(items_list, list_filter)

    @classmethod
    def __filter_list(
            cls,
            builder: CertManagerBuilder,
            list_filter: CertFilterInterface
    ):
        """
        Applies filter
        """
        if list_filter.search():
            for search in list_filter.search():
                builder.dn_filter(search)

    @classmethod
    def __limit_list(
            cls,
            items_list: List,
            list_filter: CertFilterInterface
    ) -> List[Any]:
        """
        Limits list with limit and offset
        """
        items_length = len(items_list)
        start = list_filter.offset()

        if start > items_length:
            return []

        finish = (start + list_filter.limit()) \
            if list_filter.limit() else items_length
        finish = finish if finish <= items_length else items_length

        return items_list[start:finish]

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
