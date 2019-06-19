"""
    PyCryptoPro

    Console CryptoPro providers
"""

from __future__ import annotations
from abc import ABCMeta
from pathlib import Path
import re
from subprocess import Popen, PIPE
from ..exception import CryptoProviderException


class AbstractBuilder(metaclass=ABCMeta):
    """
    Abstract builder
    """

    def __init__(self, path: str):
        self.__path = path
        self.__command = ''
        self.__args = {}

    def _set_command(self, command: str) -> AbstractBuilder:
        """
        Sets command
        """
        self.__command = command

        return self

    def _set_arg(self, name: str, value: str = None) -> AbstractBuilder:
        """
        Sets argument
        """
        self.__args[name] = value

        return self

    def _set_flagged_arg(self, name: str, flag: bool) -> AbstractBuilder:
        """
        Sets flagged (True|False) argument
        """
        if not flag and name in self.__args:
            del self.__args[name]
            return self

        return self._set_arg(name)

    def __str__(self) -> str:
        return '{0} -{1} {2}'.format(
            self.__path,
            self.__command,
            ' '.join(['-{0} {1}'.format(
                key,
                value or ''
            ) for (key, value) in self.__args.items()])
        )


class CertManagerBuilder(AbstractBuilder):
    """
    CertManager request builder
    """

    TYPE_CERTIFICATE = 'certificate'
    TYPE_CRL = 'crl'

    __types = [
        TYPE_CERTIFICATE,
        TYPE_CRL
    ]

    def list(self) -> CertManagerBuilder:
        """
        Sets "-list" command
        """
        return self._set_command('list')

    def install(self) -> CertManagerBuilder:
        """
        Sets "-install" command
        """
        return self._set_command('install')

    def delete(self) -> CertManagerBuilder:
        """
        Sets "-delete" command
        """
        return self._set_command('delete')

    def store(self, name: str, is_system: bool = True) -> CertManagerBuilder:
        """
        Sets "-store" param
        """
        return self._set_arg(
            'store',
            '{0}{1}'.format(
                's' if is_system else 'u',
                name
            )
        )

    def file(self, file_path: str) -> CertManagerBuilder:
        """
        Sets "-file" param
        """
        return self._set_arg('file', file_path)

    def container(self, name: str) -> CertManagerBuilder:
        """
        Sets "-container" param
        """
        return self._set_arg('container', name)

    def key_id(self, key_id: str) -> CertManagerBuilder:
        """
        Sets "-keyid" param
        """
        return self._set_arg('keyid', key_id)

    def type(self, cert_type: str) -> CertManagerBuilder:
        """
        Sets certificate type
        """
        if cert_type not in self.__types:
            message = 'Invalid cert type "{}"'.format(cert_type)

            raise CertManagerBuilderException(message)

        return self._set_arg(cert_type)

    def dn_filter(self, search: str) -> CertManagerBuilder:
        """
        Sets "-dn" param
        """
        return self._set_arg('dn', search)


class CryptoCpBuilder(AbstractBuilder):
    """
    CryptoCP request builder
    """

    TYPE_CERTIFICATE = 'cert'
    TYPE_CRL = 'crl'

    __types = [
        TYPE_CERTIFICATE,
        TYPE_CRL
    ]

    __working_file = ''

    def sign_attached(self) -> CryptoCpBuilder:
        """
        Sets "sign with attached signature" command
        """
        return self._set_command('sign')

    def sign_detached(self) -> CryptoCpBuilder:
        """
        Sets "sign with detached signature" command
        """
        return self._set_command('signf')

    def verify_attached(self) -> CryptoCpBuilder:
        """
        Sets "verify attached signature" command
        """
        return self._set_command('verify')

    def verify_detached(self) -> CryptoCpBuilder:
        """
        Sets "verify detached signature" command
        """
        return self._set_command('vsignf')

    def sign_store(self, store_name: str) -> CryptoCpBuilder:
        """
        Sets signature store name
        """
        return self._set_arg(store_name)

    def all(self) -> CryptoCpBuilder:
        """
        Sets '-all' param`
        """
        return self._set_arg('all')

    def norev(self, is_norev: bool = True) -> CryptoCpBuilder:
        """
        Sets '-norev' param`
        """
        return self._set_flagged_arg('norev', is_norev)

    def nochain(self, is_nochain: bool = True) -> CryptoCpBuilder:
        """
        Sets '-nochain' param`
        """
        return self._set_flagged_arg('nochain', is_nochain)

    def pin(self, pin: str) -> CryptoCpBuilder:
        """
        Sets '-pin' param`
        """
        return self._set_arg('pin', pin)

    def signature_file(self, file: Path) -> CryptoCpBuilder:
        """
        Sets '-' param`
        """
        return self._set_arg('f', str(file))

    def work_dir(self, dir_path: str) -> CryptoCpBuilder:
        """
        Sets '-dir' param`
        """
        return self._set_arg('dir', dir_path)

    def work_file(self, file: Path) -> CryptoCpBuilder:
        """
        Sets working file
        """
        self.__working_file = str(file)

        return self

    def type(self, cert_type: str) -> CryptoCpBuilder:
        """
        Sets certificate type
        """
        if cert_type not in self.__types:
            message = 'Invalid cert type "{}"'.format(cert_type)

            raise CertManagerBuilderException(message)

        return self._set_arg(cert_type)

    def __str__(self) -> str:
        return super().__str__() + ' {}'.format(self.__working_file)


class ConsoleWrapper:
    """
    Command wrapper
    """

    CODE_EMPTY_LIST = "0x8010002c"
    CODE_VERIFICATION_FAILED = '0x80091004'
    CODE_SUCCESSFUL = '0x00000000'

    def execute(self, command: str) -> str:
        """
        Executes shell command
        """
        proc = Popen(command, shell=True, stdout=PIPE, stderr=PIPE, text=True)

        return self._parse_response(*proc.communicate())

    def _parse_response(self, stdout: str, stderr: str) -> str:
        """
        Parses command output
        """
        match = re.search('ErrorCode: ([0-9a-fx]+)', stdout)
        error_code = match.group(1)

        if error_code == self.CODE_EMPTY_LIST:
            return ''

        if error_code == self.CODE_SUCCESSFUL:
            return stdout

        raise ConsoleCryptoErrorException(error_code, stdout)


class ConsoleCryptoErrorException(CryptoProviderException):
    """
    Crypto Pro error
    """


class CertManagerBuilderException(Exception):
    """
    Cert manager request building error
    """
