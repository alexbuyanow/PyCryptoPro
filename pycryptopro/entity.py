"""
    PyCryptoPro

    Certificates
"""

from __future__ import annotations
from datetime import datetime
import re
from typing import Dict


DATE_FORMAT = '%d/%m/%Y %H:%M:%S UTC'


class Info:
    """
    Person or organization info
    """

    @staticmethod
    def from_string(string: str) -> Info:
        """
        Creates info from string
        """
        return Info(dict(map(
            lambda item: (item.split('=')),
            [item for item in re.findall(
                '[A-Z]+=.+?(?=, [A-Z]+=)', string + ', Z='
            )]
        )))

    def __init__(self, data: Dict[str, str]):
        self.inn = self.__get_with_empty_default(data, 'INN')
        self.ogrn = self.__get_with_empty_default(data, 'OGRN')
        self.street = self.__get_with_empty_default(data, 'STREET')
        self.email = self.__get_with_empty_default(data, 'E')
        self.country = self.__get_with_empty_default(data, 'C')

    @classmethod
    def __get_with_empty_default(cls, data: Dict[str, str], name: str) -> str:
        """
        Gets field from dictionary with empty string as default
        """
        return data.get(name, '')


class Certificate:
    """
    Certificate
    """

    @staticmethod
    def from_data(data: Dict[str, str]) -> Certificate:
        """
        Creates certificate from data
        """
        return Certificate(
            cert_id=data['subjkeyid'],
            thumbprint=data['sha1_hash'],
            serial=data['serial'],
            valid_from=datetime.strptime(
                data['not_valid_before'],
                DATE_FORMAT
            ),
            valid_to=datetime.strptime(data['not_valid_after'], DATE_FORMAT),
            issuer=data['issuer'],
            subject=data['subject']
        )

    def __init__(
            self,
            cert_id: str,
            subject: str,
            issuer: str,
            valid_from: datetime,
            valid_to: datetime,
            serial: str,
            thumbprint: str
    ):
        self.__id = cert_id
        self.__subject = Info.from_string(subject)
        self.__issuer = Info.from_string(issuer)
        self.__valid_from = valid_from
        self.__valid_to = valid_to
        self.__serial = serial
        self.__thumbprint = thumbprint

    @property
    def identifier(self) -> str:
        """
        Gets identifier
        """
        return self.__id

    @property
    def subject(self) -> Info:
        """
        Gets subject
        """
        return self.__subject

    @property
    def issuer(self) -> Info:
        """
        Gets issuer
        """
        return self.__issuer

    @property
    def valid_from(self) -> datetime:
        """
        Gets date certificate valid from
        """
        return self.__valid_from

    @property
    def valid_to(self) -> datetime:
        """
        Gets date certificate valid to
        """
        return self.__valid_to

    @property
    def serial(self) -> str:
        """
        Gets certificate serial
        """
        return self.__serial

    @property
    def thumbprint(self) -> str:
        """
        Gets certificate hash
        """
        return self.__thumbprint


class CRL:
    """
    CRL
    """

    @staticmethod
    def from_data(data: Dict[str, str]) -> CRL:
        """
        Creates CRL from data
        """
        return CRL(
            data['authkeyid'],
            data['issuer'],
            datetime.strptime(data['thisupdate'], DATE_FORMAT),
            datetime.strptime(data['nextupdate'], DATE_FORMAT)
        )

    def __init__(
            self,
            cert_id: str,
            issuer: str,
            update: datetime,
            next_update: datetime
    ):
        self.__id = cert_id
        self.__issuer = Info.from_string(issuer)
        self.__update = update
        self.__next_update = next_update

    @property
    def identifier(self) -> str:
        """
        Gets identifier
        """
        return self.__id

    @property
    def issuer(self) -> Info:
        """
        Gets issuer
        """
        return self.__issuer

    @property
    def update(self) -> datetime:
        """
        Gets current update date
        """
        return self.__update

    @property
    def next_update(self) -> datetime:
        """
        Gets next update date
        """
        return self.__next_update


class Config:
    """
    Configuration
    """

    DEFAULT = {
        'provider_name': 'console',
        'cert_manager_path': '/opt/cprocsp/bin/amd64/certmgr',
        'cryptocp_path': '/opt/cprocsp/bin/amd64/cryptcp',
        'temp_path': '/tmp',
        'storage_name': 'ca',
        'sign_storage_name': 'uMy',
        'sign_storage_pin': '123'
    }

    def __init__(self, config: Dict[str, str] = None):
        if not config:
            config = {}

        self.__config = {**self.DEFAULT, **config}

    @property
    def cert_manager_path(self) -> str:
        """
        Gets cert manager path
        """
        return self.__config['cert_manager_path']

    @property
    def cryptocp_path(self) -> str:
        """
        Gets crypto cp path
        """
        return self.__config['cryptocp_path']

    @property
    def temp_path(self) -> str:
        """
        Gets temporary path
        """
        return self.__config['temp_path']

    @property
    def storage_name(self) -> str:
        """
        Gets certificate storage name
        """
        return self.__config['storage_name']

    @property
    def sign_storage_name(self) -> str:
        """
        Gets signature storage name
        """
        return self.__config['sign_storage_name']

    @property
    def sign_storage_pin(self) -> str:
        """
        Gets signature storage PIN
        """
        return self.__config['sign_storage_pin']

    @property
    def provider_name(self) -> str:
        """
        Gets CryptoPro provider name
        """
        return self.__config['provider_name']
