"""
    PyCryptoPro

    CryptoPro providers test
"""

from datetime import datetime
from pathlib import Path
import unittest2 as unittest
import mock
from pycryptopro.provider import (
    CryptoProviderInterface,
    ConsoleProvider,
    CryptoProviderFactory
)
from pycryptopro.entity import Certificate, CRL, Info, Config, DATE_FORMAT
from pycryptopro.exception import ProviderNotFoundException


class TestCryptoProviderFactory(unittest.TestCase):
    """
    Providers factory tests
    """

    def setUp(self):
        self.__factory = CryptoProviderFactory(Config())

    def tearDown(self):
        del self.__factory

    def test_get_provider(self):
        """
        Tests provider getting
        """
        provider = self.__factory.get_provider('console')

        self.assertIsInstance(provider, CryptoProviderInterface)
        self.assertIsInstance(provider, ConsoleProvider)

    def test_get_provider_error(self):
        """
        Tests absent provider getting
        """
        with self.assertRaisesRegex(
                ProviderNotFoundException,
                'Provider "undefined" not exists'
        ):
            self.__factory.get_provider('undefined')

    @mock.patch('pycryptopro.provider.CryptoProviderInterface')
    def test_add_provider(self, provider):
        """
        Tests provider adding
        """
        self.__factory.add_provider('test', provider)

        self.assertEqual(
            self.__factory.get_provider('test'),
            provider
        )


class TestConsoleProvider(unittest.TestCase):
    """
    Console provider tests
    """

    def setUp(self):
        self.__cert_fixture = Path(
            './tests/certificate_fixture.txt'
        ).read_text()
        self.__crl_fixture = Path('./tests/crl_fixture.txt').read_text()

    def tearDown(self):
        del self.__crl_fixture
        del self.__cert_fixture

    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_get_certificate_list(self, wrapper):
        """
        Tests certificate list getting
        """
        wrapper.return_value.execute.return_value = self.__cert_fixture
        provider = ConsoleProvider(Config())

        result = provider.get_certificate_list('')

        self.assertEqual(5, len(result))
        certificate = result[0]
        self.__assert_cert(certificate)
        wrapper.return_value.execute.assert_called_once()

    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_get_certificate_list_empty(self, wrapper):
        """
        Tests empty certificate list getting
        """
        wrapper.return_value.execute.return_value = ''
        provider = ConsoleProvider(Config())

        result = provider.get_certificate_list('')

        self.assertEqual(0, len(result))
        wrapper.return_value.execute.assert_called_once()

    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_get_certificate(self, wrapper):
        """
        Tests certificate getting
        """
        wrapper.return_value.execute.return_value = self.__cert_fixture
        provider = ConsoleProvider(Config())

        certificate = provider.get_certificate('', '')

        self.__assert_cert(certificate)
        wrapper.return_value.execute.assert_called_once()

    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_get_certificate_absent(self, wrapper):
        """
        Tests absent certificate getting
        """
        wrapper.return_value.execute.return_value = ''
        provider = ConsoleProvider(Config())

        self.assertIsNone(provider.get_certificate('', ''))
        wrapper.return_value.execute.assert_called_once()

    @classmethod
    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_add_certificate(cls, wrapper):
        """
        Tests certificate adding
        """
        wrapper.return_value.execute.return_value = ''
        provider = ConsoleProvider(Config())

        provider.add_certificate(Path(), '')
        wrapper.return_value.execute.assert_called_once()

    @classmethod
    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_remove_certificate(cls, wrapper):
        """
        Tests certificate removing
        """
        wrapper.return_value.execute.return_value = ''
        provider = ConsoleProvider(Config())

        provider.remove_certificate('', '')
        wrapper.return_value.execute.assert_called_once()

    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_get_crl_list(self, wrapper):
        """
        Tests CRL list getting
        """
        wrapper.return_value.execute.return_value = self.__crl_fixture
        provider = ConsoleProvider(Config())

        result = provider.get_crl_list('')

        self.assertEqual(2, len(result))
        certificate = result[0]
        self.__assert_crl(certificate)
        wrapper.return_value.execute.assert_called_once()

    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_get_crl_list_empty(self, wrapper):
        """
        Tests empty CRL list getting
        """
        wrapper.return_value.execute.return_value = ''
        provider = ConsoleProvider(Config())

        result = provider.get_crl_list('')

        self.assertEqual(0, len(result))
        wrapper.return_value.execute.assert_called_once()

    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_get_crl(self, wrapper):
        """
        Tests CRL getting
        """
        wrapper.return_value.execute.return_value = self.__crl_fixture
        provider = ConsoleProvider(Config())

        certificate = provider.get_crl('', '')

        self.__assert_crl(certificate)
        wrapper.return_value.execute.assert_called_once()

    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_get_crl_absent(self, wrapper):
        """
        Tests absent CRL getting
        """
        wrapper.return_value.execute.return_value = ''
        provider = ConsoleProvider(Config())

        self.assertIsNone(provider.get_crl('', ''))
        wrapper.return_value.execute.assert_called_once()

    @classmethod
    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_add_crl(cls, wrapper):
        """
        Tests CRL adding
        """
        wrapper.return_value.execute.return_value = ''
        provider = ConsoleProvider(Config())

        provider.add_crl(Path(), '')
        wrapper.return_value.execute.assert_called_once()

    @classmethod
    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_remove_crl(cls, wrapper):
        """
        Tests CRL removing
        """
        wrapper.return_value.execute.return_value = ''
        provider = ConsoleProvider(Config())

        provider.remove_crl('', '')
        wrapper.return_value.execute.assert_called_once()

    @classmethod
    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_sign_attached(cls, wrapper):
        """
        Tests signing with attached sign
        """
        wrapper.return_value.execute.return_value = 'ErrorCode: 0x00000000'
        provider = ConsoleProvider(Config())

        provider.sign_attached(Path(), '', '')
        wrapper.return_value.execute.assert_called_once()

    @classmethod
    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_sign_detached(cls, wrapper):
        """
        Tests signing with detached sign
        """
        wrapper.return_value.execute.return_value = 'ErrorCode: 0x00000000'
        provider = ConsoleProvider(Config())

        provider.sign_detached(Path(), '', '')
        wrapper.return_value.execute.assert_called_once()

    @classmethod
    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_verify_attached(cls, wrapper):
        """
        Tests attached sign validation
        """
        wrapper.return_value.execute.return_value = 'ErrorCode: 0x00000000'
        provider = ConsoleProvider(Config())

        provider.verify_attached(Path(), Path())
        wrapper.return_value.execute.assert_called_once()

    @classmethod
    @mock.patch('pycryptopro.provider.ConsoleWrapper')
    def test_verify_detached(cls, wrapper):
        """
        Tests detached sign validation
        """
        wrapper.return_value.execute.return_value = 'ErrorCode: 0x00000000'
        provider = ConsoleProvider(Config())

        provider.verify_detached(Path(), Path())
        wrapper.return_value.execute.assert_called_once()

    def __assert_cert(self, certificate):
        """
        Checks certificate data
        """
        self.assertIsInstance(certificate, Certificate)
        self.assertEqual(
            '5aac2b534b8d50306757bab8289886b755444e03',
            certificate.identifier
        )
        self.assertIsInstance(certificate.subject, Info)
        self.assertIsInstance(certificate.subject, Info)
        self.assertEqual(
            datetime.strptime('01/12/2016  17:15:00 UTC', DATE_FORMAT),
            certificate.valid_from
        )
        self.assertEqual(
            datetime.strptime('01/12/2026  17:25:00 UTC', DATE_FORMAT),
            certificate.valid_to
        )
        self.assertEqual('4DE522A4000300000815', certificate.serial)
        self.assertEqual(
            '19a2784dfc468bf50316c8d3c6646cd3be8b7da4',
            certificate.thumbprint
        )

    def __assert_crl(self, certificate):
        """
        Checks CRL data
        """
        self.assertIsInstance(certificate, CRL)
        self.assertEqual(
            '5aac2b534b8d50306757bab8289886b755444e03',
            certificate.identifier
        )
        self.assertIsInstance(certificate.issuer, Info)
        self.assertEqual(
            datetime.strptime('05/06/2019  13:50:00 UTC', DATE_FORMAT),
            certificate.update
        )
        self.assertEqual(
            datetime.strptime('06/06/2019  17:10:00 UTC', DATE_FORMAT),
            certificate.next_update
        )


if __name__ == '__main__':
    unittest.main()
