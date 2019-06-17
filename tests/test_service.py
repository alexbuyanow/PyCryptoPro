"""
    PyCryptoPro

    CryptoPro wrapper tests
"""


from datetime import datetime
from typing import List
import unittest2 as unittest
import mock
from pycryptopro.entity import Certificate, CRL, DATE_FORMAT
from pycryptopro.service import (
    CryptoProService,
    CryptoProviderException,
    CryptoProException
)


class TestCryptoProServiceCerts(unittest.TestCase):
    """
    CryptoPro service tests (work with cets and CRLs)
    """

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_certificate_list(self, provider):
        """
        Tests certificates list getting
        """
        data = self.__cert_fixtures()
        provider.get_certificate_list.return_value = data
        service = CryptoProService(provider, '', '', '', '')

        cert_list = service.get_certificate_list()

        self.assertEqual(3, len(cert_list))
        certificate = cert_list[0]
        self.assertIsInstance(certificate, Certificate)
        self.assertEqual(certificate, data[0])
        provider.get_certificate_list.assert_called_once()

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_certificate_list_error(self, provider):
        """
        Tests certificates list getting error
        """
        provider.get_certificate_list.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = CryptoProService(provider, '', '', '', '')

        with self.assertRaisesRegex(
                CryptoProException,
                ''
        ):
            service.get_certificate_list()

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_certificate(self, provider):
        """
        Tests certificate getting
        """
        cert_id = 'id'
        store = 'cert_store'
        data = self.__cert_fixtures()[0]
        provider.get_certificate.return_value = data
        service = CryptoProService(provider, '', store, '', '')

        certificate = service.get_certificate(cert_id)
        self.assertIsInstance(certificate, Certificate)
        self.assertEqual(certificate, data)
        provider.get_certificate.assert_called_once_with(cert_id, store)

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_certificate_error(self, provider):
        """
        Tests certificate getting error
        """
        provider.get_certificate.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = CryptoProService(provider, '', '', '', '')

        with self.assertRaisesRegex(
                CryptoProException,
                ''
        ):
            service.get_certificate('id')

    @classmethod
    @mock.patch('pycryptopro.service.Path')
    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_add_certificate(cls, provider, path):
        """
        Tests certificate adding
        """
        file = bytes('file', 'utf-8')
        store = 'cert_store'
        provider.add_certificate = mock.Mock()
        service = CryptoProService(provider, '', store, '', '')

        service.add_certificate(file)
        provider.add_certificate.assert_called_once_with(path(), store)

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_add_certificate_error(self, provider):
        """
        Tests certificate adding error
        """
        provider.add_certificate.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = CryptoProService(provider, '', '', '', '')

        with mock.patch('pycryptopro.service.Path'):
            with self.assertRaisesRegex(
                    CryptoProException,
                    ''
            ):
                service.add_certificate(bytes('file', 'utf-8'))

    @classmethod
    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_remove_certificate(cls, provider):
        """
        Tests certificate removing
        """
        cert_id = 'id'
        store = 'cert_store'
        provider.remove_certificate = mock.Mock()
        service = CryptoProService(provider, '', store, '', '')

        service.remove_certificate(cert_id)
        provider.remove_certificate.assert_called_once_with(cert_id, store)

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_remove_certificate_error(self, provider):
        """
        Tests certificate removing error
        """
        provider.remove_certificate.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = CryptoProService(provider, '', '', '', '')

        with self.assertRaisesRegex(
                CryptoProException,
                ''
        ):
            service.remove_certificate('id')

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_crl_list(self, provider):
        """
        Tests CRLs cert_list getting
        """
        data = self.__crl_fixtures()
        provider.get_crl_list.return_value = data
        service = CryptoProService(provider, '', '', '', '')

        cert_list = service.get_crl_list()

        self.assertEqual(3, len(cert_list))
        crl = cert_list[0]
        self.assertIsInstance(crl, CRL)
        self.assertEqual(crl, data[0])
        provider.get_crl_list.assert_called_once()

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_crl_list_error(self, provider):
        """
        Tests CRLs list getting error
        """
        provider.get_crl_list.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = CryptoProService(provider, '', '', '', '')

        with self.assertRaisesRegex(
                CryptoProException,
                ''
        ):
            service.get_crl_list()

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_crl(self, provider):
        """
        Tests CRL getting
        """
        cert_id = 'id'
        store = 'cert_store'
        data = self.__crl_fixtures()[0]
        provider.get_crl.return_value = data
        service = CryptoProService(provider, '', store, '', '')

        crl = service.get_crl(cert_id)
        self.assertIsInstance(crl, CRL)
        self.assertEqual(crl, data)
        provider.get_crl.assert_called_once_with(cert_id, store)

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_crl_error(self, provider):
        """
        Tests CRL getting error
        """
        provider.get_crl.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = CryptoProService(provider, '', '', '', '')

        with self.assertRaisesRegex(
                CryptoProException,
                ''
        ):
            service.get_crl('id')

    @classmethod
    @mock.patch('pycryptopro.service.Path')
    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_add_crl(cls, provider, path):
        """
        Tests CRL adding
        """
        file = bytes('file', 'utf-8')
        store = 'cert_store'
        provider.add_crl = mock.Mock()
        service = CryptoProService(provider, '', store, '', '')

        service.add_crl(file)
        provider.add_crl.assert_called_once_with(path(), store)

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_add_crl_error(self, provider):
        """
        Tests CRL adding error
        """
        provider.add_crl.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = CryptoProService(provider, '', '', '', '')

        with mock.patch('pycryptopro.service.Path'):
            with self.assertRaisesRegex(
                    CryptoProException,
                    ''
            ):
                service.add_crl(bytes('file', 'utf-8'))

    @classmethod
    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_remove_crl(cls, provider):
        """
        Tests CRL removing
        """
        cert_id = 'id'
        store = 'cert_store'
        provider.remove_crl = mock.Mock()
        service = CryptoProService(provider, '', store, '', '')

        service.remove_crl(cert_id)
        provider.remove_crl.assert_called_once_with(cert_id, store)

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_remove_crl_error(self, provider):
        """
        Tests CRL removing error
        """
        provider.remove_crl.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = CryptoProService(provider, '', '', '', '')

        with self.assertRaisesRegex(
                CryptoProException,
                ''
        ):
            service.remove_crl('id')

    @classmethod
    def __cert_fixtures(cls) -> List[Certificate]:
        """
        Generates certificate fixtures
        """
        fixtures = []

        for i in range(3):
            fixtures.append(Certificate(
                'id{}'.format(i),
                'subject{}'.format(i),
                'issuer{}'.format(i),
                datetime.strptime('10/05/2016  12:56:00 UTC', DATE_FORMAT),
                datetime.strptime('10/05/2026  12:56:00 UTC', DATE_FORMAT),
                'serial{}'.format(i),
                'thumbprint{}'.format(i)
            ))

        return fixtures

    @classmethod
    def __crl_fixtures(cls) -> List[CRL]:
        """
        Generates CRL fixtures
        """
        fixtures = []

        for i in range(3):
            fixtures.append(CRL(
                'id{}'.format(i),
                'issuer{}'.format(i),
                datetime.strptime('10/05/2016  12:56:00 UTC', DATE_FORMAT),
                datetime.strptime('10/05/2026  12:56:00 UTC', DATE_FORMAT)
            ))

        return fixtures


class TestCryptoProServiceSigns(unittest.TestCase):
    """
    CryptoPro service tests (work with signs)
    """

    @mock.patch('pycryptopro.service.Path')
    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_sign_attached(self, provider, sign_path):
        """
        Tests signing with attached sign
        """
        file = bytes('file', 'utf-8')
        store = 'cert_store'
        pin = 'pin_code'
        sign_path.read_bytes.return_value = bytes('sign', 'utf-8')
        provider.sign_attached.return_value = sign_path
        service = CryptoProService(provider, '', '', store, pin)

        sign = service.sign_attached(file)

        self.assertIsInstance(sign, bytes)
        provider.sign_attached.assert_called_once_with(
            sign_path(),
            store,
            pin,
            False,
            False
        )

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_sign_attached_error(self, provider):
        """
        Tests signing with attached sign error
        """
        provider.sign_attached.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = CryptoProService(provider, '', '', '', '')

        with mock.patch('pycryptopro.service.Path'):
            with self.assertRaisesRegex(
                    CryptoProException,
                    ''
            ):
                service.sign_attached(bytes('file', 'utf-8'))

    @mock.patch('pycryptopro.service.Path')
    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_sign_detached(self, provider, sign_path):
        """
        Tests signing with detached sign
        """
        file = bytes('file', 'utf-8')
        store = 'cert_store'
        pin = 'pin_code'
        sign_path.read_bytes.return_value = bytes('sign', 'utf-8')
        provider.sign_detached.return_value = sign_path
        service = CryptoProService(provider, '', '', store, pin)

        sign = service.sign_detached(file)

        self.assertIsInstance(sign, bytes)
        provider.sign_detached.assert_called_once_with(
            sign_path(),
            store,
            pin,
            False,
            False
        )

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_sign_detached_error(self, provider):
        """
        Tests signing with detached sign error
        """
        provider.sign_detached.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = CryptoProService(provider, '', '', '', '')

        with mock.patch('pycryptopro.service.Path'):
            with self.assertRaisesRegex(
                    CryptoProException,
                    ''
            ):
                service.sign_detached(bytes('file', 'utf-8'))

    @mock.patch('pycryptopro.service.Path')
    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_verify_attached(self, provider, path):
        """
        Tests attached sign validation
        """
        file = bytes('file', 'utf-8')
        provider.verify_attached = mock.Mock()
        service = CryptoProService(provider, '', '', '', '')

        self.assertTrue(service.verify_attached(file))
        provider.verify_attached.assert_called_once_with(path(), False, False)

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_verify_attached_error(self, provider):
        """
        Tests attached sign validation error
        """
        provider.verify_attached.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = CryptoProService(provider, '', '', '', '')

        with mock.patch('pycryptopro.service.Path'):
            with self.assertRaisesRegex(
                    CryptoProException,
                    ''
            ):
                service.verify_attached(bytes('file', 'utf-8'))

    @mock.patch('pycryptopro.service.Path')
    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_verify_detached(self, provider, path):
        """
        Tests detached sign validation
        """
        file = bytes('file', 'utf-8')
        sign = bytes('sign', 'utf-8')
        provider.verify_detached = mock.Mock()
        service = CryptoProService(provider, '', '', '', '')

        self.assertTrue(service.verify_detached(file, sign))
        provider.verify_detached.assert_called_once_with(
            path(),
            path(),
            False,
            False
        )

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_verify_detached_error(self, provider):
        """
        Tests detached sign validation error
        """
        provider.verify_detached.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = CryptoProService(provider, '', '', '', '')

        with mock.patch('pycryptopro.service.Path'):
            with self.assertRaisesRegex(
                    CryptoProException,
                    ''
            ):
                service.verify_detached(
                    bytes('file', 'utf-8'),
                    bytes('sign', 'utf-8')
                )
