"""
    PyCryptoPro

    CryptoPro wrapper tests
"""


from datetime import datetime
from typing import List
import unittest2 as unittest
import mock
from pycryptopro.entity import Certificate, CRL, Config, DATE_FORMAT
from pycryptopro.service import (
    CryptoProService,
    CryptoProviderException,
    CryptoProException
)
from pycryptopro.provider import CryptoProviderInterface, CryptoProviderFactory

CONFIG = {
    'cert_manager_path': '',
    'cryptocp_path': '',
    'temp_path': '',
    'storage_name': 'store',
    'sign_storage_name': 'cert_store',
    'sign_storage_pin': 'pin_code'
}


class AbstractCryptoProServiceTest(unittest.TestCase):
    """
    CryptoPro service tests prototype
    """

    @classmethod
    def _get_service(
            cls,
            provider: CryptoProviderInterface
    ) -> CryptoProService:
        """
        Gets CryptoPro service
        """
        factory = mock.Mock(CryptoProviderFactory)
        factory.get_provider.return_value = provider
        service = CryptoProService(factory, Config(CONFIG))

        return service


class TestCryptoProServiceCerts(AbstractCryptoProServiceTest):
    """
    CryptoPro service tests (work with cets and CRLs)
    """

    @mock.patch('pycryptopro.service.CertFilterInterface')
    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_certificate_list(self, provider, list_filter):
        """
        Tests certificates list getting
        """
        data = self.__cert_fixtures()
        provider.get_certificate_list.return_value = (len(data), data)
        service = self._get_service(provider)

        count, cert_list = service.get_certificate_list(list_filter)

        self.assertEqual(3, count)
        self.assertEqual(3, len(cert_list))
        certificate = cert_list[0]
        self.assertIsInstance(certificate, Certificate)
        self.assertEqual(certificate, data[0])
        provider.get_certificate_list.assert_called_once()

    @mock.patch('pycryptopro.service.CertFilterInterface')
    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_certificate_list_error(self, provider, list_filter):
        """
        Tests certificates list getting error
        """
        provider.get_certificate_list.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = self._get_service(provider)

        with self.assertRaisesRegex(
                CryptoProException,
                ''
        ):
            service.get_certificate_list(list_filter)

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_certificate(self, provider):
        """
        Tests certificate getting
        """
        cert_id = 'id'
        data = self.__cert_fixtures()[0]
        provider.get_certificate.return_value = data
        service = self._get_service(provider)

        certificate = service.get_certificate(cert_id)
        self.assertIsInstance(certificate, Certificate)
        self.assertEqual(certificate, data)
        provider.get_certificate.assert_called_once_with(
            cert_id,
            CONFIG['storage_name']
        )

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_certificate_error(self, provider):
        """
        Tests certificate getting error
        """
        provider.get_certificate.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = self._get_service(provider)

        with self.assertRaisesRegex(
                CryptoProException,
                ''
        ):
            service.get_certificate('id')

    @mock.patch('pycryptopro.service.Path')
    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_add_certificate(self, provider, path):
        """
        Tests certificate adding
        """
        file = bytes('file', 'utf-8')
        provider.add_certificate = mock.Mock()
        service = self._get_service(provider)

        service.add_certificate(file)
        provider.add_certificate.assert_called_once_with(
            path(),
            CONFIG['storage_name']
        )

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_add_certificate_error(self, provider):
        """
        Tests certificate adding error
        """
        provider.add_certificate.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = self._get_service(provider)

        with mock.patch('pycryptopro.service.Path'):
            with self.assertRaisesRegex(
                    CryptoProException,
                    ''
            ):
                service.add_certificate(bytes('file', 'utf-8'))

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_remove_certificate(self, provider):
        """
        Tests certificate removing
        """
        cert_id = 'id'
        provider.remove_certificate = mock.Mock()
        service = self._get_service(provider)

        service.remove_certificate(cert_id)
        provider.remove_certificate.assert_called_once_with(
            cert_id,
            CONFIG['storage_name']
        )

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_remove_certificate_error(self, provider):
        """
        Tests certificate removing error
        """
        provider.remove_certificate.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = self._get_service(provider)

        with self.assertRaisesRegex(
                CryptoProException,
                ''
        ):
            service.remove_certificate('id')

    @mock.patch('pycryptopro.service.CertFilterInterface')
    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_crl_list(self, provider, list_filter):
        """
        Tests CRLs cert_list getting
        """
        data = self.__crl_fixtures()
        provider.get_crl_list.return_value = (len(data), data)
        service = self._get_service(provider)
        count, cert_list = service.get_crl_list(list_filter)

        self.assertEqual(3, count)
        self.assertEqual(3, len(cert_list))
        crl = cert_list[0]
        self.assertIsInstance(crl, CRL)
        self.assertEqual(crl, data[0])
        provider.get_crl_list.assert_called_once()

    @mock.patch('pycryptopro.service.CertFilterInterface')
    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_crl_list_error(self, provider, list_filter):
        """
        Tests CRLs list getting error
        """
        provider.get_crl_list.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = self._get_service(provider)

        with self.assertRaisesRegex(
                CryptoProException,
                ''
        ):
            service.get_crl_list(list_filter)

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_crl(self, provider):
        """
        Tests CRL getting
        """
        cert_id = 'id'
        data = self.__crl_fixtures()[0]
        provider.get_crl.return_value = data
        service = self._get_service(provider)

        crl = service.get_crl(cert_id)
        self.assertIsInstance(crl, CRL)
        self.assertEqual(crl, data)
        provider.get_crl.assert_called_once_with(
            cert_id,
            CONFIG['storage_name']
        )

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_get_crl_error(self, provider):
        """
        Tests CRL getting error
        """
        provider.get_crl.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = self._get_service(provider)

        with self.assertRaisesRegex(
                CryptoProException,
                ''
        ):
            service.get_crl('id')

    @mock.patch('pycryptopro.service.Path')
    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_add_crl(self, provider, path):
        """
        Tests CRL adding
        """
        file = bytes('file', 'utf-8')
        provider.add_crl = mock.Mock()
        service = self._get_service(provider)

        service.add_crl(file)
        provider.add_crl.assert_called_once_with(
            path(),
            CONFIG['storage_name']
        )

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_add_crl_error(self, provider):
        """
        Tests CRL adding error
        """
        provider.add_crl.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = self._get_service(provider)

        with mock.patch('pycryptopro.service.Path'):
            with self.assertRaisesRegex(
                    CryptoProException,
                    ''
            ):
                service.add_crl(bytes('file', 'utf-8'))

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_remove_crl(self, provider):
        """
        Tests CRL removing
        """
        cert_id = 'id'
        provider.remove_crl = mock.Mock()
        service = self._get_service(provider)

        service.remove_crl(cert_id)
        provider.remove_crl.assert_called_once_with(
            cert_id,
            CONFIG['storage_name']
        )

    @mock.patch('pycryptopro.CryptoProviderInterface')
    def test_remove_crl_error(self, provider):
        """
        Tests CRL removing error
        """
        provider.remove_crl.side_effect = CryptoProviderException(
            'code',
            'message'
        )
        service = self._get_service(provider)

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


class TestCryptoProServiceSigns(AbstractCryptoProServiceTest):
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
        sign_path.read_bytes.return_value = bytes('sign', 'utf-8')
        provider.sign_attached.return_value = sign_path
        service = self._get_service(provider)

        sign = service.sign_attached(file)

        self.assertIsInstance(sign, bytes)
        provider.sign_attached.assert_called_once_with(
            sign_path(),
            CONFIG['sign_storage_name'],
            CONFIG['sign_storage_pin'],
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
        service = self._get_service(provider)

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
        sign_path.read_bytes.return_value = bytes('sign', 'utf-8')
        provider.sign_detached.return_value = sign_path
        service = self._get_service(provider)

        sign = service.sign_detached(file)

        self.assertIsInstance(sign, bytes)
        provider.sign_detached.assert_called_once_with(
            sign_path(),
            CONFIG['sign_storage_name'],
            CONFIG['sign_storage_pin'],
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
        service = self._get_service(provider)

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
        service = self._get_service(provider)

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
        service = self._get_service(provider)

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
        service = self._get_service(provider)

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
        service = self._get_service(provider)

        with mock.patch('pycryptopro.service.Path'):
            with self.assertRaisesRegex(
                    CryptoProException,
                    ''
            ):
                service.verify_detached(
                    bytes('file', 'utf-8'),
                    bytes('sign', 'utf-8')
                )
