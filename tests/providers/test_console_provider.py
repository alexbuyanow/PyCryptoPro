"""
    PyCryptoPro

    Console CryptoPro provider test
"""

from pathlib import Path
import unittest2 as unittest
import mock
from parameterized import parameterized
from pycryptopro.providers.console_provider import (
    CertManagerBuilder,
    CryptoCpBuilder,
    ConsoleWrapper,
    ConsoleCryptoErrorException,
    CertManagerBuilderException
)


class TestCertManagerBuilder(unittest.TestCase):
    """
    Cert Manager builder tests
    """

    def setUp(self):
        self.__builder = CertManagerBuilder('path')

    def tearDown(self):
        del self.__builder

    def test_list(self):
        """
        Tests 'list' command building
        """
        self.__assert_empty_builder()
        self.__builder.list()
        self.assertEqual('path -list ', str(self.__builder))

    def test_install(self):
        """
        Tests 'install' command building
        """
        self.__assert_empty_builder()
        self.__builder.install()
        self.assertEqual('path -install ', str(self.__builder))

    def test_delete(self):
        """
        Tests 'delete' command building
        """
        self.__assert_empty_builder()
        self.__builder.delete()
        self.assertEqual('path -delete ', str(self.__builder))

    @parameterized.expand([
        ('My', False, 'path - -store uMy'),
        ('My', True, 'path - -store sMy'),
        ('root', False, 'path - -store uroot'),
        ('root', True, 'path - -store sroot'),
    ])
    def test_store(self, name: str, is_system: bool, result: str):
        """
        Tests 'store' option building
        """
        self.__assert_empty_builder()
        self.__builder.store(name, is_system)
        self.assertEqual(result, str(self.__builder))

    def test_file(self):
        """
        Tests 'file' option building
        """
        self.__assert_empty_builder()
        self.__builder.file('file_name')
        self.assertEqual('path - -file file_name', str(self.__builder))

    def test_container(self):
        """
        Tests 'container' option building
        """
        self.__assert_empty_builder()
        self.__builder.container('container_id')
        self.assertEqual('path - -container container_id', str(self.__builder))

    def test_key_id(self):
        """
        Tests 'keyid' option building
        """
        self.__assert_empty_builder()
        self.__builder.key_id('id')
        self.assertEqual('path - -keyid id', str(self.__builder))

    @parameterized.expand([
        (CertManagerBuilder.TYPE_CERTIFICATE, 'path - -certificate '),
        (CertManagerBuilder.TYPE_CRL, 'path - -crl '),
    ])
    def test_type(self, cert_type: str, result: str):
        """
        Tests 'certificate' and 'crl' option building
        """
        self.__assert_empty_builder()
        self.__builder.type(cert_type)
        self.assertEqual(result, str(self.__builder))

    def test_type_incorrect(self):
        """
        Tests ''certificate' and 'crl' option building with incorrect type
        """
        with self.assertRaisesRegex(
                CertManagerBuilderException,
                'Invalid cert type "any"'
        ):
            self.__builder.type('any')

    def __assert_empty_builder(self):
        """
        Checks empty command string building
        """
        self.assertEqual('path - ', str(self.__builder))


class TestCryptoCpBuilder(unittest.TestCase):
    """
    CryptoCp builder tests
    """

    def setUp(self):
        self.__builder = CryptoCpBuilder('path')

    def tearDown(self):
        del self.__builder

    def test_sign_attached(self):
        """
        Tests 'sign' command building
        """
        self.__assert_empty_builder()
        self.__builder.sign_attached()
        self.assertEqual('path -sign  ', str(self.__builder))

    def test_sign_detached(self):
        """
        Tests 'signf' command building
        """
        self.__assert_empty_builder()
        self.__builder.sign_detached()
        self.assertEqual('path -signf  ', str(self.__builder))

    def test_verify_attached(self):
        """
        Tests 'verify' command building
        """
        self.__assert_empty_builder()
        self.__builder.verify_attached()
        self.assertEqual('path -verify  ', str(self.__builder))

    def test_verify_detached(self):
        """
        Tests 'vsignf' command building
        """
        self.__assert_empty_builder()
        self.__builder.verify_detached()
        self.assertEqual('path -vsignf  ', str(self.__builder))

    def test_sign_store(self):
        """
        Tests store name option building
        """
        self.__assert_empty_builder()
        self.__builder.sign_store('My')
        self.assertEqual('path - -My  ', str(self.__builder))

    def test_all(self):
        """
        Tests '-all' option building
        """
        self.__assert_empty_builder()
        self.__builder.all()
        self.assertEqual('path - -all  ', str(self.__builder))

    def test_norev(self):
        """
        Tests '-norev' option building
        """
        self.__assert_empty_builder()
        self.__builder.norev()
        self.assertEqual('path - -norev  ', str(self.__builder))

        self.__builder.norev(False)
        self.__assert_empty_builder()

    def test_nochain(self):
        """
        Tests '-nochain' option building
        """
        self.__assert_empty_builder()
        self.__builder.nochain()
        self.assertEqual('path - -nochain  ', str(self.__builder))

        self.__builder.nochain(False)
        self.__assert_empty_builder()

    def test_pin(self):
        """
        Tests 'pin' option building
        """
        self.__assert_empty_builder()
        self.__builder.pin('123')
        self.assertEqual('path - -pin 123 ', str(self.__builder))

    def test_signature_file(self):
        """
        Tests signature file option building
        """
        self.__assert_empty_builder()
        self.__builder.signature_file(Path('/test/test'))
        self.assertEqual('path - -f /test/test ', str(self.__builder))

    def test_work_dir(self):
        """
        Tests '-dir' option building
        """
        self.__assert_empty_builder()
        self.__builder.work_dir('/test/test')
        self.assertEqual('path - -dir /test/test ', str(self.__builder))

    def test_work_file(self):
        """
        Tests file option building
        """
        self.__assert_empty_builder()
        self.__builder.work_file(Path('/test/test'))
        self.assertEqual('path -  /test/test', str(self.__builder))

    @parameterized.expand([
        (CryptoCpBuilder.TYPE_CERTIFICATE, 'path - -cert  '),
        (CryptoCpBuilder.TYPE_CRL, 'path - -crl  '),
    ])
    def test_type(self, cert_type: str, result: str):
        """
        Tests '-cert' and '-crt' option building
        """
        self.__assert_empty_builder()
        self.__builder.type(cert_type)
        self.assertEqual(result, str(self.__builder))

    def test_type_incorrect(self):
        """
        Tests '-cert' and '-crt' option building with wrong type
        """
        with self.assertRaisesRegex(
                CertManagerBuilderException,
                'Invalid cert type "any"'
        ):
            self.__builder.type('any')

    def __assert_empty_builder(self):
        """
        Checks empty command string building
        """
        self.assertEqual('path -  ', str(self.__builder))


class TestConsoleWrapper(unittest.TestCase):
    """
    Console wrapper tests
    """

    @mock.patch('pycryptopro.providers.console_provider.Popen')
    def test_execute_success(self, popen):
        """
        Tests command execution with success result
        """
        popen.return_value.communicate.return_value = (
            'ErrorCode: 0x00000000',
            ''
        )

        result = ConsoleWrapper().execute('command')

        self.assertEqual('ErrorCode: 0x00000000', result)
        popen.return_value.communicate.assert_called_once_with()

    @mock.patch('pycryptopro.providers.console_provider.Popen')
    def test_execute_empty(self, popen):
        """
        Tests command execution with 'empty list' result
        """
        popen.return_value.communicate.return_value = (
            'ErrorCode: 0x8010002c',
            ''
        )

        result = ConsoleWrapper().execute('command')

        self.assertEqual('', result)
        popen.return_value.communicate.assert_called_once_with()

    @mock.patch('pycryptopro.providers.console_provider.Popen')
    def test_execute_error(self, popen):
        """
        Tests command execution with error result
        """
        popen.return_value.communicate.return_value = (
            'ErrorCode: 0x123456',
            ''
        )

        with self.assertRaisesRegex(
                ConsoleCryptoErrorException,
                ''
        ) as exception:
            ConsoleWrapper().execute('command')

        self.assertEqual('0x123456', exception.exception.code)
        self.assertEqual('ErrorCode: 0x123456', exception.exception.message)
        popen.return_value.communicate.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
