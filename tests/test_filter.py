"""
    PyCryptoPro

    Filters tests
"""

from typing import List
import unittest2 as unittest
from parameterized import parameterized
from pycryptopro.filter import CertFilter


class TestCertFilter(unittest.TestCase):
    """
    List filter test
    """

    @parameterized.expand([
        ('one', ['one']),
        ('any different words', ['any', 'different', 'words']),
        ('word word', ['word']),
        ('', []),
        (None, []),
    ])
    def test_search(self, value: str, output: List):
        """
        Test search string
        """
        cert_filter = CertFilter(value)

        self.assertListEqual(sorted(output), sorted(cert_filter.search))

    @parameterized.expand([
        (0, 0),
        (10, 10),
        (-1, 0),
        (None, 0),
    ])
    def test_limit(self, value: int, output: int):
        """
        Tests limit
        """
        cert_filter = CertFilter('', value)

        self.assertEqual(output, cert_filter.limit)

    @parameterized.expand([
        (0, 0),
        (10, 10),
        (-1, 0),
        (None, 0),
    ])
    def test_offset(self, value: int, output: int):
        """
        Tests offset
        """
        cert_filter = CertFilter('', 0, value)

        self.assertEqual(output, cert_filter.offset)
