"""
    PyCryptoPro

    Common exceptions
"""


class CryptoProviderException(Exception):
    """
    Crypto providers error
    """

    def __init__(self, code, message):
        super().__init__()

        self.code = code
        self.message = message


class ValidationFailedException(Exception):
    """
    Signature validation error
    """


class CryptoProException(Exception):
    """
    Crypto Pro error
    """

    def __init__(self, code, message):
        super().__init__()

        self.code = code
        self.message = message


class ProviderNotFoundException(Exception):
    """
    Undefined CryptoPro provider error
    """
