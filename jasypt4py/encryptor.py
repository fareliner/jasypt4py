# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)

import sys
from abc import ABCMeta
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

from jasypt4py.generator import PKCS12ParameterGenerator, RandomSaltGenerator, FixedSaltGenerator, OpenSSLPBEParametersGenerator

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

# an encode function that takes a byte array and returns an encoded python string
if PY2:
    str_encode = lambda s: str(s)
elif PY3:
    str_encode = lambda s: str(s, 'utf-8')


class StandardPBEStringEncryptor(object):
    __metaclass__ = ABCMeta

    def __init__(self, algorithm, salt_generator='Random', **kwargs):

        if salt_generator == 'Random':
            self.salt_generator = RandomSaltGenerator(**kwargs)
        elif salt_generator == 'Fixed':
            self.salt_generator = FixedSaltGenerator(**kwargs)
        else:
            raise NotImplementedError('Salt generator %s is not implemented' % salt_generator)

        # setup the generators and cipher
        if algorithm == 'PBEWITHSHA256AND256BITAES-CBC':

            # create sha256 PKCS12 secret generator
            self.key_generator = PKCS12ParameterGenerator(SHA256)

            # setup the AES cipher
            self._cipher_factory = AES.new
            self._cipher_mode = AES.MODE_CBC
        elif algorithm == 'PBEWITHSHA256AND128BITAES-CBC':

            # create sha256 PKCS12 secret generator
            self.key_generator = PKCS12ParameterGenerator(SHA256, key_size_bits=PKCS12ParameterGenerator.KEY_SIZE_128)

            # setup the AES cipher
            self._cipher_factory = AES.new
            self._cipher_mode = AES.MODE_CBC

        elif algorithm == 'PBEWITHMD5AND128BITAES_CBC_OPENSSL':

            # create MD5 generator
            self.key_generator = OpenSSLPBEParametersGenerator()

            # setup the AES cipher
            self._cipher_factory = AES.new
            self._cipher_mode = AES.MODE_CBC

        else:
            raise NotImplementedError('Algorithm %s is not implemented' % algorithm)

    @staticmethod
    def pad(block_size, s):
        """
        Pad a string to the provided block size when using fixed block ciphers.

        :param block_size: int - the cipher block size
        :param s: str - the string to pad
        :return: a padded string that can be fed to the cipher
        """
        return s + (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size)

    @staticmethod
    def unpad(s):
        """
        Remove padding from the string after decryption when using fixed block ciphers.

        :param s: str - the string to remove padding from
        :return: the unpadded string
        """
        if PY2:
            return s[0:-ord(s[-1])]
        elif PY3:
            return s[0:-s[-1]]
        else:
            raise ImportError('Only Python 2 and 3 are supported')

    def encrypt(self, password, text, iterations=1000):

        # generate a 16 byte salt which is used to generate key material and iv
        salt = self.salt_generator.generate_salt()

        # generate key material
        key, iv = self.key_generator.generate_derived_parameters(password, salt, iterations)

        # setup AES cipher
        cipher = self._cipher_factory(key, self._cipher_mode, iv)

        # pad the plain text secret to AES block size
        encrypted_message = cipher.encrypt(self.pad(AES.block_size, text))

        # concatenate salt + encrypted message
        return str_encode(b64encode(bytes(salt) + encrypted_message))

    def decrypt(self, password, ciphertext, iterations=1000):

        # decode the base64 encoded and encrypted secret
        n_cipher_bytes = b64decode(ciphertext)

        # extract salt bytes 0 - SALT_SIZE
        salt = n_cipher_bytes[:self.salt_generator.salt_block_size]
        # print('dec-salt = %s' % binascii.hexlify(salt))

        # create reverse key material
        key, iv = self.key_generator.generate_derived_parameters(password, salt, iterations)

        cipher = self._cipher_factory(key, self._cipher_mode, iv)

        # extract encrypted message bytes SALT_SIZE - len(cipher)
        n_cipher_message = n_cipher_bytes[self.salt_generator.salt_block_size:]

        # decode the message and unpad
        decoded = cipher.decrypt(n_cipher_message)

        return str_encode(self.unpad(decoded))
