# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)

from abc import ABCMeta
from array import array
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

from jasypt.generator import PKCS12ParameterGenerator, RandomSaltGenerator


class StandardPBEStringEncryptor(object):
    __metaclass__ = ABCMeta

    def __init__(self, algorithm, salt_generator='Random', **kwargs):

        if salt_generator == 'Random':
            self.salt_generator = RandomSaltGenerator(**kwargs)
        else:
            raise NotImplementedError('Salt generator %s is not implemented' % salt_generator)

        # setup the generators and cipher
        if algorithm == 'PBEWITHSHA256AND256BITAES-CBC':

            # create sha256 PKCS12 secret generator
            self.key_generator = PKCS12ParameterGenerator(SHA256)

            # setup the AES cipher
            self._cipher_factory = AES.new
            self._cipher_mode = AES.MODE_CBC

        else:
            raise NotImplementedError('Algorithm %s is not implemented' % algorithm)

    def encrypt(self, password, text, iterations=1000):

        # generate a 16 byte salt which is used to generate key material and iv
        salt = self.salt_generator.generate_salt()

        # generate key material
        key, iv = self.key_generator.generate_derived_parameters(password, salt, iterations)

        # setup AES cipher
        cipher = self._cipher_factory(key, self._cipher_mode, iv)

        # pad the plain text secret to AES block size
        encrypted_message = cipher.encrypt(self.key_generator.pad(AES.block_size, text))

        # concatenate salt + encrypted message
        return b64encode(salt + array('B', encrypted_message))

    def decrypt(self, password, ciphertext, iterations=1000):

        # decode the base64 encoded and encrypted secret
        n_cipher_bytes = b64decode(ciphertext)

        # extract salt bytes 0 - SALT_SIZE
        salt = array('B', n_cipher_bytes[:self.salt_generator.salt_block_size])
        # print('dec-salt = %s' % binascii.hexlify(salt))

        # create reverse key material
        key, iv = self.key_generator.generate_derived_parameters(password, salt, iterations)

        cipher = self._cipher_factory(key, self._cipher_mode, iv)

        # extract encrypted message bytes SALT_SIZE - len(cipher)
        n_cipher_message = array('B', n_cipher_bytes[self.salt_generator.salt_block_size:])

        # decode the message and unpad
        decoded = cipher.decrypt(n_cipher_message.tostring())

        return self.key_generator.unpad(decoded)
