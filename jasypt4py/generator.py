# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)

from abc import ABCMeta, abstractmethod
from Crypto import Random

from jasypt4py.exceptions import ArgumentError


class PBEParameterGenerator(object):
    __metaclass__ = ABCMeta

    @staticmethod
    def adjust(a, a_off, b):
        """
        Adjusts the byte array as per PKCS12 spec

        :param a: byte[] - the target array
        :param a_off: int - offset to operate on
        :param b: byte[] - the bitsy array to pick from
        :return: nothing as operating on array by reference
        """
        x = (b[len(b) - 1] & 0xff) + (a[a_off + len(b) - 1] & 0xff) + 1

        a[a_off + len(b) - 1] = x & 0xff

        x = x >> 8

        for i in range(len(b) - 2, -1, -1):
            x = x + (b[i] & 0xff) + (a[a_off + i] & 0xff)
            a[a_off + i] = x & 0xff
            x = x >> 8

    @staticmethod
    def pkcs12_password_to_bytes(password):
        """
        Converts a password string to a PKCS12 v1.0 compliant byte array.

        :param password: byte[] - the password as simple string
        :return: The unsigned byte array holding the password
        """
        pkcs12_pwd = [0x00] * (len(password) + 1) * 2

        for i in range(0, len(password)):
            digit = ord(password[i])
            pkcs12_pwd[i * 2] = digit >> 8
            pkcs12_pwd[i * 2 + 1] = digit

        return bytearray(pkcs12_pwd)


class PKCS12ParameterGenerator(PBEParameterGenerator):
    """
    Equivalent of the Bouncycastle PKCS12ParameterGenerator.
    """
    __metaclass__ = ABCMeta

    KEY_SIZE_256 = 256
    KEY_SIZE_128 = 128
    DEFAULT_IV_SIZE = 128

    KEY_MATERIAL = 1
    IV_MATERIAL = 2
    MAC_MATERIAL = 3

    def __init__(self, digest_factory, key_size_bits=KEY_SIZE_256, iv_size_bits=DEFAULT_IV_SIZE):
        """

        :param digest_factory: object - the digest algoritm to use (e.g. SHA256 or MD5)
        :param key_size_bits: int - key size in bits
        :param iv_size_bits: int - iv size in bits
        """
        super(PKCS12ParameterGenerator, self).__init__()
        self.digest_factory = digest_factory
        self.key_size_bits = key_size_bits
        self.iv_size_bits = iv_size_bits

    def generate_derived_parameters(self, password, salt, iterations=1000):
        """
        Generates the key and iv that can be used with the cipher.

        :param password: str - the password used for the key material
        :param salt: byte[] - random salt
        :param iterations: int - number if hash iterations for key material

        :return: key and iv that can be used to setup the cipher
        """
        key_size = (self.key_size_bits // 8)
        iv_size = (self.iv_size_bits // 8)

        # pkcs12 padded password (unicode byte array with 2 trailing 0x0 bytes)
        password_bytes = PKCS12ParameterGenerator.pkcs12_password_to_bytes(password)

        d_key = self.generate_derived_key(password_bytes, salt, iterations, self.KEY_MATERIAL, key_size)
        if iv_size and iv_size > 0:
            d_iv = self.generate_derived_key(password_bytes, salt, iterations, self.IV_MATERIAL, iv_size)
        else:
            d_iv = None
        return d_key, d_iv

    def generate_derived_key(self, password, salt, iterations, id_byte, key_size):
        """
        Generate a derived key as per PKCS12 v1.0 spec

        :param password: bytearray - pkcs12 padded password (unicode byte array with 2 trailing 0x0 bytes)
        :param salt: bytearray - random salt
        :param iterations: int - number if hash iterations for key material
        :param id_byte: int - the material padding
        :param key_size: int - the key size in bytes (e.g. AES is 256/8 = 32, IV is 128/8 = 16)
        :return: the sha256 digested pkcs12 key
        """

        u = int(self.digest_factory.digest_size)
        v = int(self.digest_factory.block_size)

        d_key = bytearray(key_size)

        # Step 1
        D = bytearray(v)
        for i in range(0, v):
            D[i] = id_byte

        # Step 2
        if salt and len(salt) != 0:
            salt_size = len(salt)
            s_size = v * ((salt_size + v - 1) // v)
            S = bytearray(s_size)

            for i in range(s_size):
                S[i] = salt[i % salt_size]
        else:
            S = bytearray(0)

        # Step 3
        if password and len(password) != 0:
            password_size = len(password)
            p_size = v * ((password_size + v - 1) // v)

            P = bytearray(p_size)

            for i in range(p_size):
                P[i] = password[i % password_size]
        else:
            P = bytearray(0)

        # Step 4
        I = S + P

        B = bytearray(v)

        # Step 5
        c = ((key_size + u - 1) // u)

        # Step 6
        for i in range(1, c + 1):
            # Step 6 - a
            digest = self.digest_factory.new()
            digest.update(bytes(D))
            digest.update(bytes(I))
            A = digest.digest()  # bouncycastle now resets the digest, we will create a new digest

            for j in range(1, iterations):
                A = self.digest_factory.new(A).digest()

            # Step 6 - b
            for k in range(0, v):
                B[k] = A[k % u]

            # Step 6 - c
            for j in range(0, (len(I) // v)):
                self.adjust(I, j * v, B)

            if i == c:
                for j in range(0, key_size - ((i - 1) * u)):
                    d_key[(i - 1) * u + j] = A[j]
            else:
                for j in range(0, u):
                    d_key[(i - 1) * u + j] = A[j]

        # we string encode as Crypto functions need strings
        return bytes(d_key)


class SaltGenerator(object):
    """
    Base for a salt generator
    """
    __metaclass__ = ABCMeta

    DEFAULT_SALT_SIZE_BYTE = 16

    def __init__(self, salt_block_size=DEFAULT_SALT_SIZE_BYTE):
        self.salt_block_size = salt_block_size

    @abstractmethod
    def generate_salt(self):
        pass


class RandomSaltGenerator(SaltGenerator):
    """
    A basic random salt generator
    """
    __metaclass__ = ABCMeta

    def __init__(self, salt_block_size=SaltGenerator.DEFAULT_SALT_SIZE_BYTE, **kwargs):
        """

        :param salt_block_size: the salt block size in bytes
        """
        super(RandomSaltGenerator, self).__init__(salt_block_size)

    def generate_salt(self):
        return bytearray(Random.get_random_bytes(self.salt_block_size))


class FixedSaltGenerator(SaltGenerator):
    """
    A fixed string salt generator
    """
    __metaclass__ = ABCMeta

    def __init__(self, salt_block_size=SaltGenerator.DEFAULT_SALT_SIZE_BYTE, salt=None, **kwargs):
        """

        :param salt_block_size: the salt block size in bytes
        """
        super(FixedSaltGenerator, self).__init__(salt_block_size)
        if not salt:
            raise ArgumentError('salt not provided')
        # ensure supplied type matches
        if isinstance(salt, str):
            self.salt = bytearray(salt, 'utf-8')
        elif isinstance(salt, bytearray):
            self.salt = salt
        else:
            raise TypeError('salt must either be a string or bytearray but not %s' % type(salt))

    def generate_salt(self):
        return self.salt
