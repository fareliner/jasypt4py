import unittest

from jasypt4py.encryptor import StandardPBEStringEncryptor


class TestStandardPBEStringEncryptor(unittest.TestCase):

    def test_custom_salt_size(self):
        jasypt = StandardPBEStringEncryptor(algorithm='PBEWITHSHA256AND256BITAES-CBC', salt_block_size=32)

        self.assertFalse(jasypt.salt_generator is None, 'expect a salt generator to be configured')
        self.assertFalse(jasypt.key_generator is None, 'expect a key material generator to be configured')
        self.assertEqual(jasypt.salt_generator.salt_block_size, 32, 'expect a custom salt block size')

    def test_invalid_salt_generator_selected(self):
        with self.assertRaises(NotImplementedError) as context:
            StandardPBEStringEncryptor(algorithm=None, salt_generator=None)

        self.assertTrue('Salt generator None is not implemented' in context.exception)

    def test_invalid_algorithm_selected(self):
        with self.assertRaises(NotImplementedError) as context:
            StandardPBEStringEncryptor(algorithm=None)

        self.assertTrue('Algorithm None is not implemented' in context.exception)

    def test_encrypt_decrypt_with_custom_iteration(self):
        jasypt = StandardPBEStringEncryptor('PBEWITHSHA256AND256BITAES-CBC')
        pwd = 'pssst...don\'t tell anyone'
        message = 'secret value'

        encrypted_message = jasypt.encrypt(pwd, message, 4000)
        decrypted_message = jasypt.decrypt(pwd, encrypted_message, 4000)

        # print('enc = %s' % encrypted_message)
        # print('dec = %s' % decrypted_message)

        self.assertEqual(message, decrypted_message, 'expect same result from reverse function')

    def test_encrypt_decrypt_large_key(self):
        jasypt = StandardPBEStringEncryptor('PBEWITHSHA256AND256BITAES-CBC')
        pwd = 'CAX6MDwO+QwgPeGRTEjM+84LWWTfQ1icE3wj8IIc8nUAx1I2+EmbUzy8ntCB0m21SWE0IMWSr/qvRDOP1EQua2rs2RHtsGGu/dxCJQ4ct4qlcQFTKNPbhpewoxbTmaBbbrIXIny4dZzYWXte0kNS4FscUrZX1RSNGq2qoaw4MPuVSRi0WtNmtd5ZJ5HVUQohkApiecZe0TJvBppXePFEobuts+NYtpdf0vWLJtWWr3e03qP3AYelNN2GcHDZdtMaEXNT0wbBClbULDaYOC4vCmyfzbHZan6SFFX8bHvtsS1tBuCcxXzfQwUkAKJQYgNrNdOW3xyM6mVAWT4AOjtVjO3PdrmRacML3KSYv+BRktKJRgmQWF5Msg=='
        message = 'secret value'

        encrypted_message = jasypt.encrypt(pwd, message)
        decrypted_message = jasypt.decrypt(pwd, encrypted_message)

        self.assertEqual(message, decrypted_message, 'expect same result from reverse function')

    def test_encrypt_decrypt_large_message(self):
        jasypt = StandardPBEStringEncryptor('PBEWITHSHA256AND256BITAES-CBC')
        pwd = 'CAX6MDwO+QwgPeGZzYWXVAWT4AOjtVjO3PdrmRacML3KSYv+BRktKJRgmQWF5Msg=='
        message = """
        Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras rhoncus, leo vel feugiat tempor, felis ex viverra nulla, vitae finibus massa risus sed massa. Nulla malesuada sapien vel massa eleifend bibendum. Nunc congue augue lobortis augue placerat, tempor ultrices tellus pretium. Etiam at molestie velit. Vestibulum tincidunt vestibulum purus, vitae volutpat ex condimentum vel. Aliquam erat volutpat. Curabitur cursus, neque nec fringilla tempus, nulla nunc egestas ex, in tincidunt metus enim accumsan diam. Aenean pellentesque tellus quis dui posuere cursus. Mauris gravida nisl a elit eleifend, quis lobortis turpis lobortis.

        Ut at hendrerit nibh, non pulvinar dui. Praesent rhoncus molestie nulla vel accumsan. In varius neque in eros posuere tempor. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Phasellus interdum eget mauris id faucibus. Fusce eu odio ullamcorper, convallis libero sit amet, iaculis velit. Sed sollicitudin ligula arcu, ultrices pellentesque neque pharetra vitae. Morbi tristique imperdiet convallis. Donec non augue iaculis dolor lacinia consectetur in eu tellus. Maecenas sagittis erat vel fringilla aliquet. Donec vestibulum quam eget varius imperdiet. Phasellus mattis tristique orci nec efficitur. Aliquam condimentum mattis orci, non iaculis nisl scelerisque vel.

        Fusce tempus, elit dapibus rutrum rutrum, sem ante blandit lectus, sit amet bibendum arcu justo ut lorem. Mauris scelerisque lorem nec mauris dapibus, ut imperdiet quam elementum. Cras maximus lorem eget tincidunt feugiat. Vivamus at urna sollicitudin, euismod ipsum pulvinar, pretium libero. Sed sit amet interdum turpis. Integer mauris libero, ultricies eget hendrerit nec, blandit sit amet lorem. Nullam porttitor mi imperdiet felis aliquam, a porttitor augue semper. Ut massa justo, blandit ut neque malesuada, tempor placerat est. Maecenas in velit condimentum, commodo justo sit amet, mollis quam. Cras felis mi, iaculis non tempor ut, scelerisque nec eros. Suspendisse arcu magna, cursus et rutrum a, feugiat sed est. Proin ut risus mi. Duis imperdiet erat a augue consequat malesuada. Mauris lacinia nisl vel gravida facilisis. Curabitur a enim nisl.

        Morbi eget hendrerit turpis. Suspendisse sollicitudin scelerisque consectetur. Maecenas porta, leo eu sodales eleifend, velit turpis viverra mauris, in semper orci neque ut lorem. Aliquam sit amet interdum velit. Mauris elementum volutpat felis, sed ornare felis mollis in. Pellentesque vehicula placerat ex, in scelerisque sapien maximus quis. Donec vitae ante ipsum. Cras consectetur nulla at magna rutrum, et finibus tortor consectetur. Nulla facilisi. Duis nulla lectus, pulvinar ac molestie eu, placerat sit amet eros. Aenean id magna arcu. Vivamus commodo faucibus orci, sit amet accumsan justo imperdiet sit amet. Aenean dictum a arcu in ullamcorper. Vestibulum leo leo, congue nec justo eu, malesuada interdum nibh. Maecenas at sem efficitur, bibendum purus sed, tincidunt nulla.
        """

        encrypted_message = jasypt.encrypt(pwd, message)
        decrypted_message = jasypt.decrypt(pwd, encrypted_message)

        self.assertEqual(message, decrypted_message, 'expect same result from reverse function')


if __name__ == '__main__':
    unittest.main()
