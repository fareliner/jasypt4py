# Jasypt for Python

A python module that produces Jasypt/Bouncycastle compatible hashes and encrypted passwords.    

### Prerequisites

Any python environment that can run `pycrypto`.

### Installation

Download the packaged [jasypt4py module](https://github.com/fareliner/jasypt4py/releases/latest) and install it with pip.

Example `pip` Installation:

```sh
pip install -U jasypt4py
```

### Limitations

Currently only supports `PBEWITHSHA256AND256BITAES-CBC-BC` from Jasypt/Bouncycastle.

### Usage

See tests.

#### Encryption

Jasypt encryption function:

```sh
$JASYPT_HOME/bin/encrypt.sh providerClassName = "org.bouncycastle.jce.provider.BouncyCastleProvider" \
                            saltGeneratorClassName = "org.jasypt.salt.RandomSaltGenerator" \
                            algorithm = "PBEWITHSHA256AND256BITAES-CBC-BC" \
                            password = 'pssst...don\'t tell anyone' \
                            keyObtentionIterations = 4000 \
                            input = 'secret value'
```

is equivalent to:

```python
from jasypt4py import StandardPBEStringEncryptor

cryptor = StandardPBEStringEncryptor('PBEWITHSHA256AND256BITAES-CBC')

cryptor.encrypt('pssst...don\'t tell anyone', 'secret value', 4000)
```

#### Decryption

Jasypt decryption function:

```sh
$JASYPT_HOME/bin/decrypt.sh providerClassName = "org.bouncycastle.jce.provider.BouncyCastleProvider" \
                            saltGeneratorClassName = "org.jasypt.salt.RandomSaltGenerator" \
                            algorithm = "PBEWITHSHA256AND256BITAES-CBC-BC" \
                            password = 'pssst...don\'t tell anyone' \
                            keyObtentionIterations = 4000 \
                            input = 'xgX5+yRbKhs4zSubkAPkg9gSBkZU6XWt7csceM/3xDY='
```

is equivalent to:

```python
from jasypt4py import StandardPBEStringEncryptor

cryptor = StandardPBEStringEncryptor('PBEWITHSHA256AND256BITAES-CBC')

cryptor.decrypt('pssst...don\'t tell anyone', 'xgX5+yRbKhs4zSubkAPkg9gSBkZU6XWt7csceM/3xDY=', 4000)
```