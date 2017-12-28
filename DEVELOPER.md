# Jasypt for Python Developer Notes

### Testing

Run the unit tests using the python built in unittest runner:

```sh
python -m unittest discover
```

or use nose testing:

```sh
python setup.py nosetests
```

### Build and Release

This project uses the standard python setup mechanism. To build a distributable package simply use:

```sh
python setup.py sdist --formats=gztar bdist_wheel
```

Optionally sign the artifacts:

```sh
for f in dist/*.{gz,whl}; do 
  gpg --detach-sign -a $f
done
```

Uploading to pypi only works with a Cpython interpreter and also requires twine. Also make sure you have a valid `~/.pypirc` configuration file. This example should work:

```ini
[distutils]
index-servers =
  pypi
  pypitest

[pypi]
username:[your-username]
password:[your-password]

[pypitest]
repository: https://test.pypi.org/legacy/
username:[your-username]
password:[your-password]
```

And upload all resources:

```sh
pip install -U twine
twine upload -r pypitest dist/*
```