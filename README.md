# Pyonic
A Python SDK for the Ion Channel API 

### Documentation
Link: https://pyonic.readthedocs.io/en/latest/

### Testing

Testing is enabled for the Pyonic SDK via Pytest

To execute tests ensure that both authentication environment variables 'IONUSER' and 'IONPASSWORD' are set 

This can be done by executing:

```bash
export IONUSER='SomeUser' export IONPASSWORD='SomePassword'
```

1.) Enter a directory where a file is located for specific testing - /Testing/Analyses_test

2.) Run Generalized Testing for all tests by executing ```bash pytest``` - will recursively check directories and file trees for test files and execute them


[![Black](https://github.com/ion-channel/Pyonic/actions/workflows/black.yml/badge.svg)](https://github.com/ion-channel/Pyonic/actions/workflows/black.yml)
