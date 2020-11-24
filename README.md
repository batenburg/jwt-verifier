# JWT Verifier

This JWT Verifier is for Symfony and Laravel. Right now this package is in it is firs testing version.

Build Status: [![Build Status](https://travis-ci.org/batenburg/jwt-verifier.svg?branch=master)](https://travis-ci.org/batenburg/response-factroy-bundle.svg?branch=master)

Code coverage: [![Coverage Status](https://coveralls.io/repos/github/batenburg/jwt-verifier/badge.svg?branch=master)](https://coveralls.io/github/batenburg/response-factroy-bundle?branch=master)

## Future improvements

This package can be used with both Symfony as Laravel. For both frameworks you need to set up dependency injection.
1. Have a separate packages for Symfony and Laravel which use this packages.
2. Have a request in this package, so we do need require the Symfony request anymore as a dependency.
3. Add multiple adaptors to the package, so we can support more Packages.
