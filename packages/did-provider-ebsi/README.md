# Veramo did:ebsi provider

This package contains an implementation of `AbstractIdentifierProvider` for the `did:ebsi` method ([specs](https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method)).
This enables creation, onboarding and control of `did:ebsi` entities.

> Note: for running successful onboarding tests, one should export env variable `export EBSI_BEARER="ey..."`  before running tests. Bearer token can be fetched [here (onboard with CAPTCHA)](https://app-pilot.ebsi.eu/users-onboarding/v2).