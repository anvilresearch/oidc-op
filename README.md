# NOTICE

We’re archiving Anvil Connect and all related packages. This code is entirely MIT Licensed. You’re free to do with it what you want. That said, we are recommending _**against**_ using it, due to the potential for security issues arising from unmaintained software. For more information, see the announcement at [anvil.io](https://anvil.io).

# OpenID Connect for Nodejs

[![Build Status](https://travis-ci.org/anvilresearch/oidc-op.svg?branch=master)](https://travis-ci.org/anvilresearch/oidc-op)
[![codecov](https://codecov.io/gh/anvilresearch/oidc-op/branch/master/graph/badge.svg)](https://codecov.io/gh/anvilresearch/oidc-op)


This library aims to implement a full-featured OpenID Connect Provider for
Nodejs. It is not intended to be used directly by most developers, but rather
via a complete self-contained server such as Anvil Connect. Some applications
require an embedded identity provider, such as entertainment or IoT appliances.
This package can be used directly in these cases.

The module should make available an OIDCProvider class which can be
instantiated multiple times to support multitenancy use cases. It should also
have a method that provides a mountable router or app for widely used frameworks
like Express.

## Scope

- Core
- Discovery
- Dynamic Registration
- OAuth 2.0 Multiple Response Types
- OAuth 2.0 Form Post Response Types
- Session Management
- Front-Channel Logout
- Back-Channel Logout
- OAuth 2.0 Client Credentials Grant
- Proof Key for Code Exchange by OAuth Clients (PKCE)
- Authorization Cross Domain Code (ACDC)

## Dependencies

This package is a work in progress, dependent on other ongoing projects. Code
contained herein will be completed when the following dependencies are ready to
release:

- [anvilresearch/jose](https://github.com/anvilresearch/jose)
- [anvilresearch/webcrypto](https://github.com/anvilresearch/webcrypto)
- [anvilresearch/json-document](https://github.com/anvilresearch/json-document)

## Tentative Scope

- Account Chooser 1.0
- Native Applications Agent Core 1.0
- Native Applications API Bindings 1.0

## Out of Scope

- Local Authentication
- Persistence

## Internal Interface

OpenID Connect makes no provisions for how a user is initially authenticated
by the IdP. It's up to the implementer to determine whether to use passwords,
LDAP, SAML, OAuth, or some other means. The host system is responsible for
other dependencies of the OIDC authentication flows as well, such as
persistence, managing user attributes, multi-factor auth and so on.

In addition to implementing OpenID Connect Provider functions, this library
defines an interface between OpenID Connect and the host application.

The goal of the interface is to manage the flow of responsibility between the
OpenID Connect implementation and functions provided by the host application,
such as local user authentication, persistence, and domain specific event
handing.

## MIT License

Copyright (c) 2016 [Anvil Research, Inc.](http://anvil.io)
