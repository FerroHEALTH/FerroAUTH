<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog

All notable changes to FerroSMART are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The `ferrosmart` server: `serve`, `config check` and `healthcheck` on the
  family's stack, the `[ferrosmart]` configuration with its issuer and
  `RS256` signing key ring (current, previous and next key), the RFC 8414
  metadata, the SMART configuration and the JWK Set (#514).
- The PostgreSQL store with its embedded migrations, run under the
  advisory lock of `sqlx` at start, and its readiness indicator; the client
  registry of `[[ferrosmart.client]]` tables, each checked against SMART's
  registration rules (a JWK Set by URL or by value, with `kty`, `kid` and
  bare public members) and written to the store at every start (#514).
