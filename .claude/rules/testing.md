<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Testing discipline

Test discipline is non-negotiable (a standing hard rule; see `CLAUDE.md`). It
applies to every crate.

## The hard rule

- **Never** silently weaken, skip, or delete an existing test to make a build
  pass.
- **Never** edit a test to route around a bug it exposes. If a test fails and
  the fix is unclear, leave it failing and record a `// TODO(#NNNN):` naming
  its issue.
- A conformance test asserts the specification: cite the section it encodes
  (SMART App Launch, the RFC, OpenID Connect Discovery), and never adjust an
  expectation to match a defect. The status and challenge strings the
  products' own tests pin today are the contract the library meets; a
  difference between a product's pinned behaviour and the design is settled
  on the tracker, never by editing the test.

## Tooling

- **Runner:** `cargo-nextest` (`cargo nextest run --workspace`, with and
  without `--all-features`).
- **Upstreams:** every authorization server, key set location, token
  endpoint and upstream resource server is a `wiremock` stub. No test reaches
  the network.
- **Keys:** every signing key is generated when the case runs
  (`aws-lc-rs`), in memory, and the public half is published through the
  stub. No key, token, secret or password, real or synthetic, is committed.
- **The audit line** is read back through a test `tracing::Subscriber` that
  keeps the events under `ferrohealth_smart::audit`, so a case asserts the
  field set byte for byte and the absence of every forbidden value.

## Coverage is a mandate, not just pass rate

The bar is `docs/architecture.md` §10, every rule a test before a product
moves:

- every check of the token validation as its own refusal with its own test,
  for a token minted under each default algorithm, with the `none` and HMAC
  refusals pinned as asserted negative tests;
- the key set: `use`, `key_ops`, `alg` and `kty` filtering, the `kid`
  match, the ambiguous no-`kid` case, the unknown-`kid` refetch and its
  interval, the max-age refetch, the failed read answering `503`;
- the scopes: the grammar, the v1 mapping, the out-of-order and unknown
  cases, the wildcard, the patient compartment, the union rule, the granular
  constraint without an evaluator;
- Basic: the colon and control-character rules, the UTF-8 decoding, the
  decoy, the scopes a user carries;
- the client credentials client: the three authentication methods, the
  assertion's claims and lifetime, the cache and its margin, the shared
  fetch, the one renewal on a `401`, the RFC 6749 §5.2 error body;
- the error model: every status and challenge string of §3.7.
- **Coverage only ratchets up.** Cases are added, never removed to go green.
- **One behaviour per case.**

## Where tests live

Unit tests live beside the code they test (`#[cfg(test)] mod tests`); a test
that drives the public API lives in the crate's one integration binary,
`tests/it/main.rs` plus one `mod` per topic. Dedicated test files under `src/`
are banned.

## Test shapes

- `Result`-returning tests where plumbing can fail; assertions carry a
  message where the values alone do not say what failed.
- Doctests are copy-paste templates, never `ignore`; `no_run` for an
  example that would open a socket.

## No patient data, no credential, ever

Every claim, subject, client id, password and scope the tests show is
invented for them, and every key is generated when the case runs.
