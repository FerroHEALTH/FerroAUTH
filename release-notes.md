
### Changed

- Breaking: the `aud` and `typ` of a `private_key_jwt` client assertion
  follow the grant's security profile and are never configured: the token
  endpoint under `typ` `JWT` (SMART App Launch 2.2.0, Client
  Authentication: Asymmetric), and under `security_profile = "fapi2"` the
  issuer identifier as a string under `client-authentication+jwt` (FAPI 2.0
  §5.3.3.1, RFC 10070 §4). RFC 10070 §4 has every client name the issuer;
  SMART 2.2 governs a SMART client, so the plain grant keeps the token
  endpoint, a deviation recorded in `docs/architecture.md` §3.5 and
  reported in #528. `client::AssertionAudience`, the
  `ClientCredentials::assertion_audience` field and
  `client::fapi2::Fapi2Error::AssertionAudience` are removed;
  `client::CLIENT_AUTHENTICATION_TYP` is new. `AssertionKey::assertion`
  takes the audience and the `typ` (`assertion(client_id, audience, typ)`).
  Upgrade: delete `assertion_audience` from every
  `[<lane>.credentials.oauth]` table; a grant that needs the issuer as
  `aud` sets `security_profile = "fapi2"` (#529).

### Removed

- The `assertion_audience` key of `[<lane>.credentials.oauth]`. This
  release refuses it with `ConfigError::Removed`, naming what replaced it;
  the next release deletes the refusal (#529).


### Support period

Only the newest release is supported: there are no maintenance branches, no long-term-support line and no backports, and upgrading is free. Under the Cyber Resilience Act, Cadasto B.V. commits to keep publishing security fixes for at least five years after each release (Art 13(8)) and ships them only in the newest release (Art 13(10)). For this release that commitment runs until the end of November 2031 (Regulation (EU) 2024/2847 Art 13(19)); see [SECURITY.md](https://github.com/FerroHEALTH/FerroAUTH/blob/main/SECURITY.md#supported-versions).
