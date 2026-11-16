
Releases beside `ferrohealth-smart` 0.28.0, whose `resource::Caller`,
`client::cache::TokenSource` and `config::endpoint::RetrySection` this
crate carries in its public API.

### Changed

- Breaking: requires `ferrohealth-smart` 0.28.0 (caret `0.28.0`) in place of
  `0.27.0`. Upgrade: move `ferrohealth-smart` to 0.28.0 with this crate, so
  one copy links (#529).


### Support period

Only the newest release is supported: there are no maintenance branches, no long-term-support line and no backports, and upgrading is free. Under the Cyber Resilience Act, Cadasto B.V. commits to keep publishing security fixes for at least five years after each release (Art 13(8)) and ships them only in the newest release (Art 13(10)). For this release that commitment runs until the end of November 2031 (Regulation (EU) 2024/2847 Art 13(19)); see [SECURITY.md](https://github.com/FerroHEALTH/FerroAUTH/blob/main/SECURITY.md#supported-versions).
