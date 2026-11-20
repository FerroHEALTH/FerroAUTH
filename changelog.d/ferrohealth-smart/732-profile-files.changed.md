- Breaking: a profile loads from a file a deployment supplies, and the
  compiled presets are the standards-only one and the vendors' (`rfc9068`,
  `keycloak`, `entra`, `okta`, `ferrosmart`). An issuer table names its preset
  as `preset` (in place of `profile`), may name a `profile_file` in the form
  of a preset file (`profile::ProfileFile`: profile keys, `kind`, a
  `[federation]` table), and sets profile keys in its
  `[auth.issuer.<name>.profile]` table, which win over the file, which wins
  over the preset. The 31 profile keys that sat on the issuer table itself
  are removed from it (`IssuerEntry::profile` is now that table and
  `IssuerEntry::profile_keys` is removed), and the onward table follows:
  `[<lane>.credentials.onward]` takes `preset`, `profile_file` and a
  `profile` table in place of `profile` and `keys`. `Profile::with_keys`
  sets keys over a resolved profile. A product moves `profile = "…"` to
  `preset = "…"` and every profile key under the issuer's `profile` table.
