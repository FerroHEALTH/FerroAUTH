- The authorization endpoint meets what OpenID Connect Core 1.0 §15.1
  has every OpenID Provider implement, beside SMART App Launch 2.2.0's
  PKCE and `aud`, which stay required. `prompt=none` answers
  `login_required` with no page, and `none` beside another value is
  `invalid_request`. `prompt=login` and `select_account` reach the upstream
  login, and `prompt=consent` shows the consent page where a remembered
  consent or an organisation approval would answer. `max_age` reaches the
  upstream login: a login older than it, or one that names no
  `auth_time`, is begun again once with `prompt=login`, and one still
  older answers `login_required`. The ID Token's `auth_time` is the
  upstream login's. `ui_locales` reaches the upstream login and chooses
  the pages' language before `Accept-Language`. `display`,
  `claims_locales` and `acr_values` are taken. The OpenID Connect
  discovery document names `display_values_supported` and
  `ui_locales_supported` (#662).
