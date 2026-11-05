<!-- This file describes vendored third-party material; the bytes beside it
     keep their upstream licence, not the licence of this repository. -->

# Provenance: the Keycloak documentation

Vendored verbatim by `scripts/vendor/keycloak-docs.sh`. Never edit a file
here: change the pin in docs/VERSIONS.md and re-run the script.

- Source: <https://github.com/keycloak/keycloak>, rendered as the Keycloak 26.8.2
  guides at <https://www.keycloak.org/documentation>
- Pin: tag `26.8.2`, which resolves to commit `e514445f9dcdabc5bdcf67cab56c1e49655de067` (2026-11-05T15:27:24Z)
- Fetched: 2026-11-05, each file from raw.githubusercontent.com at the commit
  and checked against the git blob id the commit records
- Upstream licence: the repository's `LICENSE.txt`, the Apache License,
  Version 2.0, January 2004, vendored beside this file. Its §4 permits
  reproducing and distributing copies of the work in any medium, with a
  copy of the licence given to every recipient. The files are unmodified.
- Layout: the upstream paths, unchanged
- Files: 41
- Tree digest (sha256 over the sorted per-file `sha256  path` listing,
  `PROVENANCE.md` excluded): `0a21c4c27d4d40cad6ead9e3a3272c698ca5c2d324fad3dfb70e912e1acfa23f`
- Read by: the `keycloak` issuer profile of #215, the token exchange
  grant of #217 and the live Keycloak case of #239, vendored by #222 and #239

## What is taken

- `docs/guides/securing-apps/token-exchange.adoc`: "Configuring and using
  token exchange", the standard (V2) and legacy (V1) exchange, delegation
  and the limitation that "{project_name} Token exchange does not yet have
  support for the `resource` parameter". In Keycloak 26 the chapter lives
  in the securing applications guide, not the server administration guide.
- `docs/guides/templates/features.adoc`: the `techpreview` and
  `techpreviewdeprecated` macros, whose text ("is *Preview* and is not
  fully supported") the token exchange chapter's preview notices render.
- `docs/documentation/server_admin/topics/clients/oidc/proc-using-a-service-account.adoc`: "Using a
  service account".
- `docs/documentation/server_admin/topics/admin-cli.adoc`: the admin CLI chapter, whose section "Adding
  or removing roles for client's service account" states that "A
  client's service account is a user account with username
  `service-account-CLIENT_ID`".
- `docs/documentation/server_admin/topics/clients/con-protocol-mappers.adoc` and
  `docs/documentation/server_admin/topics/clients/proc-creating-mappers.adoc`: "OIDC token and SAML
  assertion mappings" and creating protocol mappers, with the impersonator
  mappers.
- `docs/documentation/server_admin/topics/identity-broker.adoc` and `docs/documentation/server_admin/topics/identity-broker/`:
  "Integrating identity providers", whole.
- `docs/documentation/server_admin/topics/clients/oidc/con-audience.adoc`: "Audience support", the
  audience mapper a client's access tokens carry `aud` by.
- `docs/guides/server/containers.adoc`: "Running Keycloak in a
  container", whose section "Trying Keycloak in development mode" runs the
  image with `start-dev` and the `KC_BOOTSTRAP_ADMIN_USERNAME` and
  `KC_BOOTSTRAP_ADMIN_PASSWORD` variables.
- `services/src/main/java/org/keycloak/protocol/oidc/mappers/AudienceProtocolMapper.java` and
  `services/src/main/java/org/keycloak/protocol/oidc/mappers/OIDCAttributeMapperHelper.java`: the audience mapper's
  provider id (`PROVIDER_ID = "oidc-audience-mapper"`), its
  `included.custom.audience` key and the `access.token.claim` key, which
  no guide states. The source files carry the same Apache License 2.0
  header.

The guides' images, and the other chapters the `include::` lines of an
index name, are not taken.

| File | sha256 | git blob id |
|---|---|---|
| `LICENSE.txt` | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` | `d645695673349e3947e8e5ae42332d0ac3164cd7` |
| `docs/documentation/server_admin/topics/admin-cli.adoc` | `2443b1a18cf8ac9ff81062ba875fb854a69c0cc0cea6351d057d15fb16afa483` | `a698a8246357d1cbc48c4d7138dcdd1c6e78b8a6` |
| `docs/documentation/server_admin/topics/clients/con-protocol-mappers.adoc` | `edb5a5ca0dcc2ff44a386a46420733a7f103f586efdc71bba46e8ea4a6dddcc2` | `ec681ceb05970357fed5af538209dbdad851f7a1` |
| `docs/documentation/server_admin/topics/clients/oidc/con-audience.adoc` | `ff9f6c0adf79a2b16f94daac4596f1ed0aa67bae1bf4da6e55703df818882225` | `dfdb6995fc93b73d42ea899e5ab8d77b1a7140d2` |
| `docs/documentation/server_admin/topics/clients/oidc/proc-using-a-service-account.adoc` | `0ab4e3d6fc78b640abdfd8086af1e791d4ed89750a84211bd06ee8e7b24709ed` | `6852d9fb3efd0bafc0234c0718b4d65d07db2157` |
| `docs/documentation/server_admin/topics/clients/proc-creating-mappers.adoc` | `dea2fd0deb49fc2d350eff27676f03d0fed8954b592c52ab907bfc64ef99f216` | `81766dbe777bc25e2b042e6a92b7986349d78544` |
| `docs/documentation/server_admin/topics/identity-broker.adoc` | `f2596b2638ff35ae8987d3ede01b9b51742c62d640a8f820c2c3a1163c2f9b0f` | `45c0b18049d5920d4327614b5534d2ee34fce30c` |
| `docs/documentation/server_admin/topics/identity-broker/client-initiated-account-linking.adoc` | `f1f026de516e7b7721484b8783697291bd1cef029e9762b68e4c248e631edecb` | `90b3fbee4645ae96f53e37bb2a0b2d43f99570ba` |
| `docs/documentation/server_admin/topics/identity-broker/configuration.adoc` | `8b8492d1a1d49198b1a1a089e3fbb63eeadf0eb38c1b2ac4f2e3201a2ff591c1` | `d49855eeb67ac50957708e90c769dd833a76d31f` |
| `docs/documentation/server_admin/topics/identity-broker/default-provider.adoc` | `7f9fc2f8f841ef442bf77d72ed78469412228a5379ce5a1079ea56c159b5b45f` | `652e938b987e4feb36b9b857fd25582567b66e64` |
| `docs/documentation/server_admin/topics/identity-broker/first-login-flow.adoc` | `1e7d08c9e4d1373b92f3cf8eae1d087760fb0603b6d2411caa30d72d18fd6c3a` | `e7619f74824fee1edaeaf1c92b104bed48460127` |
| `docs/documentation/server_admin/topics/identity-broker/kubernetes.adoc` | `81fc19aefff296b06e7fb7965dad7ed7a97fac85207ddde982602b0f547516d0` | `14f94e5f4bae343bc4f60f224bd6d222eef0048d` |
| `docs/documentation/server_admin/topics/identity-broker/logout.adoc` | `42e88f67b31d6cd7261dc062d15449f5fcead8bb4479c54fb926e3fae4b7969e` | `a630f680577650128ba232a406c900eb7ec2e7dd` |
| `docs/documentation/server_admin/topics/identity-broker/mappers.adoc` | `dc40786affd3dad049a6ab116317ad5dcbd536db3a4a5791e827874ede9247e9` | `e85d4f7be02a5abecabaf31a83054918776c8185` |
| `docs/documentation/server_admin/topics/identity-broker/oauth2.adoc` | `b05540eba4a4a0c391993527b0c6e2859e00b8f385bb2cc7478b455f657bc370` | `05b63dc24322b17b5821f7ce983e0b962b193982` |
| `docs/documentation/server_admin/topics/identity-broker/oidc.adoc` | `54e003e2396f2aa5d177d71db5b440bdeff4cce46bdda2c7f0dbc4658d9aef7c` | `8bdf4e10dfd770aeab00b5acb4edb920b929d06b` |
| `docs/documentation/server_admin/topics/identity-broker/overview.adoc` | `3aacdef256bbd82cc9964512a6353cc1f97541299b2e6e02e543246e3dc56356` | `1ec4ba48258053fe4602d76681cf0023aee65606` |
| `docs/documentation/server_admin/topics/identity-broker/post-login-flow.adoc` | `9100ea4dd5fb637cf850934c78dd7d839c0d4efae3cc4902312cb762c27ed730` | `171bd1fa527cda70f3f2aee28670cca23e89c871` |
| `docs/documentation/server_admin/topics/identity-broker/saml.adoc` | `74d027736077bee4ba103c7ba3a476a3a016347ea1aa8bda2262e8189efe97f2` | `c5c41008a0b88ce9a18ffd725397def874da25f0` |
| `docs/documentation/server_admin/topics/identity-broker/session-data.adoc` | `a9115b87ed592bc764f24b9d0ff2f8c7273c0d867df1333be716ec64a10b50ab` | `2e352bb950e463f62c4558d9907fd22c2dabeb0e` |
| `docs/documentation/server_admin/topics/identity-broker/social-login.adoc` | `1cdde0f9bc6cf4f8de42577c1e6ada16fe8e6bf56f20b24091da1f630000b448` | `521241c26541a5a0da8d41049642cb62cca9bc94` |
| `docs/documentation/server_admin/topics/identity-broker/social/bitbucket.adoc` | `1bb831785565ba908c0477e3413cc838c65af4368c66a39beb201cd0fe892999` | `1116752825119a8f23f8d61ef1c1ac7cf6b2e6e7` |
| `docs/documentation/server_admin/topics/identity-broker/social/facebook.adoc` | `3a67082b99343e0f694dc4eed40d02e7baa13b42b8fbc816894a7f998d3582b8` | `2b68db858b910e695012309855842952aba1ffe1` |
| `docs/documentation/server_admin/topics/identity-broker/social/github.adoc` | `5d45d249d3f50add0407d00c86bff77f41ab1bf1f45e8852d2e0c4d457e22f03` | `8baa068ab0433c8388989ab5aa48f2ce6515f57b` |
| `docs/documentation/server_admin/topics/identity-broker/social/gitlab.adoc` | `feac47da538aecd494874f481b8347caf0611a0da47a523352a02c6aa894b196` | `57bb0fe3bbc9e97e4068d49a8e23fc3a05bb1db2` |
| `docs/documentation/server_admin/topics/identity-broker/social/google.adoc` | `d2919eb1ded7f6354d7c35e7b88d92cbc66dacc018aabecb7c16563fc6542332` | `630902caa340b838875f2738ed3a09c0fe255140` |
| `docs/documentation/server_admin/topics/identity-broker/social/instagram.adoc` | `c2cdb193faee7638ebaf134d80bc72b16b39a7e502fb92b4943865952d18f2e5` | `ab21a32cb94a955cae9a2e6385b21635d2082306` |
| `docs/documentation/server_admin/topics/identity-broker/social/linked-in.adoc` | `1665b182129466e668df21f0562eb0ad2e17f443dace3b98264ff7f68719d31e` | `5ac8e793b43be9af4687b652f19758353fa53ec0` |
| `docs/documentation/server_admin/topics/identity-broker/social/microsoft.adoc` | `1d205623787a6b555932e4adf5c43f05e11270d11cc93874acddf148611e97b2` | `6317cd2b57ef1d56fca7c617a883a29ac90c773c` |
| `docs/documentation/server_admin/topics/identity-broker/social/openshift.adoc` | `b98c3d4aedff32b0397ccfa6e4458c88da28e6beeca5cb72c2fc87702e95405d` | `37114423f737026534ee9bc62b2b70deda55ab30` |
| `docs/documentation/server_admin/topics/identity-broker/social/paypal.adoc` | `d3ac2d103949624cef6db7468533852093e86e2a1e5fa293aec02a80964f1437` | `d20a5066bb943e483b807353aca3daa3f7ee9d22` |
| `docs/documentation/server_admin/topics/identity-broker/social/stack-overflow.adoc` | `068a327f2fff677e11ae95fca470d22895d3834f524957d8edd63a84fc0ebedf` | `707aed95aa891258babe467036ca0941096d6a48` |
| `docs/documentation/server_admin/topics/identity-broker/social/twitter.adoc` | `f8e033e24db60030f7fc12991b3ee826f463912b68fc8f5d08825dc6fe4397f4` | `60a2569fcfefb1b54a07effc4b069f36f5ff380b` |
| `docs/documentation/server_admin/topics/identity-broker/spiffe.adoc` | `8891801ec1a324697c7d73068b6ebc509b48d8613d542445e18f1b688a4516fb` | `cb89eb8f59507d4778ebad4e5cb3d7da113fe674` |
| `docs/documentation/server_admin/topics/identity-broker/suggested.adoc` | `430a657dd585dd18df658d812805004068257626e379bd4beb976c8299783113` | `74bf35226645a23f7d5d19b9b13b1aa9cc2bc92c` |
| `docs/documentation/server_admin/topics/identity-broker/tokens.adoc` | `2ece6b41b216450282d991d6322bb7aee6a5e29347649dc8ab2da5b8af562b74` | `99be93b8fb8be5907ee3fa42bb2695817ddcdd78` |
| `docs/guides/securing-apps/token-exchange.adoc` | `99d6d660675f2d4d35cbdc0825ffab7f5aeeb39d970c580340b1d472a72d7afa` | `8b6b4f866dbfe084d062723687eadd2ec71e5abe` |
| `docs/guides/server/containers.adoc` | `2c9fa7ff5e2017b5ea316248bdf3bacee792178ab463de7fc0feee1aa81a9699` | `daccd5b809cf9c1826e3172cbe6bf52ef33e3825` |
| `docs/guides/templates/features.adoc` | `46d92510c4e2cafc8780518f1932784d29359a1c8088a8b643bc63c044d0dc03` | `9a6a96620d13ee8a9ba715240f3607e02e1e1576` |
| `services/src/main/java/org/keycloak/protocol/oidc/mappers/AudienceProtocolMapper.java` | `706653e426b063601795c1047e6b0f61cf04f378da24569fbb6ab6ff2c25341a` | `64d67834343c5726a630c708d6594664b0a776fd` |
| `services/src/main/java/org/keycloak/protocol/oidc/mappers/OIDCAttributeMapperHelper.java` | `bd4be995ef4a84026472aa33dea151eba444cd9af68011a5a2165e07805c9b52` | `06af33df0a1a31b4727761d53e8b1fbae6da4f88` |
