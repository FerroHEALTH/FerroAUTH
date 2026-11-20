<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# The consent rules

This page is the whole rule set for FerroSMART's consent page: who sees
it, when, and which text each rule rests on. How to configure the clients,
roles and approvals the rules read is on
[Clients, roles and consent](clients.md).

SMART App Launch 2.2.0 leaves the decision to the server: it "will enforce
access rules based on local policies and optionally direct end-user input"
(Obtain authorization code, Response). Its Best Practices tie the consent
step to apps of another party: "in 3rd-party authorization scenarios
(where the client and the resource server are not from the same
organization), it is a common requirement for authorization servers to
obtain the user's consent prior to granting the scopes requested by the
client". OpenID Connect Core 1.0 §3.1.2.4 lets the server obtain consent
through a dialogue "or by establishing consent via conditions for
processing the request or other means (for example, via previous
administrative consent)". FerroSMART uses that room so that a person sees
the page when it protects them, and never when it protects nothing.

## Policy comes first

Before any rule below, policy narrows the request. The granted scope is
never wider than the request, the client's ceiling, the roles the person
holds or the patient in context, and the approval when one answers. No
page, no approval and no remembered consent widens it.

## Who sees the page

The first rule that matches decides.

| # | When | The page | Ground |
|---|---|---|---|
| 1 | The app sends `prompt=consent` | Always shown | OpenID Connect Core 1.0 §3.1.2.1: the server "SHOULD prompt the End-User for consent" |
| 2 | A public client whose redirect URI in this request is not a claimed `https` URI (a custom scheme, or a loopback address) | Always shown, with a remembered choice ticked | RFC 8252 §8.6: no automatic processing "except when the identity of the client can be assured"; §7.2; RFC 6749 §10.2 |
| 3 | A professional, using an app the organisation approved (the organisation's own or another party's), and the approval covers every scope offered, `offline_access` included | Not shown | The approval is "previous administrative consent" (OpenID Connect Core 1.0 §3.1.2.4) |
| 4 | As row 3, and the request names `patient/` scopes | Not shown in an EHR launch; shown in a standalone launch | In an EHR launch the professional opened the app for the patient the EHR has open, so the approval covers those scopes (§3.1.2.4) |
| 5 | A patient, related person or person, using the organisation's own app (`first_party`), and the approval covers every scope offered, `offline_access` included | Not shown | §3.1.2.4; SMART Best Practices tie consent to third-party apps; the organisation processes its patients' data in its own app under GDPR Art. 9(2)(h), not on consent |
| 6 | A patient, related person or person, using an app of another party | Shown, unless rule 7 answers | SMART Best Practices: consent is the norm for third-party apps; the patient decides whether another party reads their data |
| 7 | The person ticked "Remember this choice" before, for the same client and the same resource server, and that choice covers every scope offered | Not shown | Remembering is FerroSMART's own design; a request for more scopes, or for another resource server, shows the page again |
| 8 | Anything else | Shown | SMART App Launch 2.2.0, Obtain authorization code, Response |

A `fhirUser` of type `Patient`, `RelatedPerson` or `Person` is a patient
or speaks for one (SMART App Launch 2.2.0, Scopes for requesting identity
data). Every other person who signs in is a professional for these rules.

Backend Services has no person, so it has no page: "the client is
pre-authorized by the server" (SMART App Launch 2.2.0, Backend Services,
Scopes). `prompt=none` never shows a page; FerroSMART keeps no login
session of its own, so it answers `login_required` (OpenID Connect Core
1.0 §3.1.2.1).

## Lasting access for a patient of the organisation's own app

OpenID Connect Core 1.0 §11 says "the OP MUST always obtain consent to
returning a Refresh Token that enables offline access". The same text
names "previous administrative consent" as one way to obtain consent
(§3.1.2.4), with no limit on whose consent that is. So an approval of the
organisation's own app that lists `offline_access` covers it for the
organisation's patients as well as its staff, and the patient sees no page
about it. A page about lasting access in the organisation's own app would
confuse many patients, an elderly person among them, and it would protect
nothing: the organisation already holds the data, and no other party
receives it.

What protects the patient is control afterwards. SMART lets lasting access
run "as long as the authorization server and end-user will allow"
(Scopes and Launch Context, `offline_access`), and FerroSMART's management
page, the SMART `management_endpoint`, lists every app that holds live
access, the organisation's own included. Disconnect ends that app's access
at once: its refresh tokens stop working. The organisation's approval
stays, so the next sign-in follows it again.

## What the page shows

The page lists the resource scopes (`patient/`, `user/` and extension
scopes) with a box each, ticked, which the person may untick. The sign-in,
launch and refresh scopes (`openid`, `fhirUser`, `profile`, `email`,
`launch`, `launch/patient`, `launch/encounter`, `offline_access`,
`online_access`) are fixed lines with no box. They give the app no data
the boxes do not, and SMART issues a refresh token only "if granted"
(App Launch, Refresh access token), so an app copes without one; the person
ends lasting access on the management page, where it is listed with how
long it lasts. "Remember this choice" is off unless the person remembered a
choice for the app before.

## After the decision

- Every code's audit record names its basis: `page`, `remembered`,
  `organisation` or `first-party` ([Audit records](../operate/audit.md)).
- The person sees every remembered consent and every app with live access
  on the management page, and disconnects any of them there.
- The administrator withdraws an approval at once through the
  [admin API](admin-api.md), or by removing or changing its table and
  restarting; every token issued on it is revoked.
