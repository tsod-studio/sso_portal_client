# django-sso-portal-client — implementation plan

Status: implementing (2026-07-15)

## Goal

A reusable Django app (`sso_portal_client`, distribution name
`django-sso-portal-client`) that any Django relying party installs to get
SSO-portal login with **automatic group mapping onto standard
`django.contrib.auth.models.Group`** — plus a Django version of the
SampleStore demo RP living in this repo as `example_project/`, wired
against a local `sso_portal` dev server.

Design contract (mirrors `sso_portal`'s `docs/app-integration-guide.md` §7):
the portal decides *who may sign in* (app_access plugin); the RP receives
`groups` (list[str]) / `role` (str) OIDC claims and derives everything else
locally. This package implements the RP half once, properly:

- **groups claim → Django Groups** (created on demand, membership synced on
  every login, overwrite-not-append so removals propagate)
- **permissions**: none invented — RPs attach standard Django permissions to
  the synced Groups; membership sync then grants/revokes them automatically.
  This is the "自動給予群組對應的權限" story, using nothing but Django's own
  permission machinery.

## Repo layout

```
pyproject.toml            # uv-managed; hatchling; dist django-sso-portal-client
sso_portal_client/        # the reusable app (flat layout)
  __init__.py apps.py conf.py sync.py receivers.py views.py urls.py
  models.py migrations/   # only if the sid-session mapping lands (see below)
tests/                    # pytest-django; settings in tests/settings.py
example_project/          # "SampleStore (Django)" demo RP — see below
docs/implementation-plan.md
README.md                 # package docs: install, settings, permission recipe
Makefile                  # test / lint / format targets (ruff + pytest)
.gitignore
```

Versions: Django >= 6.0, django-allauth >= 65.15 (same floor as sso_portal),
Python >= 3.12. Dev deps: pytest, pytest-django, ruff.

## Core design

### OIDC client: allauth `openid_connect`

We do NOT hand-roll the OIDC flow. The package depends on django-allauth's
`openid_connect` provider (discovery, PKCE S256, state/nonce handled by a
maintained library — the portal enforces PKCE). The package ships:

- `sso_portal_client.conf.get_settings()` — validated access to a single
  `SSO_PORTAL_CLIENT` settings dict:

  ```python
  SSO_PORTAL_CLIENT = {
      'SERVER_URL': 'http://127.0.0.1:8000/o',   # issuer; discovery derived
      'CLIENT_ID': ..., 'CLIENT_SECRET': ...,     # from env in real RPs
      'GROUP_PREFIX': None,   # None => manage ALL group memberships;
                              # 'samplestore-' => manage only that namespace
      'STAFF_GROUPS': [],     # claim groups granting is_staff (empty = never touch)
      'SUPERUSER_GROUPS': [], # same for is_superuser (empty = never touch)
  }
  ```

- `sso_portal_client.provider_config()` — returns the
  `SOCIALACCOUNT_PROVIDERS['openid_connect']` dict (one APP entry, id
  `sso_portal`, PKCE on) so an RP's settings stay to ~5 lines.

### Group sync (the heart — standard Django Group only)

`sso_portal_client.sync.sync_user_groups(user, claims)` — pure function,
unit-testable without a live portal:

- `claim_groups = [g for g in claims.get('groups', []) if g]`
- `GROUP_PREFIX is None` (default): SSO is the sole authority —
  `user.groups.set([Group.objects.get_or_create(name=g)[0] for g in claim_groups])`
- `GROUP_PREFIX = 'x-'`: manage only the namespace — add prefix-matching
  claim groups (get_or_create), remove the user's other `x-*` memberships,
  leave non-prefix local groups AND non-prefix claim groups untouched.
- `STAFF_GROUPS` / `SUPERUSER_GROUPS` non-empty → set the boolean from the
  intersection (both grant and revoke); empty list → never touch the flag.
- No role model, no profile — group-centric by design. `role` claim is
  ignored by the package (RPs that want it can hook the same signal).

Hook point: a receiver on `allauth.account.signals.user_logged_in` filtered
to `sociallogin` from our provider id, syncing from the claims allauth
persisted for the login (`sociallogin.account.extra_data`, plus id_token
claims if allauth exposes them for openid_connect — verify empirically which
of extra_data/userinfo carries `groups` from the portal and test against a
recorded claim fixture). Also fire on `social_account_added` (first login).
The receiver must be connected in `AppConfig.ready()`.

Package also emits its own signal `sso_portal_client.signals.claims_synced`
(kwargs: user, claims) after sync, so RPs can hang custom mapping (e.g.
role) without us inventing models.

### Back-channel logout + session ping (best-effort, time-boxed)

Wanted for parity with the Flask sample (portal's store-switch fans out
logout by `sid`), but gated on one empirical question: **can we obtain the
id_token's `sid` claim through allauth's public extension points?**
(`sid` is only trustworthy from the id_token; the portal's userinfo cannot
carry a correct one.)

- If yes (token response's id_token reachable via provider subclass /
  adapter hook): model `PortalSession(sid, session_key, user)` written at
  login; `POST /sso/backchannel-logout/` verifies the logout_token
  (signature via portal jwks, iss, aud, events claim present, nonce absent
  — same checks as `examples/sample_rp/app.py` in the sso_portal repo) and
  deletes matching Django sessions; `GET /sso/session-ping/` returns
  read-only 200/401 (MUST NOT touch/extend the session — see the Flask
  sample's docstring for why).
- If it needs forking allauth internals: SKIP, leave `urls.py` shipping only
  session-ping (which works keyed on the Django session alone, without sid),
  and document the limitation + the Flask sample as the reference for full
  switch integration. Do not burn the schedule here; group sync is the
  product.

### URLs

`path('sso/', include('sso_portal_client.urls'))` → whatever of
backchannel-logout / session-ping lands per the above.

## example_project/ — SampleStore (Django)

Minimal but real Django project proving "RP 只要引入就自動有":

- `config/` settings: SQLite, `SSO_PORTAL_CLIENT` from env with dev
  defaults (`SERVER_URL=http://127.0.0.1:8000/o`, client id
  `samplestore-django`), `GROUP_PREFIX=None`, `STAFF_GROUPS=['samplestore-admin']`.
  Runs on **localhost:9002** (Flask sample owns 9001; distinct host:port =
  distinct session cookie scope on one dev box).
- `store/` app:
  - `/` — login state, the user's synced `user.groups` list, links.
  - `/admin-area/` — gated with plain Django authorization:
    `@permission_required('store.view_admin_area')`. A data migration
    creates the custom permission and attaches it to the
    `samplestore-admin` Group (get_or_create) — THE demo that group
    membership arriving from SSO automatically confers a normal Django
    permission. No custom decorators, no claim inspection in views.
  - Templates extend one small base; keep dependencies to Django only.
- Login link goes straight to the provider (allauth
  `provider_login_url`-equivalent for openid_connect id `sso_portal`,
  `process=login`); `ACCOUNT_ALLOW_REGISTRATION` closed, no local signup UI.
- README section: register the RP on the portal — copy-paste
  `manage.py shell` snippet creating the OAuth2 Application
  (client_id `samplestore-django`, redirect
  `http://localhost:9002/accounts/oidc/sso_portal/login/callback/` — use
  the exact callback path allauth generates, verify at implementation
  time) — plus `setup_app_access_demo` note: alice (users+admin) sees
  admin-area; bob (users) doesn't; carol is blocked at the portal.

## Phases & agents

- **Phase A (agent, default model)** — package core: pyproject/uv scaffold,
  conf, sync (+ its exhaustive unit tests: full vs prefix scope, staff/
  superuser grant+revoke, get_or_create, idempotence), receivers wired to
  allauth signals with an integration-style test faking a sociallogin,
  provider_config(), best-effort backchannel/session-ping per the decision
  rule above, README, Makefile, ruff+pytest green.
- **Phase B (agent, opus)** — example_project SampleStore per the spec
  above + its tests (view gating via permission, data migration behavior)
  + README run-book; must not modify package code except version-pinning
  discoveries reported back.
- **Phase C (me)** — integration: full test run, boot portal + example RP,
  register the OAuth2 app, real-browser E2E (alice sees admin-area, bob
  403, carol blocked at portal), git initial commit(s).

## Non-goals (v1)

- No PyPI publishing (installed via path/git dependency).
- No role/profile models; `role` claim intentionally unmapped (signal
  provided instead).
- No switch-widget JS bundling — RPs load it from the portal as documented
  in app-integration-guide (the Django sample may include the two script
  tags if trivially cheap, else skip).
