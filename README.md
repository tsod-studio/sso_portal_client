# django-sso-portal-client

Reusable Django app for relying parties (RPs) of the SSO portal. Install it
and every portal login automatically maps the portal's `groups` OIDC claim
onto standard `django.contrib.auth.models.Group` memberships — created on
demand, **overwritten (not appended) on every login** so removals on the
portal propagate to your app. Attach ordinary Django permissions to those
groups and access control follows portal group membership with zero custom
code.

Built on django-allauth's `openid_connect` provider (discovery, PKCE S256,
state/nonce handled by allauth — the portal requires PKCE).

- Python >= 3.12, Django >= 6.0, django-allauth >= 65.15

## Install

Not published to PyPI — install from a path or git dependency:

```bash
uv add /path/to/sso_portal_client
# or
uv add git+https://github.com/<you>/sso_portal_client
```

## Settings (the whole integration)

```python
INSTALLED_APPS = [
    # ...
    'django.contrib.sessions',          # DB sessions required for back-channel logout
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.openid_connect',
    'sso_portal_client',
]

MIDDLEWARE = [
    # ... Django defaults ...
    'allauth.account.middleware.AccountMiddleware',
]

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]

# The 5 lines that matter:
from sso_portal_client import provider_config

SSO_PORTAL_CLIENT = {
    'SERVER_URL': 'http://127.0.0.1:8000/o',       # portal issuer; discovery derived
    'CLIENT_ID': env('SSO_CLIENT_ID'),
    'CLIENT_SECRET': env('SSO_CLIENT_SECRET'),
}
SOCIALACCOUNT_PROVIDERS = {'openid_connect': provider_config()}
```

`SERVER_URL` is the issuer base URL (allauth appends
`/.well-known/openid-configuration` itself); a full discovery URL also
works. `CLIENT_ID`/`CLIENT_SECRET` come from the OAuth2 Application you
register on the portal's dashboard, with redirect URI
`https://<your-app>/accounts/oidc/sso_portal/login/callback/`.

URLs:

```python
urlpatterns = [
    path('accounts/', include('allauth.urls')),
    path('sso/', include('sso_portal_client.urls')),   # backchannel-logout + session-ping + logout
]
```

Then `python manage.py migrate` (one small table for logout session
tracking, see below).

## The permission recipe (the headline feature)

You never inspect claims in views. Attach standard Django permissions to
the groups the portal syncs, and membership sync grants/revokes them
automatically on every login:

```python
# e.g. in a data migration, once:
group, _ = Group.objects.get_or_create(name='samplestore-admin')
permission = Permission.objects.get(codename='view_admin_area')
group.permissions.add(permission)
```

```python
# in views — plain Django authorization, nothing SSO-specific:
@permission_required('store.view_admin_area')
def admin_area(request): ...
```

When a portal operator adds a user to `samplestore-admin`, their next login
here grants the permission; when the operator removes them, their next
login revokes it. No role models, no claim parsing, no custom decorators.

## Settings reference

| Key | Default | Meaning |
|---|---|---|
| `SERVER_URL` | required | Portal issuer base URL (or full discovery URL) |
| `CLIENT_ID` | required | OAuth2 client id registered on the portal |
| `CLIENT_SECRET` | `''` | OAuth2 client secret |
| `GROUP_PREFIX` | `None` | Group-sync scope, see table below |
| `STAFF_GROUPS` | `[]` | Claim groups granting `is_staff` (empty = never touch the flag) |
| `SUPERUSER_GROUPS` | `[]` | Same for `is_superuser` |
| `POST_LOGOUT_REDIRECT_URL` | `None` | Absolute URL for RP-initiated logout (see "Log out everywhere"); `None` omits `post_logout_redirect_uri` |
| `STATIC_ORIGIN` | `None` | Origin serving the portal's `/static/js/switch*.js` (see "Embedding the store-switch widget"); `None` reuses `SERVER_URL`'s origin |

### `GROUP_PREFIX` semantics

| | `GROUP_PREFIX = None` (default) | `GROUP_PREFIX = 'myapp-'` |
|---|---|---|
| Groups in the claim | All memberships set from the claim (created on demand) | Only `myapp-*` claim groups added; other claim groups ignored (not even created) |
| Local memberships not in the claim | **Removed** — the portal is the sole authority | `myapp-*` memberships removed; everything else untouched |
| Locally-managed groups | Not possible — don't hand-assign groups in this mode | Fully supported outside the prefix namespace |

Use `None` when the portal is your only identity/authorization source. Use
a prefix when your app also manages its own local groups and only a
namespace (e.g. `myapp-admin`, `myapp-users`) belongs to the portal.

### `STAFF_GROUPS` / `SUPERUSER_GROUPS`

Non-empty list: the flag is set on every login from the intersection with
the claim's groups — **grants and revokes**. Empty (default): the flag is
never touched. The match runs against the full claim group list, regardless
of `GROUP_PREFIX`.

## Back-channel logout

`POST /sso/backchannel-logout/` implements OIDC Back-Channel Logout 1.0.
The package records the id_token's `sid` claim per login (model
`PortalSession`, populated by the login receiver), and on a valid
`logout_token` (RS256 signature against the portal's jwks, `iss`, `aud`,
backchannel-logout `events` entry, `nonce` absent, `sid` present — any
failure is a 400) deletes the matching `django_session` rows. This is what
lets the portal's store-switch flow kill your app's session the moment the
user switches away.

Requires the **database session backend** (Django's default) — a
signed-cookie session cannot be revoked server-side.

## Reading portal claims (picture, locale, anything future)

Claims delivered at login are persisted verbatim in
``SocialAccount.extra_data`` (a JSON field) — the raw record of what the
portal asserted. Nothing needs a dedicated column on the RP unless
Django's own machinery reads it (groups / staff flags / User basics,
which the login sync materializes). Read everything else on demand:

```python
from sso_portal_client.claims import get_claim, get_claims

get_claim(request.user, 'picture')   # LINE avatar URL, or None
get_claim(request.user, 'locale')    # saved portal UI language, or None
get_claims(request.user)             # the merged claim dict
```

New portal claims become readable with zero RP migrations.

## Log out everywhere (RP-initiated logout)

`POST /sso/logout/` ends the session **everywhere**, not just in this app.
Back-channel logout (above) is the portal pushing a logout to you; this is the
reverse — your user clicking "log out" here and having the portal's session
(and, via the portal's own fan-out, every other RP) end too.

The view:

1. Logs out locally **first and unconditionally** — the local session is
   always cleared, even if the portal is unreachable.
2. Redirects (302) to the portal's `end_session_endpoint` (from the discovery
   document). If discovery can't be fetched, it still logs out locally and
   redirects to a local fallback instead of erroring (see below).

POST only (logout is state-changing) — a `GET` returns 405. Wire a small
CSRF-protected form:

```html
<form method="post" action="{% url 'sso_portal_client:logout' %}">
  {% csrf_token %}
  <button type="submit">Log out everywhere</button>
</form>
```

### Settings

- `POST_LOGOUT_REDIRECT_URL` (absolute URL, default `None`): where the portal
  returns the browser after ending its session. It must be registered as a
  `post_logout_redirect_uris` value on this app's portal OAuth2 Application —
  django-oauth-toolkit validates the URI against that list. It is also the
  **local fallback** when the portal's discovery document can't be fetched
  (then Django's `LOGOUT_REDIRECT_URL`, then `/`).

### Hint-or-prompt behavior (a note on the degraded UX)

The OIDC RP-Initiated Logout spec lets the RP pass an `id_token_hint` (the raw
id_token JWT) so the portal can log the user out **without a confirmation
prompt** and honor `post_logout_redirect_uri`. This package does **not** send
the hint, because **allauth 65.18 exposes no supported hook that surfaces the
raw id_token string**: the `openid_connect` adapter decodes the id_token and
stores only the decoded claims in `SocialAccount.extra_data['id_token']`; the
raw JWT is discarded, `SocialToken` has no field for it, and the callback view
hardcodes the stock adapter (so a custom `oauth2_adapter_class` isn't honored).
Capturing it would require monkeypatching or re-registering a full custom
provider — both out of scope for a config-only package.

Consequence (the documented degraded-but-functional UX): without a hint the
portal shows its logout **confirmation page**, and `post_logout_redirect_uri`
is omitted (the spec ties it to the hint). Logout still works end to end — the
user just clicks "confirm" once. If a future allauth release (or a host project
that *can* reach the raw token) stashes the raw id_token JWT in the Django
session under `sso_portal_client.conf.SESSION_ID_TOKEN_KEY`, `global_logout`
picks it up automatically and sends both `id_token_hint` and (when
`POST_LOGOUT_REDIRECT_URL` is set) `post_logout_redirect_uri` for a prompt-free
logout — no code change needed here.

## Session ping

`GET /sso/session-ping/` returns `200 {"sub": ..., "sid": ...}` for a live
session, `401` otherwise. It is the endpoint you pass as `sessionPingUrl`
to the portal's switch widget. It is deliberately **read-only — it must
never refresh the session** — otherwise the widget's polling would make
your session self-renewing forever (see the docstring on
`sso_portal_client.views.session_ping`, which mirrors the portal's Flask
reference RP). Consequently, do not enable `SESSION_SAVE_EVERY_REQUEST`.

## Embedding the store-switch widget

The portal's switch widget ships as two plain `<script src>` tags
(`switch.js` + `switch-widget.js`, see `example_project/store/templates/
store/index.html`). `portalOrigin` passed into `PortalSwitch.init()` /
`PortalSwitchWidget.init()` must always be the portal's **app** origin (the
`SERVER_URL` origin) — that's what the widget talks to at runtime (login
URL, switch popup). But in production the app origin serves no `/static/`
at all; the portal's static assets live on a separate CDN domain
(`STATIC_URL`). Point the `<script src>` tags there via
`SSO_PORTAL_CLIENT['STATIC_ORIGIN']` (default `None` reuses `SERVER_URL`'s
origin, which is correct in development where the portal's runserver does
serve `/static/`). The CDN serves those files `Cache-Control: public,
max-age=300` and invalidates on portal deploys, so the URL is stable — no
cache-busting query string needed.

## `claims_synced` signal

Fired after every group sync with the merged claims (userinfo + id_token;
id_token wins). Hang custom mapping here — e.g. the portal's `role` claim,
which this package intentionally does not map to any model:

```python
from django.dispatch import receiver
from sso_portal_client.signals import claims_synced

@receiver(claims_synced)
def map_role(sender, user, claims, **kwargs):
    user.profile.role = claims.get('role', '')
    user.profile.save(update_fields=['role'])
```

## Security caveats (from the portal's integration guide)

- **Group names are an API contract.** Your permission wiring hardcodes the
  literal strings it expects in the `groups` claim; renaming a group on the
  portal silently breaks the mapping with no error on either side.
  Coordinate renames with the portal operator.
- **Changes apply at the next login.** `groups` is computed fresh per token
  issuance; group/role revocation is not retroactive for already-issued
  tokens or live sessions. Keep token lifetimes short on the portal, and
  wire back-channel logout (above) so the portal can proactively end a
  session — it kills the session, not a single permission, but it bounds
  how long a since-revoked user keeps acting on stale permissions.
- Key your own records on the `sub` claim (stable), not
  `preferred_username`/`email` (both mutable).

## SampleStore (Django) example

`example_project/` is a runnable Django 6 RP — "SampleStore" — that installs
this package and nothing else does the SSO work. It proves the headline: a
portal login syncs the `groups` claim onto Django groups, and a group that
owns a permission confers it with no claim-inspecting code (`store/views.py`
gates `/admin-area/` with a plain `@permission_required`). It runs on
**localhost:9002** (the Flask reference RP owns 9001 — different host:port so
the two demos' session cookies don't collide on one machine).

What it demonstrates:

- Login goes straight to the portal (`SOCIALACCOUNT_ONLY` — no local
  username/password UI at all).
- `/` shows the signed-in user's synced `user.groups`, `is_staff`, and
  `is_superuser`.
- `/admin-area/` requires `store.view_admin_area`, which a data migration
  (`store/migrations/0002_admin_group.py`) attaches to the `samplestore-admin`
  group. Membership sync then grants/revokes it automatically.
- A custom 403 page lists the user's current groups and explains that access
  derives from SSO group membership → Django permission.

- The index page also wires the portal's in-store fast-switch integration
  (`switch.js` button + `switch-widget.js` badge), pointing the widget's
  session guard at the package's read-only `/sso/session-ping/`. Combined
  with the back-channel logout receiver, switching users in the portal popup
  kills this app's old session and re-enters the OIDC flow as the new user.
  Prerequisites are the portal's store-switch demo data (`setup_switch_demo`:
  Demo Store at `127.0.0.1`, PINs `1234`/`5678`) and a full portal login by
  each switch target **today** (daily enrollment).

### 1. Prepare the portal (sso_portal, on 127.0.0.1:8000)

Run the portal's demo bootstrappers first (they create the `alice`/`bob`
users and the `samplestore-users` / `samplestore-admin` groups):

```bash
# in the sso_portal repo
uv run python manage.py setup_switch_demo
uv run python manage.py setup_app_access_demo
```

Then register **this** RP as an OAuth2 Application on the portal and print its
secret (copy-paste into the portal's `manage.py shell`):

```bash
# in the sso_portal repo
uv run python manage.py shell -c "
from django.apps import apps
from django.contrib.auth.models import Group
from oauth2_provider.generators import generate_client_secret
from oauth2_provider.models import Application

CLIENT_ID = 'samplestore-django'
REDIRECT = 'http://localhost:9002/accounts/oidc/sso_portal/login/callback/'

app = Application.objects.filter(client_id=CLIENT_ID).first()
if app is None:
    secret = generate_client_secret()   # DOT hashes client_secret on save, so capture the plaintext first
    app = Application(
        name='SampleStore (Django)',
        client_id=CLIENT_ID,
        client_secret=secret,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris=REDIRECT,
        post_logout_redirect_uris='http://localhost:9002/',  # for /sso/logout/ (DOT validates it)
        algorithm=Application.RS256_ALGORITHM,
        skip_authorization=True,
    )
    app.save()
    print('SSO_CLIENT_SECRET=' + secret)
else:
    print('Application already exists; delete it to regenerate the secret.')

# Optional: wire the package's back-channel logout endpoint (guarded — the
# oidc_session plugin may be disabled on the portal).
if apps.is_installed('apps.oidc_session'):
    from apps.oidc_session.models import ApplicationLogoutConfig
    ApplicationLogoutConfig.objects.update_or_create(
        application=app,
        defaults={'backchannel_logout_uri': 'http://localhost:9002/sso/backchannel-logout/'},
    )

# Restrict sign-in to samplestore-users so the portal's app-access gate
# applies (this is what blocks carol). Guarded — app_access may be disabled.
if apps.is_installed('apps.app_access'):
    from apps.app_access.models import ApplicationAccessPolicy
    users_group, _ = Group.objects.get_or_create(name='samplestore-users')
    policy, _ = ApplicationAccessPolicy.objects.get_or_create(application=app, defaults={'restricted': True})
    policy.restricted = True
    policy.save()
    policy.allowed_groups.set([users_group])
"
```

### 2. Run SampleStore (this repo, on localhost:9002)

Paste the printed `SSO_CLIENT_SECRET` into both commands (it is the only
required env var; `SSO_SERVER_URL` and `SSO_CLIENT_ID` have working dev
defaults — `http://127.0.0.1:8000/o` and `samplestore-django`):

```bash
# in this repo
SSO_CLIENT_SECRET=<paste> uv run python example_project/manage.py migrate
SSO_CLIENT_SECRET=<paste> uv run python example_project/manage.py runserver localhost:9002
```

Open <http://localhost:9002/> and log in.

### Demo matrix

The portal decides *who may sign in*; SampleStore derives everything from the
synced groups:

| User | Portal groups | Result at SampleStore |
|---|---|---|
| **alice** | `samplestore-users`, `samplestore-admin` | Signs in; `is_staff` true (via `STAFF_GROUPS`); `/admin-area/` **allowed** |
| **bob** | `samplestore-users` | Signs in; `/admin-area/` returns the explanatory **403** |
| **carol** | *(none — not in `samplestore-users`)* | **Blocked at the portal's authorize page** — SampleStore never gets a callback |

`alice`/`bob` are created by `setup_switch_demo` + `setup_app_access_demo`.
"carol" stands for any portal user lacking `samplestore-users`; create one on
the portal (`User.objects.create_user('carol', password='demo1234')`, no group
memberships) to see the portal-side block.

### Running the example's tests

The example ships its own suite (view gating + data-migration behavior),
driven by Django's test runner against its own settings (the package's
`pytest` is scoped to `tests/` and does not collect these):

```bash
cd example_project && uv run python manage.py test store
```

## Development

```bash
uv sync
make test          # uv run pytest
make lint          # uv run ruff check .
make format-check  # uv run ruff format --check .
```
