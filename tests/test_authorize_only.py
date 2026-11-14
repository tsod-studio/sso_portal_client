"""The authorize-only client (``sso_portal_client.authorize_only``): the request it builds, the id_token it redeems
and verifies, and the claim checks binding the answer to the request. No portal is reached: discovery, the token
endpoint and the key set are answered here, with keys made for the test."""

import datetime
import io
import json
import time
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import rsa

from sso_portal_client import authorize_only, oidc

ISSUER = 'https://portal.invalid/o'
#: The authorize-only Application's credentials here: made up, as every value in this module.
CLIENT_ID = 'rp-authorize'
SHARED = 'not-a-real-secret'
REDIRECT_URI = 'https://rp.invalid/approve/callback/'
#: What a token endpoint answers where an id_token should be.
NUMBER = 7
DISCOVERY = {
    'issuer': ISSUER,
    'token_endpoint': f'{ISSUER}/token/',
    'jwks_uri': f'{ISSUER}/.well-known/jwks.json',
}
REQUEST = authorize_only.AuthorizeOnlyRequest(
    redirect_uri=REDIRECT_URI,
    binding_message='Refund NT$500 at desk 1',
    state='the-state',
    nonce='the-nonce',
    code_verifier='the-verifier',
)
REQUESTED_AT = datetime.datetime(2026, 11, 14, 9, 0, tzinfo=datetime.UTC)


@pytest.fixture(scope='module')
def key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope='module')
def stranger() -> rsa.RSAPrivateKey:
    """A key the portal never published."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwks(key: rsa.RSAPrivateKey, kid: str = 'portal-key') -> dict[str, Any]:
    public = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return {'keys': [{**public, 'kid': kid, 'use': 'sig', 'alg': 'RS256'}]}


def served(*sets: object) -> Any:
    """The portal's key set endpoint answering ``sets`` in turn, under PyJWT's own fetch, cache and cooldown."""
    opener = MagicMock()
    opener.open.side_effect = [io.BytesIO(json.dumps(keys).encode()) for keys in sets]
    return patch.object(jwt.jwks_client.urllib.request, 'build_opener', return_value=opener)


def token(key: rsa.RSAPrivateKey, **claims: Any) -> str:
    now = int(time.time())
    body = {'iss': ISSUER, 'aud': CLIENT_ID, 'sub': 'sub-mona', 'iat': now, 'exp': now + 300, **claims}
    return jwt.encode(
        {name: value for name, value in body.items() if value is not None},
        key,
        algorithm='RS256',
        headers={'kid': 'portal-key'},
    )


def answered(payload: Any, status: int = 200) -> MagicMock:
    response = MagicMock()
    response.json.return_value = payload
    response.raise_for_status.side_effect = requests.HTTPError('bad') if status >= 400 else None
    return response


def client() -> authorize_only.AuthorizeOnlyClient:
    return authorize_only.AuthorizeOnlyClient(client_id=CLIENT_ID, client_secret=SHARED)


@pytest.fixture
def portal(key: rsa.RSAPrivateKey) -> Iterator[None]:
    """Discovery and the key set answered here."""
    with (
        patch.object(oidc.requests, 'get', return_value=answered(DISCOVERY)),
        patch.object(jwt.PyJWKClient, 'fetch_data', return_value=jwks(key)),
    ):
        yield


def redeem(answer: MagicMock) -> tuple[dict[str, Any], MagicMock]:
    with patch.object(authorize_only.requests, 'post', return_value=answer) as posted:
        claims = client().redeem(code='a-code', code_verifier='a-verifier', redirect_uri=REDIRECT_URI)
    return claims, posted


def unavailable(answer: MagicMock) -> None:
    with pytest.raises(authorize_only.AuthorizeOnlyError) as failed:
        redeem(answer)
    assert failed.value.reason == authorize_only.PORTAL_UNAVAILABLE


def invalid(answer: MagicMock) -> None:
    with pytest.raises(authorize_only.AuthorizeOnlyError) as failed:
        redeem(answer)
    assert failed.value.reason == authorize_only.INVALID_TOKEN


class TestRequest:
    def test_fresh_secrets_for_each_request(self) -> None:
        first = authorize_only.AuthorizeOnlyRequest(redirect_uri=REDIRECT_URI)
        second = authorize_only.AuthorizeOnlyRequest(redirect_uri=REDIRECT_URI)
        assert len({first.state, first.nonce, second.state, second.nonce}) == 4
        assert first.code_verifier != second.code_verifier
        assert len(first.code_verifier) >= 43
        assert (first.binding_message, first.login_hint) == ('', '')

    def test_pkce_s256(self) -> None:
        # RFC 7636, appendix B.
        verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
        assert authorize_only.code_challenge(verifier) == 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
        assert REQUEST.code_challenge == authorize_only.code_challenge('the-verifier')

    def test_a_binding_message_the_portal_would_refuse(self) -> None:
        limit = authorize_only.BINDING_MESSAGE_MAX_LENGTH
        assert authorize_only.AuthorizeOnlyRequest(redirect_uri=REDIRECT_URI, binding_message='x' * limit)
        with pytest.raises(ValueError, match='binding_message'):
            authorize_only.AuthorizeOnlyRequest(redirect_uri=REDIRECT_URI, binding_message='x' * (limit + 1))

    def test_digest(self) -> None:
        assert authorize_only.digest('abc') == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'


class TestAuthorizationUrl:
    def test_a_standard_oidc_request_the_portal_always_asks_again_for(self) -> None:
        authorize = authorize_only.AuthorizeOnlyClient(
            client_id=CLIENT_ID, client_secret=SHARED, authorize_url='https://portal.invalid/switch/authorize/'
        )
        parts = urlsplit(authorize.authorization_url(REQUEST))
        assert f'{parts.scheme}://{parts.netloc}{parts.path}' == 'https://portal.invalid/switch/authorize/'
        assert {name: values[0] for name, values in parse_qs(parts.query).items()} == {
            'response_type': 'code',
            'client_id': CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'scope': 'openid profile',
            'state': 'the-state',
            'nonce': 'the-nonce',
            'code_challenge': REQUEST.code_challenge,
            'code_challenge_method': 'S256',
            'prompt': 'login',
            'max_age': '0',
            'display': 'popup',
            'binding_message': 'Refund NT$500 at desk 1',
        }

    def test_defaults_to_the_portals_own_endpoint(self) -> None:
        assert authorize_only.default_authorize_url() == 'http://127.0.0.1:8000/switch/authorize/'
        assert client().authorize_url == authorize_only.default_authorize_url()

    def test_a_page_with_a_login_hint_and_no_message(self) -> None:
        request = authorize_only.AuthorizeOnlyRequest(redirect_uri=REDIRECT_URI, login_hint='mona')
        query = parse_qs(urlsplit(client().authorization_url(request, display='page')).query)
        assert query['display'] == ['page']
        assert query['login_hint'] == ['mona']
        assert 'binding_message' not in query


@pytest.mark.usefixtures('portal')
class TestRedeem:
    def test_a_good_id_token(self, key: rsa.RSAPrivateKey) -> None:
        claims, posted = redeem(answered({'id_token': token(key, nonce='n')}))
        assert (claims['sub'], claims['nonce']) == ('sub-mona', 'n')
        assert posted.call_args.args == (DISCOVERY['token_endpoint'],)
        assert posted.call_args.kwargs['data'] == {
            'grant_type': 'authorization_code',
            'code': 'a-code',
            'redirect_uri': REDIRECT_URI,
            'code_verifier': 'a-verifier',
        }
        assert posted.call_args.kwargs['auth'] == (CLIENT_ID, SHARED)
        assert posted.call_args.kwargs['timeout'] == oidc.HTTP_TIMEOUT_SECONDS

    @pytest.mark.parametrize(
        'claims',
        [
            {'aud': 'test-client-id'},  # an ordinary sign-in's id_token
            {'iss': 'https://elsewhere.invalid/o'},
            {'exp': int(time.time()) - 60},
            {'sub': None},
            {'iat': None},
        ],
    )
    def test_an_id_token_for_another_client_issuer_or_time(
        self, key: rsa.RSAPrivateKey, claims: dict[str, Any]
    ) -> None:
        invalid(answered({'id_token': token(key, **claims)}))

    def test_a_signature_the_portal_never_made(self, stranger: rsa.RSAPrivateKey) -> None:
        invalid(answered({'id_token': token(stranger)}))

    def test_not_a_jwt(self) -> None:
        invalid(answered({'id_token': 'not-a-jwt'}))

    @pytest.mark.parametrize(
        'answer',
        [
            answered({}, status=400),
            answered({'expires_in': 60}),
            answered({'id_token': NUMBER}),
            answered(['not', 'an', 'object']),
        ],
    )
    def test_a_token_endpoint_that_does_not_answer_with_one(self, answer: MagicMock) -> None:
        unavailable(answer)

    def test_a_token_endpoint_answering_no_json(self) -> None:
        answer = answered(None)
        answer.json.side_effect = ValueError('not json')
        unavailable(answer)

    def test_a_token_endpoint_out_of_reach(self) -> None:
        with (
            patch.object(authorize_only.requests, 'post', side_effect=requests.Timeout('slow')),
            pytest.raises(authorize_only.AuthorizeOnlyError) as failed,
        ):
            client().redeem(code='a-code', code_verifier='v', redirect_uri=REDIRECT_URI)
        assert failed.value.reason == authorize_only.PORTAL_UNAVAILABLE


class TestUpstream:
    def test_discovery_out_of_reach(self, key: rsa.RSAPrivateKey) -> None:
        with patch.object(oidc.requests, 'get', side_effect=requests.ConnectionError('down')):
            unavailable(answered({'id_token': token(key)}))

    @pytest.mark.parametrize('endpoint', [None, '', NUMBER])
    def test_discovery_without_a_token_endpoint(self, key: rsa.RSAPrivateKey, endpoint: object) -> None:
        document = {**DISCOVERY, 'token_endpoint': endpoint}
        with patch.object(oidc.requests, 'get', return_value=answered(document)):
            unavailable(answered({'id_token': token(key)}))

    def test_a_key_set_out_of_reach(self, key: rsa.RSAPrivateKey) -> None:
        with (
            patch.object(oidc.requests, 'get', return_value=answered(DISCOVERY)),
            patch.object(jwt.PyJWKClient, 'fetch_data', side_effect=jwt.PyJWKClientConnectionError('down')),
        ):
            unavailable(answered({'id_token': token(key)}))

    def test_a_key_set_uri_that_is_none(self, key: rsa.RSAPrivateKey) -> None:
        with patch.object(oidc.requests, 'get', return_value=answered({**DISCOVERY, 'jwks_uri': 'not-a-url'})):
            unavailable(answered({'id_token': token(key)}))

    def test_a_key_the_portal_does_not_list(self, key: rsa.RSAPrivateKey) -> None:
        unlisted = jwt.encode({'sub': 'x'}, key, algorithm='RS256', headers={'kid': 'another-key'})
        with (
            patch.object(oidc.requests, 'get', return_value=answered(DISCOVERY)),
            served(jwks(key), jwks(key)) as fetched,
        ):
            invalid(answered({'id_token': unlisted}))
        # The set is fetched once more for the unknown key, and no more.
        assert fetched.return_value.open.call_count == 2

    def test_a_key_rotated_in_right_after_a_fetch(self, key: rsa.RSAPrivateKey, stranger: rsa.RSAPrivateKey) -> None:
        with (
            patch.object(oidc.requests, 'get', return_value=answered(DISCOVERY)),
            served(jwks(stranger, kid='old-key'), jwks(key)) as fetched,
        ):
            # The set fetched a moment ago lacks the key the portal signs with now.
            claims, _posted = redeem(answered({'id_token': token(key)}))
        assert claims['sub'] == 'sub-mona'
        assert fetched.return_value.open.call_count == 2

    def test_its_key_client_is_not_the_logout_one(self) -> None:
        uri = DISCOVERY['jwks_uri']
        assert oidc.jwk_client(uri, refetch_cooldown=False) is oidc.jwk_client(uri, refetch_cooldown=False)
        assert oidc.jwk_client(uri, refetch_cooldown=False) is not oidc.jwk_client(uri)
        assert oidc.jwk_client(uri, refetch_cooldown=False).cooldown_duration == 0
        assert oidc.jwk_client(uri).cooldown_duration > 0


def passing(**changes: Any) -> dict[str, Any]:
    """Claims that pass every check for :data:`REQUEST`, with ``changes`` (``None`` leaves a claim out)."""
    claims = {
        'sub': 'sub-mona',
        'nonce': REQUEST.nonce,
        'acr': authorize_only.ACR,
        'amr': ['pin'],
        'auth_time': int(REQUESTED_AT.timestamp()) + 30,
        'binding_message': REQUEST.binding_message,
        'jti': 'jti-1',
        'groups': ['managers'],
        **changes,
    }
    return {name: value for name, value in claims.items() if value is not None}


def failed(claims: dict[str, Any], **options: Any) -> str:
    arguments: dict[str, Any] = {
        'nonce_digest': authorize_only.digest(REQUEST.nonce),
        'binding_message': REQUEST.binding_message,
        'requested_at': REQUESTED_AT,
        'now': REQUESTED_AT + datetime.timedelta(seconds=40),
        **options,
    }
    return authorize_only.failed_check(claims, **arguments)


class TestFailedCheck:
    def test_claims_that_pass_every_check(self) -> None:
        assert failed(passing()) == ''
        assert failed(passing(groups=None)) == ''

    @pytest.mark.parametrize('method', authorize_only.METHODS)
    def test_every_way_to_identify(self, method: str) -> None:
        assert failed(passing(amr=[method])) == ''

    @pytest.mark.parametrize(
        ('changes', 'check'),
        [
            ({'nonce': 'another-nonce'}, 'nonce'),
            ({'nonce': None}, 'nonce'),
            ({'nonce': NUMBER}, 'nonce'),
            ({'acr': None}, 'acr'),  # an ordinary sign-in
            ({'acr': 'urn:other'}, 'acr'),
            ({'sid': 'a-session'}, 'sid'),
            ({'amr': ['lineautologin']}, 'amr'),
            ({'amr': 'pin'}, 'amr'),
            ({'amr': None}, 'amr'),
            ({'auth_time': None}, 'auth_time'),
            ({'auth_time': True}, 'auth_time'),
            ({'auth_time': '1763110830'}, 'auth_time'),
            ({'auth_time': int(REQUESTED_AT.timestamp()) - 1}, 'auth_time'),  # before the request
            ({'auth_time': int(REQUESTED_AT.timestamp()) + 42}, 'auth_time'),  # after now and its second of slack
            ({'binding_message': 'Refund NT$50 at desk 1'}, 'binding_message'),
            ({'binding_message': None}, 'binding_message'),
            ({'jti': None}, 'jti'),
            ({'jti': ''}, 'jti'),
            ({'jti': NUMBER}, 'jti'),
            ({'groups': 'managers'}, 'groups'),
        ],
    )
    def test_each_check(self, changes: dict[str, Any], check: str) -> None:
        assert failed(passing(**changes)) == check

    def test_the_first_check_that_fails_is_named(self) -> None:
        assert failed(passing(nonce='x', acr='y', sid='z')) == 'nonce'
        assert failed(passing(acr='y', sid='z')) == 'acr'

    def test_a_second_of_slack_for_the_portals_clock(self) -> None:
        now = REQUESTED_AT + datetime.timedelta(seconds=40)
        assert failed(passing(auth_time=int(now.timestamp()) + 1), now=now) == ''

    def test_an_identification_gone_stale(self) -> None:
        auth_time = int(REQUESTED_AT.timestamp())
        at_limit = REQUESTED_AT + datetime.timedelta(seconds=authorize_only.FRESH_SECONDS)
        assert failed(passing(auth_time=auth_time), now=at_limit) == ''
        assert failed(passing(auth_time=auth_time), now=at_limit + datetime.timedelta(seconds=1)) == 'auth_time'
        assert failed(passing(auth_time=auth_time), now=at_limit, fresh_seconds=60) == 'auth_time'

    def test_the_methods_an_rp_accepts(self) -> None:
        assert failed(passing(amr=['qr']), methods=('pin',)) == 'amr'
        assert failed(passing(amr=['qr', 'pin']), methods=('pin',)) == ''

    def test_no_message_sent_means_none_may_come_back(self) -> None:
        assert failed(passing(binding_message=None), binding_message='') == ''
        assert failed(passing(binding_message=''), binding_message='') == 'binding_message'
        assert failed(passing(), binding_message='') == 'binding_message'

    def test_a_replay_log(self) -> None:
        seen: list[str] = []

        def used(jti: str) -> bool:
            seen.append(jti)
            return jti == 'jti-old'

        assert failed(passing(), jti_used=used) == ''
        assert failed(passing(jti='jti-old'), jti_used=used) == 'jti'
        assert seen == ['jti-1', 'jti-old']
