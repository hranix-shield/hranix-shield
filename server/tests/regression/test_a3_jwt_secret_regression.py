"""A-3 security fix regression anchor (2026-07-14).

`Settings.jwt_secret` used to default to a fixed string
("dev-insecure-secret-change-me") committed in this AGPL-licensed repo's
source. The architect proved live that anyone who read the source — which,
for an AGPL open-source project, is everyone — could forge a valid JWT for
"admin" with that public string and have it accepted by /auth/me, with no
call to /auth/login and no knowledge of any password. Fixed by removing the
string as a working default (jwt_secret now defaults to None) and having
services.auth.resolve_jwt_secret() generate+persist a random secret instead.

This pins the fix shut: a token forged with the OLD public placeholder string
must always be rejected, regardless of what the real signing secret is.
"""

import pytest
from jose import jwt

from app.services.auth import JWT_ALGORITHM, TokenError, decode_access_token

OLD_PUBLIC_PLACEHOLDER_SECRET = "dev-insecure-secret-change-me"


@pytest.mark.unit
def test_token_forged_with_old_public_placeholder_secret_is_rejected():
    forged_token = jwt.encode(
        {"sub": "admin", "role": "admin"},
        OLD_PUBLIC_PLACEHOLDER_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    with pytest.raises(TokenError):
        decode_access_token(forged_token)
