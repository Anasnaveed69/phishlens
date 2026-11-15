"""Password hashing with Argon2id (memory-hard, salted)."""
from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_ph = PasswordHasher()  # argon2id with library-recommended parameters

# Pre-computed hash used when the username does not exist, so login timing
# doesn't reveal which usernames are valid.
_DUMMY_HASH = _ph.hash("phishlens-dummy-password")

MIN_LENGTH = 10


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _ph.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_problems(password: str) -> list[str]:
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"at least {MIN_LENGTH} characters")
    if password.isalpha() or password.isdigit():
        problems.append("mix letters with numbers or symbols")
    return problems
