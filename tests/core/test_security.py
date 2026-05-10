from app.core.security import hash_password, verify_password


def test_password_hashing() -> None:
    password = "SuperSecretPassword123!"  # noqa: S105
    hashed_password = hash_password(password)

    assert hashed_password != password
    assert verify_password(password, hashed_password) is True


def test_password_verification_fails_with_wrong_password() -> None:
    password = "SuperSecretPassword123!"  # noqa: S105
    wrong_password = "WrongPassword123!"  # noqa: S105
    hashed_password = hash_password(password)

    assert verify_password(wrong_password, hashed_password) is False


def test_multiple_hashes_of_same_password_are_different() -> None:
    password = "SuperSecretPassword123!"  # noqa: S105
    hash1 = hash_password(password)
    hash2 = hash_password(password)

    # Due to salting, hashes should be different
    assert hash1 != hash2

    assert verify_password(password, hash1) is True
    assert verify_password(password, hash2) is True
