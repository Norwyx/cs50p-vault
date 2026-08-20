from src import database, main
from src import security
from src.security import derive_key, encrypt, generate_salt, hash_password


def test_validate_master_password_rejects_short_password():
    """
    Tests that master passwords below the minimum length are rejected.
    """
    assert main.validate_master_password("short") is not None
    assert main.validate_master_password("") is not None


def test_validate_master_password_accepts_strong_password():
    """
    Tests that master passwords meeting the minimum length are accepted.
    """
    assert main.validate_master_password("a-long-enough-password") is None


def test_change_master_password_reencrypts_credentials(monkeypatch):
    """
    Tests that changing the master password re-encrypts all stored credentials
    with the new key and swaps the in-memory encryption key.
    """
    old_password = "old-master-password"
    new_password = "new-master-password"
    secret = "super-secret-password"

    conn = database.get_db_connection(":memory:")
    database.init_db(conn)

    salt = generate_salt()
    key_salt = generate_salt()
    database.set_master_password(conn, hash_password(old_password), salt, key_salt)
    old_key = derive_key(old_password, key_salt)

    vault = main.Vault(conn)
    vault._encryption_key = old_key
    database.add_credential(conn, "github", "user", encrypt(secret, old_key))

    inputs = iter([old_password, new_password, new_password])
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(inputs))

    vault.change_master_password()

    assert vault.is_locked is False
    _, _, new_key_salt = database.get_master_password(conn)
    new_key = derive_key(new_password, new_key_salt)
    assert vault._encryption_key == new_key

    credential = database.get_credential(conn, "github")
    decrypted = security.decrypt(credential["encrypted_password"], new_key)
    assert decrypted == secret


def test_change_master_password_aborts_on_corrupt_data(monkeypatch):
    """
    Tests that changing the master password is aborted without side effects
    when an existing credential cannot be decrypted with the current key.
    """
    old_password = "old-master-password"
    new_password = "new-master-password"

    conn = database.get_db_connection(":memory:")
    database.init_db(conn)

    salt = generate_salt()
    key_salt = generate_salt()
    database.set_master_password(conn, hash_password(old_password), salt, key_salt)
    original_data = database.get_master_password(conn)

    vault = main.Vault(conn)
    vault._encryption_key = derive_key("wrong-key", generate_salt())
    database.add_credential(conn, "github", "user", encrypt("secret", derive_key("other-key", generate_salt())))

    inputs = iter([old_password, new_password, new_password])
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(inputs))

    vault.change_master_password()

    assert database.get_master_password(conn) == original_data
    credential = database.get_credential(conn, "github")
    assert credential is not None