import sqlite3
from src import database
from src.security import hash_password, generate_salt


hashed_password = hash_password("test_password")


def test_set_and_get_master_password():
    """
    Tests the setting and retrieval of the master password.

    This test ensures that `set_master_password` correctly stores the hashed password
    and salt, and that `get_master_password` retrieves the correct values.
    """
    conn = database.get_db_connection(":memory:")
    database.init_db(conn)
    salt = generate_salt()
    key_salt = generate_salt()
    database.set_master_password(conn, hashed_password, salt, key_salt)
    retrieved_data = database.get_master_password(conn)
    assert retrieved_data is not None
    assert retrieved_data[0] == hashed_password
    assert retrieved_data[1] == salt
    assert retrieved_data[2] == key_salt
    conn.close()


def test_update_master_password():
    """
    Tests the updating of the master password.

    This test verifies that `update_master_password` can successfully change the
    stored hashed password and salts.
    """
    conn = database.get_db_connection(":memory:")
    database.init_db(conn)
    salt1 = generate_salt()
    key_salt1 = generate_salt()
    database.set_master_password(conn, hashed_password, salt1, key_salt1)

    new_hashed_password = hash_password("new_test_password")
    salt2 = generate_salt()
    key_salt2 = generate_salt()
    database.update_master_password(conn, new_hashed_password, salt2, key_salt2)

    retrieved_data = database.get_master_password(conn)
    assert retrieved_data is not None
    assert retrieved_data[0] == new_hashed_password
    assert retrieved_data[1] == salt2
    assert retrieved_data[2] == key_salt2
    conn.close()


def test_set_master_password_is_idempotent():
    """
    Tests that setting the master password repeatedly keeps a single row.
    """
    conn = database.get_db_connection(":memory:")
    database.init_db(conn)
    salt = generate_salt()
    key_salt = generate_salt()
    database.set_master_password(conn, hashed_password, salt, key_salt)
    database.set_master_password(conn, hashed_password, salt, key_salt)
    count = conn.execute("SELECT COUNT(*) FROM master_password").fetchone()[0]
    assert count == 1
    conn.close()


def test_update_credential_missing_returns_false():
    """
    Tests that updating a credential for a non-existent service returns False.
    """
    conn = database.get_db_connection(":memory:")
    database.init_db(conn)
    assert database.update_credential(conn, "missing", "user", b"password") is False
    conn.close()


def test_delete_credential_missing_returns_false():
    """
    Tests that deleting a credential for a non-existent service returns False.
    """
    conn = database.get_db_connection(":memory:")
    database.init_db(conn)
    assert database.delete_credential(conn, "missing") is False
    conn.close()


def test_add_and_get_credential():
    """
    Tests the addition and retrieval of a single credential.

    This test ensures that `add_credential` correctly stores a credential and that
    `get_credential` can retrieve it by service name.
    """
    conn = database.get_db_connection(":memory:")
    database.init_db(conn)
    database.add_credential(conn, "test_service", "test_username", b"encrypted_password")
    credential = database.get_credential(conn, "test_service")
    assert credential is not None
    assert tuple(credential) == (
        "test_service",
        "test_username",
        b"encrypted_password",
    )
    conn.close()    


def test_get_all_credentials():
    """
    Tests the retrieval of all credentials.

    This test verifies that `get_all_credentials` returns a list of all stored
    credentials.
    """
    conn = database.get_db_connection(":memory:")
    database.init_db(conn)
    database.add_credential(conn, "test_service", "test_username", b"encrypted_password1")
    database.add_credential(conn, "test_service2", "test_username2", b"encrypted_password2")
    credentials = database.get_all_credentials(conn)
    assert len(credentials) == 2
    assert [tuple(cred) for cred in credentials] == [
        (
            "test_service",
            "test_username",
            b"encrypted_password1",
        ),
        (
            "test_service2",
            "test_username2",
            b"encrypted_password2",
        ),
    ]
    conn.close()


def test_update_credential():
    """
    Tests the updating of an existing credential.

    This test ensures that `update_credential` can modify the username and encrypted
    password for a given service.
    """
    conn = database.get_db_connection(":memory:")
    database.init_db(conn)
    database.add_credential(conn, "test_service", "test_username", b"encrypted_password")
    database.update_credential(conn, "test_service", "test_username2", b"new_encrypted_password")
    credential = database.get_credential(conn, "test_service")
    assert credential is not None
    assert tuple(credential) == (
        "test_service",
        "test_username2",
        b"new_encrypted_password",
    )
    conn.close()


def test_delete_credential():
    """
    Tests the deletion of a credential.

    This test verifies that `delete_credential` removes a credential from the database
    and that it can no longer be retrieved.
    """
    conn = database.get_db_connection(":memory:")
    database.init_db(conn)
    database.add_credential(conn, "test_service", "test_username", b"encrypted_password")
    database.delete_credential(conn, "test_service")
    assert database.get_credential(conn, "test_service") is None
    conn.close()