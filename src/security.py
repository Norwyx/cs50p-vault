import base64
import os

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


ph = PasswordHasher()


def generate_salt() -> bytes:
    """
    Generates a cryptographically secure random salt.

    This function uses `os.urandom` to generate 16 bytes of random data, which is
    a suitable length for a salt in cryptographic operations like hashing and
    key derivation.

    Returns:
        A 16-byte random salt.
    """
    return os.urandom(16)


def hash_password(password: str) -> str:
    """
    Hashes a password using the Argon2 password hashing algorithm.

    Argon2 is a modern, secure hashing algorithm that is resistant to both
    GPU-based and custom hardware attacks. This function takes a plain-text
    password and returns its hashed representation.

    Args:
        password: The plain-text password to hash.

    Returns:
        The Argon2 hash of the password as a string.
    """
    return ph.hash(password)


def verify_password(hashed_password: str, password: str) -> bool:
    """
    Verifies a plain-text password against a stored Argon2 hash.

    This function securely checks if the provided password matches the stored
    hash. It is designed to be resistant to timing attacks.

    Args:
        hashed_password: The stored Argon2 hash.
        password: The plain-text password to verify.

    Returns:
        `True` if the password matches the hash, `False` otherwise.
    """
    try:
        ph.verify(hashed_password, password)
        return True
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        return False


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 32-byte encryption key from a password and salt using PBKDF2.

    This function uses the PBKDF2 (Password-Based Key Derivation Function 2)
    with HMAC-SHA256. It performs a high number of iterations (480,000) to
    make brute-force attacks computationally expensive.

    Args:
        password: The master password.
        salt: A random salt to ensure key uniqueness.

    Returns:
        A 32-byte URL-safe, base64-encoded encryption key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt(data: str, key: bytes) -> bytes:
    """
    Encrypts data using Fernet symmetric encryption.

    Fernet ensures that a message encrypted using it cannot be manipulated or
    read without the key. It uses AES-128 in CBC mode with PKCS7 padding,
    and signs the message with HMAC-SHA256.

    Args:
        data: The plain-text data to encrypt.
        key: The encryption key derived from the master password.

    Returns:
        The encrypted data as bytes.
    """
    return Fernet(key).encrypt(data.encode())


def decrypt(token: bytes, key: bytes) -> str:
    """
    Decrypts data using Fernet symmetric encryption.

    This function takes the encrypted token and the encryption key to retrieve
    the original plain-text data.

    Args:
        token: The encrypted data to decrypt.
        key: The encryption key used during encryption.

    Returns:
        The decrypted data as a string.
    """
    return Fernet(key).decrypt(token).decode()
