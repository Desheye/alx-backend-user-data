#!/usr/bin/env python3
"""Module for password encryption.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Generates a hashed password using a random salt.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Verifies if a hashed password matches the given password.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
