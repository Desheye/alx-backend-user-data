#!/usr/bin/env python3
"""User Authentication and Session Management Module"""
import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from typing import Union
from user import User
from uuid import uuid4


def _hash_password(pwd: str) -> str:
    """Generate a secure, salted hash of the given password"""
    encrypted = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())
    return encrypted


def _create_unique_id() -> str:
    """Generate a unique identifier as a string"""
    unique_id = uuid4()
    return str(unique_id)


class Auth:
    """Manage user accounts and sessions"""

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, pwd: str) -> User:
        """Create a new user account in the database
        Returns: Newly created User object
        """
        try:
            existing_user = self._db.find_user_by(email=email)
        except NoResultFound:
            secure_pwd = _hash_password(pwd)
            new_user = self._db.add_user(email, secure_pwd)
            return new_user
        else:
            raise ValueError(f'Account with email {email} already exists')

    def valid_login(self, email: str, pwd: str) -> bool:
        """Check if the provided login credentials are valid
        Returns: True if correct, False otherwise
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        stored_pwd = user.hashed_password
        if bcrypt.checkpw(pwd.encode(), stored_pwd):
            return True
        return False

    def create_session(self, email: str) -> str:
        """Initiate a new session for the user
        Returns: Session identifier
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        session_id = _create_unique_id()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[str, None]:
        """Retrieve user information based on active session
        Returns: User object if valid, None otherwise
        """
        if not session_id:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: int) -> None:
        """Terminate an active user session"""
        try:
            user = self._db.find_user_by(id=user_id)
        except NoResultFound:
            return None
        self._db.update_user(user.id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Issue a token for password reset
        Returns: Reset token string
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        reset_token = _create_unique_id()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, new_pwd: str) -> None:
        """Change user's password using a valid reset token"""
        if not reset_token or not new_pwd:
            return None
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError
        secure_pwd = _hash_password(new_pwd)
        self._db.update_user(user.id, hashed_password=secure_pwd,
                             reset_token=None)
