#!/usr/bin/env python3
"""
Definition of _hash_password function
"""
import bcrypt
from uuid import uuid4
from sqlalchemy.orm.exc import NoResultFound
from typing import (
    TypeVar,
    Union
)

from db import DB
from user import User

U = TypeVar('U', bound=User)


def _hash_password(password: str) -> bytes:
    """
    Hashes a password string and returns it in bytes form
    Args:
        password (str): password in string format
    """
    passwd = password.encode('utf-8')
    return bcrypt.hashpw(passwd, bcrypt.gensalt())


def _generate_uuid() -> str:
    """
    Generate a uuid and return its string representation
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self) -> None:
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Register a new user and return a user object
        Args:
            email (str): new user's email address
            password (str): new user's password
        Return:
            if no user with given email exists, return newly created user
            else raise ValueError
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            hashed = _hash_password(password)
            usr = self._db.add_user(email, hashed)
            return usr
        raise ValueError(f"User {email} already exists")


    def valid_login(self, email: str, password: str) -> bool:
        """
        Validate a user's login credentials and return True if they are correct
        or False if they are not
        Args:
            email (str): user's email address
            password (str): user's password
        Return:
            True if credentials are correct, else False
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        user_password = user.hashed_password
        passwd = password.encode("utf-8")
        return bcrypt.checkpw(passwd, user_password)
