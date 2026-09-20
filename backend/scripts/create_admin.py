"""Create the first administrator.

    python -m scripts.create_admin --username boris --display-name "Boris Evtimov"

The password is read from a prompt, never from an argument (arguments are
visible in `ps`) and never from a file. Nothing is echoed.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys

from app.core.config import get_settings
from app.core.security import hash_password
from app.db.pool import Database
from app.db.repositories.users import UserRepository

MIN_PASSWORD_LENGTH = 12


async def create(username: str, display_name: str, password: str, is_admin: bool) -> None:
    settings = get_settings()
    database = Database(settings)
    await database.connect()
    try:
        users = UserRepository(database.pool)
        if await users.by_username(username) is not None:
            sys.exit(f"user {username!r} already exists")
        user_id = await users.create(
            username, display_name, hash_password(password, settings), is_admin=is_admin
        )
        print(f"created user {username} with id {user_id}")
    finally:
        await database.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument("--no-admin", action="store_true")
    args = parser.parse_args()

    password = getpass.getpass("password: ")
    if len(password) < MIN_PASSWORD_LENGTH:
        sys.exit(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if password != getpass.getpass("repeat: "):
        sys.exit("passwords do not match")

    asyncio.run(create(args.username, args.display_name, password, not args.no_admin))


if __name__ == "__main__":
    main()
