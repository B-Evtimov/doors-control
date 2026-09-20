"""Issue a one-time enrolment code for a user.

    python -m scripts.issue_enrollment_code --username boris --ttl 900

The code is printed once. Only its SHA-256 is stored, so if the operator
loses it there is nothing to recover - issue another one.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import secrets
import sys

from app.core.config import get_settings
from app.db.pool import Database
from app.db.repositories.devices import EnrollmentRepository
from app.db.repositories.users import UserRepository


async def issue(username: str, ttl: int) -> None:
    settings = get_settings()
    database = Database(settings)
    await database.connect()
    try:
        user = await UserRepository(database.pool).by_username(username)
        if user is None:
            sys.exit(f"no such user: {username}")
        code = secrets.token_urlsafe(24)
        await EnrollmentRepository(database.pool).create(
            user_id=user["id"],
            code_hash=hashlib.sha256(code.encode()).digest(),
            created_by=user["id"],
            ttl_seconds=ttl,
        )
        print(f"enrollment code for {username} (valid {ttl}s): {code}")
    finally:
        await database.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True)
    parser.add_argument("--ttl", type=int, default=900)
    asyncio.run(issue(*vars(parser.parse_args()).values()))


if __name__ == "__main__":
    main()
