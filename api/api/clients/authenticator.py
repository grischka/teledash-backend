from datetime import datetime, timedelta
from typing import Dict, Optional, TypedDict

from pyrogram.client import Client as TelegramClient
from pyrogram.errors.exceptions import BadRequest
from pyrogram.errors.exceptions.unauthorized_401 import SessionPasswordNeeded
from pyrogram.types.authorization.sent_code import SentCode
from pyrogram.types.user_and_chats.user import User

# Full pyrogram error reference: https://docs.pyrogram.org/api/errors/

authenticator = None

# Enable or disable login to the Telegram test servers.
# Reference: https://docs.pyrogram.org/topics/test-servers
TELEGRAM_TEST_MODE = False


class MapEntry(TypedDict):
    created_at: datetime
    tg_client: TelegramClient


class SignInResponse(TypedDict):
    user: User
    session_hash: str


class TelegramAuthenticator:
    """
    Handles Telegram authentication via phone.
    TODO: Doesn't scale because stored in memory.
    """

    map: Dict[str, MapEntry]

    def __init__(self) -> None:
        self.map = {}

    def get_client(self, client_id: str) -> MapEntry:
        return self.map[client_id]

    def has_client(self, client_id: str) -> bool:
        return client_id in self.map

    def add_client(self, client_id: str, tg_client: TelegramClient) -> None:
        self.map[client_id] = {"created_at": datetime.utcnow(), "tg_client": tg_client}

    async def remove_client(self, client_id: str) -> None:
        if client_id not in self.map:
            return

        tg_client = self.map[client_id]["tg_client"]
        if tg_client.is_connected:
            await tg_client.disconnect()

        del self.map[client_id]

    async def remove_stale_clients(self) -> None:
        time_ago = datetime.utcnow() - timedelta(minutes=30)
        ids_to_delete = [
            client_id
            for client_id, client in self.map.items()
            if client["created_at"] < time_ago
        ]
        [await self.remove_client(client_id) for client_id in ids_to_delete]

    async def start_auth(
        self,
        client_id: str,
        api_id: int,
        api_hash: str,
        phone_number: str,
    ) -> SentCode:
        """
        Start Telegram authentication process and send login
        code for specified phone number.
        """

        await self.remove_stale_clients()

        if self.has_client(client_id):
            await self.remove_client(client_id)

        tg_client = TelegramClient(
            client_id,
            api_id=api_id,
            api_hash=api_hash,
            phone_number=phone_number,
            test_mode=TELEGRAM_TEST_MODE,
            no_updates=True,
            in_memory=True,
        )
        result = None
        await tg_client.connect()

        try:
            result = await tg_client.send_code(phone_number=phone_number)
        except BadRequest as e:
            if tg_client.is_connected:
                await tg_client.disconnect()

            raise ValueError(e)

        self.add_client(client_id, tg_client)

        return result

    async def signin(
        self,
        client_id: str,
        phone_number: str,
        phone_code_hash: str,
        phone_code: str,
        password: Optional[str],
    ) -> SignInResponse:
        """
        Finish Telegram authentication process (sign in) and
        create session hash for client.
        """

        user = None
        session_hash = None

        if not self.has_client(client_id):
            raise Exception(
                f"Session for client {client_id} not created. Please restart authentication process."  # noqa: E50
            )

        tg_client = self.get_client(client_id)["tg_client"]

        if password:
            try:
                user = await tg_client.check_password(password)
            except Exception as e:
                raise ValueError(e)

        try:
            user = await tg_client.sign_in(
                phone_number=phone_number,
                phone_code_hash=phone_code_hash,
                phone_code=phone_code,
            )
        except BadRequest as e:
            raise ValueError(e)
        except SessionPasswordNeeded as e:
            raise Exception(e)
        except Exception as e:
            raise e

        if not isinstance(user, User):
            # accepting TOS not implemented
            # see https://docs.pyrogram.org/api/methods/sign_in#pyrogram.Client.sign_in
            raise Exception(
                "Authorization not completed, because the user needs to accept the Terms of Services first (method not implemented)"  # noqa: E50
            )

        session_hash = await tg_client.export_session_string()
        await tg_client.disconnect()

        # remove client from list
        await self.remove_client(client_id)

        return {"user": user, "session_hash": session_hash}


def get_authenticator() -> TelegramAuthenticator:
    global authenticator

    if not authenticator:
        authenticator = TelegramAuthenticator()

    return authenticator
