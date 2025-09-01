#!/usr/bin/env python3

import argparse
import logging
import re
import os
import asyncio
import sys
import requests
import aiohttp
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from typing import Tuple, Optional
from datetime import datetime
from predator_sdk import PredatorSDK  # Assuming this is a custom SDK

class TelegramSniperBot:
    """Telegram bot for automated Solana token swaps based on message content."""

    BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    BASE58_PATTERN = re.compile(r'[1-9A-HJ-NP-Za-km-z]{32}')
    PAIR_TOKEN_PATTERN = re.compile(r'[a-zA-Z0-9]{33,64}')
    CONFIG_FILE = "bot_config.json"

    def __init__(self, args: argparse.Namespace) -> None:
        """Initialize the Telegram bot with provided arguments."""
        self.args = args
        self.api_id = args.api_id
        self.api_hash = args.api_hash
        self.phone_number = args.phone_number
        self.amount_to_swap = args.amount_to_swap
        self.chat_id = args.chatid
        self.discord_webhook_url = args.discord
        self.private_key = args.private_key
        self.session_string = args.session_string

        # Setup logging
        self._setup_logging()

        # Initialize Telegram client
        self.client = (TelegramClient(StringSession(self.session_string), self.api_id, self.api_hash)
                      if self.session_string else TelegramClient(StringSession(), self.api_id, self.api_hash))

        # Initialize PredatorSDK
        self.sdk = PredatorSDK()

    def _setup_logging(self) -> None:
        """Configure logging for the bot."""
        logging.basicConfig(
            filename=f'telegram_sniper_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        logging.getLogger('httpx').setLevel(logging.WARNING)
        self.logger = logging.getLogger(__name__)
        # Add console handler for real-time output
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(console_handler)

    def _save_session(self) -> None:
        """Save the Telegram session string to a configuration file."""
        try:
            session_string = self.client.session.save()
            config = {
                "session_string": session_string,
                "api_id": self.api_id,
                "api_hash": self.api_hash,
                "phone_number": self.phone_number
            }
            with open(self.CONFIG_FILE, 'w') as f:
                import json
                json.dump(config, f, indent=4)
            self.logger.info(f"Session saved to {self.CONFIG_FILE}")
        except Exception as e:
            self.logger.error(f"Failed to save session: {str(e)}")

    async def _get_pool_info(self, pair_token: str) -> Optional[str]:
        """Fetch pool information from DexScreener API for a given pair token."""
        url = f"https://api.dexscreener.com/latest/dex/pairs/solana/{pair_token}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        pairs = data.get("pairs", [])
                        for token in pairs:
                            contract_id = token.get("baseToken", {}).get("address")
                            if contract_id:
                                self.logger.info(f"Found quote mint: {contract_id}")
                                return contract_id
                    else:
                        self.logger.warning(f"DexScreener API returned status {resp.status}")
        except Exception as e:
            self.logger.error(f"Failed to fetch pool info for {pair_token}: {str(e)}")
        return None

    def _notify_discord(self, message: str, success: bool = True) -> None:
        """Send a notification to Discord webhook."""
        if not self.discord_webhook_url:
            return

        payload = {"content": f"{'Swap successful' if success else 'Swap failed'}:\n{message}"}
        try:
            response = requests.post(self.discord_webhook_url, json=payload)
            if response.status_code == 204:
                self.logger.info("Discord notification sent successfully")
            else:
                self.logger.warning(f"Failed to send Discord notification: Status {response.status_code}")
        except Exception as e:
            self.logger.error(f"Error sending Discord notification: {str(e)}")

    def _is_base58(self, s: str) -> bool:
        """Check if a string is a valid Base58 string."""
        return all(c in self.BASE58_ALPHABET for c in s)

    def _find_first_token_or_public_key(self, text: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract the first valid token or public key from text."""
        potential_keys = self.BASE58_PATTERN.findall(text)
        potential_pair_tokens = self.PAIR_TOKEN_PATTERN.findall(text)

        for token in potential_pair_tokens:
            self.logger.info(f"Found pair token: {token}")
            return token, 'pair_token'
        for key in potential_keys:
            if self._is_base58(key):
                self.logger.info(f"Found public key: {key}")
                return key, 'public_key'
        return None, None

    async def _perform_swap(self, token_address: str) -> None:
        """Execute a token swap using PredatorSDK."""
        try:
            self.logger.info(f"Attempting to swap {self.amount_to_swap} for token: {token_address}")
            result = await self.sdk.buy({
                'privateKeys': self.private_key,
                'tokenAddress': token_address,
                'amount': str(self.amount_to_swap),
            })
            self.logger.info(f"Swap successful: {result}")
            self._notify_discord(str(result))
        except Exception as e:
            error_msg = f"Swap failed for {token_address}: {str(e)}"
            self.logger.error(error_msg)
            self._notify_discord(error_msg, success=False)
            raise

    async def _process_message(self, event: events.NewMessage.Event) -> None:
        """Process incoming Telegram message and initiate swap if valid token found."""
        try:
            message_text = event.message.text
            token, token_type = self._find_first_token_or_public_key(message_text)

            if not token:
                self.logger.info("No Solana public keys or pair tokens found in message")
                return

            if token_type == 'public_key':
                await self._perform_swap(token)
            elif token_type == 'pair_token':
                quote_mint = await self._get_pool_info(token)
                await self._perform_swap(quote_mint or token)
        except Exception as e:
            self.logger.error(f"Error processing message: {str(e)}")

    def _register_event_handlers(self) -> None:
        """Register Telegram event handlers for new messages."""
        handler = self._process_message
        if self.chat_id:
            self.client.on(events.NewMessage(chats=int(self.chat_id)))(handler)
        else:
            self.client.on(events.NewMessage())(handler)
        self.logger.info(f"Event handler registered{' for chat ID ' + self.chat_id if self.chat_id else ''}")

    async def run(self) -> None:
        """Main method to start the bot."""
        try:
            self.logger.info("Initializing PredatorSDK...")
            await self.sdk.initialize()
            self.logger.info("PredatorSDK initialized successfully")

            self.logger.info("Starting Telegram client...")
            self._register_event_handlers()
            await self.client.start(phone=self.phone_number)
            self.logger.info("Telegram client started successfully")

            # Save session for future use
            self._save_session()

            self.logger.info("Bot is now running and listening for messages")
            await self.client.run_until_disconnected()

        except Exception as e:
            self.logger.error(f"Fatal error in bot: {str(e)}")
            raise

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Telegram Bot for Solana Token Swaps')
    parser.add_argument('--private_key', required=True, help='Private Key for Solana Wallet')
    parser.add_argument('--api_id', required=True, help='Telegram API ID')
    parser.add_argument('--api_hash', required=True, help='Telegram API Hash')
    parser.add_argument('--phone_number', required=True, help='Telegram Phone Number')
    parser.add_argument('--amount_to_swap', required=True, type=float, help='Amount to Swap')
    parser.add_argument('--chatid', default='', help='Telegram Chat ID (optional)')
    parser.add_argument('--discord', help='Discord Webhook URL (optional)')
    parser.add_argument('--session_string', help='Telegram Session String (optional)')
    return parser.parse_args()

async def main() -> None:
    """Main entry point for the Telegram bot."""
    args = parse_arguments()
    bot = TelegramSniperBot(args)
    await bot.run()

if __name__ == '__main__':
    asyncio.run(main())