#!/usr/bin/env python3

import json
import logging
import os
from typing import Dict, Any, Optional
from datetime import datetime
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class PredatorSDK:
    """
    A Python SDK for interacting with the Predator API to perform Solana token operations
    such as buying, selling, and creating tokens, with secure data encryption.
    """

    DEFAULT_BASE_URL = "https://api.predator.bot"
    ENCRYPTION_ALGORITHM = algorithms.AES
    ENCRYPTION_MODE = modes.CBC
    BLOCK_SIZE = 16

    def __init__(self, config: Dict[str, str] = None) -> None:
        """
        Initialize the PredatorSDK with optional configuration.

        Args:
            config (Dict[str, str], optional): Configuration dictionary with 'base_url'.
        """
        self.config = config or {}
        self.base_url = self.config.get('base_url', self.DEFAULT_BASE_URL)
        self.encryption_key: Optional[bytes] = None
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json'})
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configure logging for the SDK."""
        logging.basicConfig(
            filename=f'predator_sdk_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        # Add console handler for real-time output
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(console_handler)

    async def initialize(self) -> None:
        """
        Initialize the SDK by fetching the encryption key from the API.

        Raises:
            Exception: If the encryption key cannot be retrieved.
        """
        if self.encryption_key:
            self.logger.debug("Encryption key already initialized")
            return

        try:
            self.logger.info("Fetching encryption key from API")
            response = self.session.get(f"{self.base_url}/encryption-key")
            response.raise_for_status()
            self.encryption_key = bytes.fromhex(response.json()['encryptionKey'])
            self.logger.info("Encryption key retrieved successfully")
        except requests.RequestException as e:
            error_msg = f"Failed to fetch encryption key: {str(e)}"
            self.logger.error(error_msg)
            raise Exception(error_msg) from e

    async def buy(self, options: Dict[str, str]) -> Dict[str, Any]:
        """
        Execute a buy operation for a Solana token.

        Args:
            options (Dict[str, str]): Dictionary containing 'privateKeys', 'tokenAddress', and 'amount'.

        Returns:
            Dict[str, Any]: API response data.

        Raises:
            Exception: If the buy operation fails.
        """
        return await self._execute_operation('buy', options)

    async def sell(self, options: Dict[str, str]) -> Dict[str, Any]:
        """
        Execute a sell operation for a Solana token.

        Args:
            options (Dict[str, str]): Dictionary containing 'privateKeys', 'tokenAddress', 'percentage'.

        Returns:
            Dict[str, Any]: API response data.

        Raises:
            ValueError: If the percentage is invalid.
            Exception: If the sell operation fails.
        """
        try:
            percentage = float(options.get('percentage', 0))
            if not 0 < percentage <= 100:
                raise ValueError('Percentage must be between 0 and 100.')
        except (TypeError, ValueError) as e:
            self.logger.error(f"Invalid percentage value: {str(e)}")
            raise ValueError('Percentage must be a valid number.') from e

        sell_options = options.copy()
        sell_options['amount'] = str(percentage)
        return await self._execute_operation('sell', sell_options)

    async def create(self, options: Dict[str, str]) -> Dict[str, Any]:
        """
        Execute a create operation for a new Solana token.

        Args:
            options (Dict[str, str]): Dictionary containing token creation parameters.

        Returns:
            Dict[str, Any]: API response data.

        Raises:
            Exception: If the create operation fails.
        """
        return await self._execute_operation('create', options)

    async def _execute_operation(self, operation: str, options: Dict[str, str]) -> Dict[str, Any]:
        """
        Execute a specified operation (buy, sell, or create) with encrypted data.

        Args:
            operation (str): The operation to perform ('buy', 'sell', or 'create').
            options (Dict[str, str]): Operation-specific parameters.

        Returns:
            Dict[str, Any]: API response data.

        Raises:
            Exception: If the operation fails or data preparation/encryption fails.
        """
        await self.initialize()
        endpoint = f"/{operation}"

        try:
            data = self._prepare_data(operation, options)
            encrypted_data = self._encrypt(json.dumps(data))
            self.logger.info(f"Executing {operation} operation")
            response = self.session.post(
                f"{self.base_url}{endpoint}",
                json={'encryptedData': encrypted_data}
            )
            response.raise_for_status()
            result = response.json()
            self.logger.info(f"{operation.capitalize()} operation successful")
            return result
        except requests.RequestException as e:
            error = self._handle_error(e)
            self.logger.error(f"{operation.capitalize()} operation failed: {str(error)}")
            raise error
        except Exception as e:
            self.logger.error(f"Unexpected error during {operation} operation: {str(e)}")
            raise

    def _prepare_data(self, operation: str, options: Dict[str, str]) -> Dict[str, Any]:
        """
        Prepare data payload for the specified operation.

        Args:
            operation (str): The operation type ('buy', 'sell', or 'create').
            options (Dict[str, str]): Operation-specific parameters.

        Returns:
            Dict[str, Any]: Prepared data payload.

        Raises:
            ValueError: If the operation is unsupported or required parameters are missing.
            KeyError: If required option keys are missing.
        """
        try:
            base_data = {'privateKeys': options['privateKeys']}

            if operation in ['buy', 'sell']:
                return {
                    **base_data,
                    'tokenBAddress': options['tokenAddress'],
                    'tokenBAmount': options['amount']
                }
            elif operation == 'create':
                required_fields = ['devPrivateKey', 'amount', 'name', 'symbol', 'description',
                                 'telegram', 'twitter', 'website', 'file']
                for field in required_fields:
                    if field not in options:
                        raise KeyError(f"Missing required field for create operation: {field}")
                return {
                    **base_data,
                    'tokenBAddress': options['devPrivateKey'],
                    'tokenBAmount': options['amount'],
                    'tokenName': options['name'],
                    'tokenSymbol': options['symbol'],
                    'tokenDescription': options['description'],
                    'telegramLink': options['telegram'],
                    'twitterLink': options['twitter'],
                    'websiteLink': options['website'],
                    'fileUrl': options['file']
                }
            else:
                raise ValueError(f"Unsupported operation: {operation}")
        except KeyError as e:
            self.logger.error(f"Missing required option: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Error preparing data for {operation}: {str(e)}")
            raise

    def _encrypt(self, text: str) -> str:
        """
        Encrypt the provided text using AES-CBC with the initialized encryption key.

        Args:
            text (str): Text to encrypt.

        Returns:
            str: Encrypted data in the format 'iv:encrypted_data' (hex-encoded).

        Raises:
            Exception: If the encryption key is not initialized or encryption fails.
        """
        if not self.encryption_key:
            error_msg = "Encryption key not initialized. Call initialize() first."
            self.logger.error(error_msg)
            raise Exception(error_msg)

        try:
            iv = os.urandom(self.BLOCK_SIZE)
            cipher = Cipher(
                self.ENCRYPTION_ALGORITHM(self.encryption_key),
                self.ENCRYPTION_MODE(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            padded_text = self._pad(text.encode())
            encrypted = encryptor.update(padded_text) + encryptor.finalize()
            result = f"{iv.hex()}:{encrypted.hex()}"
            self.logger.debug("Data encrypted successfully")
            return result
        except Exception as e:
            self.logger.error(f"Encryption failed: {str(e)}")
            raise Exception(f"Encryption error: {str(e)}") from e

    @staticmethod
    def _pad(s: bytes) -> bytes:
        """
        Pad the input bytes to align with the AES block size.

        Args:
            s (bytes): Input bytes to pad.

        Returns:
            bytes: Padded bytes.
        """
        padding_length = 16 - len(s) % 16
        return s + (padding_length * chr(padding_length)).encode()

    @staticmethod
    def _handle_error(error: requests.RequestException) -> Exception:
        """
        Handle HTTP request errors and return a formatted exception.

        Args:
            error (requests.RequestException): The request exception.

        Returns:
            Exception: Formatted exception with error details.
        """
        if error.response is not None:
            return Exception(f"API error: {error.response.status_code} - {error.response.text}")
        elif error.request is not None:
            return Exception("No response received from the server")
        return Exception(f"Request error: {str(error)}")

    def close(self) -> None:
        """
        Close the HTTP session to free resources.
        """
        self.session.close()
        self.logger.info("HTTP session closed")