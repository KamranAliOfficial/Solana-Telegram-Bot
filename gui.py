#!/usr/bin/env python3

import tkinter as tk
from tkinter import messagebox, filedialog
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import subprocess
import sys
import os
import json
import platform
import logging
from typing import Dict, Optional
from datetime import datetime

class TelegramBotGUI:
    """
    A professional GUI application for controlling a Telegram Sniper Bot for Solana Tokens.
    Provides a user-friendly interface to configure and run the bot with proper error handling
    and configuration management.
    """

    CONFIG_FILE_EXTENSION = ".json"
    CONFIG_FILE_TYPES = [("JSON files", "*.json")]
    SCRIPT_NAME = "telegram.py"

    def __init__(self, master: ttk.Window) -> None:
        """Initialize the Telegram Bot GUI application."""
        self.master = master
        self.master.title("Telegram Sniper for Solana Tokens")
        self.master.geometry("600x500")
        self.process: Optional[subprocess.Popen] = None
        self.entries: Dict[str, ttk.Entry] = {}
        
        # Configure logging
        self._setup_logging()
        
        # Setup UI
        self._configure_styles()
        self._create_widgets()
        
        # Load default configuration if exists
        self._load_default_config()

    def _setup_logging(self) -> None:
        """Configure logging for the application."""
        logging.basicConfig(
            filename=f'telegram_bot_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def _configure_styles(self) -> None:
        """Configure ttkbootstrap styles for consistent UI appearance."""
        style = ttk.Style("darkly")
        style.configure("TButton", font=("Helvetica", 12))
        style.configure("TLabel", font=("Helvetica", 12))
        style.configure("TEntry", font=("Helvetica", 12))
        style.configure("Header.TLabel", font=("Helvetica", 18, "bold"))

    def _create_widgets(self) -> None:
        """Create and arrange all GUI widgets."""
        main_frame = ttk.Frame(self.master, padding="20")
        main_frame.pack(fill=BOTH, expand=YES)

        # Header
        ttk.Label(
            main_frame, 
            text="Telegram Sniper for Solana Tokens",
            style="Header.TLabel",
            bootstyle="warning"
        ).pack(pady=10)

        # Configuration fields
        fields = [
            ("Private Key:", "private_key", True),
            ("API ID:", "api_id", True),
            ("API Hash:", "api_hash", True),
            ("Phone Number:", "phone_number", True),
            ("Amount to Swap:", "amount_to_swap", True),
            ("Chat ID:", "chatid", False),
            ("Discord:", "discord", False)
        ]

        for label, key, required in fields:
            frame = ttk.Frame(main_frame)
            frame.pack(fill=X, pady=5)
            ttk.Label(frame, text=label, width=20).pack(side=LEFT)
            entry = ttk.Entry(frame, bootstyle="warning")
            entry.pack(side=LEFT, expand=YES, fill=X)
            self.entries[key] = entry
            if required:
                entry.configure(bootstyle="warning")
            else:
                entry.configure(bootstyle="secondary")

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=X, pady=20)
        
        buttons = [
            ("Run Bot", self.run_bot, "success"),
            ("Save Config", self.save_config, "info"),
            ("Load Config", self.load_config, "info")
        ]
        
        for text, command, style in buttons:
            ttk.Button(
                button_frame,
                text=text,
                command=command,
                bootstyle=style
            ).pack(side=RIGHT, padx=5)

    def run_bot(self) -> None:
        """Execute the Telegram bot script in a new terminal window."""
        try:
            if self.process and self.process.poll() is None:
                messagebox.showinfo("Info", "Bot is already running.")
                return

            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.SCRIPT_NAME)
            if not os.path.exists(script_path):
                error_msg = f"{self.SCRIPT_NAME} not found in the application directory."
                self.logger.error(error_msg)
                messagebox.showerror("Error", error_msg)
                return

            # Validate required fields
            required_fields = ["private_key", "api_id", "api_hash", "phone_number", "amount_to_swap"]
            for field in required_fields:
                if not self.entries[field].get().strip():
                    error_msg = f"{field.replace('_', ' ').title()} is required."
                    self.logger.error(error_msg)
                    messagebox.showerror("Error", error_msg)
                    return

            # Build command
            command = [sys.executable, script_path]
            for key, entry in self.entries.items():
                value = entry.get().strip()
                if value:
                    command.extend([f"--{key}", value])

            # Execute command based on platform
            system = platform.system()
            if system == "Windows":
                self.process = subprocess.Popen(
                    ["start", "cmd", "/k"] + command,
                    shell=True
                )
            elif system == "Darwin":  # macOS
                self.process = subprocess.Popen(
                    ["osascript", "-e", f'tell application "Terminal" to do script "{" ".join(command)}"']
                )
            else:  # Linux and other Unix-like systems
                self.process = subprocess.Popen(
                    ["x-terminal-emulator", "-e"] + command
                )

            self.logger.info("Bot started successfully")
            messagebox.showinfo("Info", "Bot started in a new terminal window.")

        except Exception as e:
            self.logger.error(f"Failed to run bot: {str(e)}")
            messagebox.showerror("Error", f"Failed to run bot: {str(e)}")

    def save_config(self) -> None:
        """Save current configuration to a JSON file."""
        try:
            config = {key: entry.get().strip() for key, entry in self.entries.items()}
            file_path = filedialog.asksaveasfilename(
                defaultextension=self.CONFIG_FILE_EXTENSION,
                filetypes=self.CONFIG_FILE_TYPES
            )
            if file_path:
                with open(file_path, 'w') as f:
                    json.dump(config, f, indent=4)
                self.logger.info(f"Configuration saved to {file_path}")
                messagebox.showinfo("Info", "Configuration saved successfully.")
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {str(e)}")
            messagebox.showerror("Error", f"Failed to save configuration: {str(e)}")

    def load_config(self) -> None:
        """Load configuration from a JSON file."""
        try:
            file_path = filedialog.askopenfilename(filetypes=self.CONFIG_FILE_TYPES)
            if file_path:
                with open(file_path, 'r') as f:
                    config = json.load(f)
                for key, value in config.items():
                    if key in self.entries:
                        self.entries[key].delete(0, tk.END)
                        self.entries[key].insert(0, value)
                self.logger.info(f"Configuration loaded from {file_path}")
                messagebox.showinfo("Info", "Configuration loaded successfully.")
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {str(e)}")
            messagebox.showerror("Error", f"Failed to load configuration: {str(e)}")

    def _load_default_config(self) -> None:
        """Attempt to load a default configuration file if it exists."""
        default_config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "default_config.json"
        )
        if os.path.exists(default_config_path):
            try:
                with open(default_config_path, 'r') as f:
                    config = json.load(f)
                for key, value in config.items():
                    if key in self.entries:
                        self.entries[key].delete(0, tk.END)
                        self.entries[key].insert(0, value)
                self.logger.info("Default configuration loaded")
            except Exception as e:
                self.logger.warning(f"Failed to load default configuration: {str(e)}")

def main() -> None:
    """Main entry point for the application."""
    root = ttk.Window(themename="darkly")
    app = TelegramBotGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()