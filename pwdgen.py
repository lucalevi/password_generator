"""
Advanced Password Generator with GUI

This script provides a graphical user interface (GUI) for generating strong,
customizable passwords.
Users can specify the length of the password, include/exclude numbers and
special characters, and exclude similar-looking characters.
The generated passwords are displayed with a strength indicator, and users can
copy passwords to the clipboard. A history of generated passwords is also
maintained.

Author: Luca Iacolettig with DeepSeek
Date: 2025-02-08
Version: 1.0
"""

import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import pyperclip
import math


class PasswordGenerator:
    """
    A class to create a password generator application with a graphical user interface.

    Attributes:
        root (tk.Tk): The main window of the application.
        history (list): A list to store the history of generated passwords.
        themes (dict): A dictionary of color themes for the application.
    """

    def __init__(self, root):
        """
        Initializes the PasswordGenerator class.

        Args:
            root (tk.Tk): The main window of the application.
        """
        self.root = root
        self.root.title("Advanced Password Generator")
        self.root.geometry("440x480")  # Adjusted window size
        self.history = []  # Stores the last few generated passwords
        self.themes = {
            "Default": {"bg": "#f0f0f0", "fg": "#000000"},
            "Dark": {"bg": "#2d2d2d", "fg": "#ffffff"},
            "Ocean": {"bg": "#e0f7fa", "fg": "#00796b"},
            "Forest": {"bg": "#e8f5e9", "fg": "#2e7d32"},
        }

        self.setup_ui()  # Set up the user interface
        self.apply_theme("Default")  # Apply the default theme

    def setup_ui(self):
        """
        Sets up the user interface for the password generator.
        """
        main_frame = ttk.Frame(self.root)
        main_frame.pack(padx=20, pady=20, fill="both", expand=True)

        # Options Frame
        options_frame = ttk.LabelFrame(main_frame, text="Settings")
        options_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        # Password Length
        ttk.Label(options_frame, text="Password Length (4-50):").grid(
            row=0, column=0, sticky="w"
        )
        self.length_entry = ttk.Entry(options_frame, width=5)
        self.length_entry.grid(row=0, column=1, sticky="w")
        self.length_entry.insert(0, "12")  # Default password length

        # Checkboxes for password options
        self.numbers_var = tk.BooleanVar(value=True)  # Include numbers by default
        self.specials_var = tk.BooleanVar(
            value=True
        )  # Include special characters by default
        self.exclude_similar_var = tk.BooleanVar()  # Exclude similar characters option

        ttk.Checkbutton(
            options_frame, text="Include Numbers", variable=self.numbers_var
        ).grid(row=1, column=0, sticky="w")
        ttk.Checkbutton(
            options_frame, text="Include Special Characters", variable=self.specials_var
        ).grid(row=1, column=1, sticky="w")
        ttk.Checkbutton(
            options_frame,
            text="Exclude Similar Characters (e.g., il1Lo0O)",
            variable=self.exclude_similar_var,
        ).grid(row=2, column=0, columnspan=2, sticky="w")

        # Generate Button
        ttk.Button(
            main_frame, text="Generate Password", command=self.generate_password
        ).grid(row=1, column=0, pady=10)

        # Password Display
        self.password_var = tk.StringVar()  # Stores the generated password
        password_entry = ttk.Entry(
            main_frame, textvariable=self.password_var, width=40, font=("Arial", 12)
        )
        password_entry.grid(row=2, column=0, pady=5)

        # Copy Button
        ttk.Button(
            main_frame, text="Copy to Clipboard", command=self.copy_password
        ).grid(row=3, column=0)

        # Strength Indicator
        self.strength_label = ttk.Label(main_frame, text="Strength: ")
        self.strength_label.grid(row=4, column=0, pady=5)

        # Password History
        history_frame = ttk.LabelFrame(main_frame, text="Password History")
        history_frame.grid(row=5, column=0, sticky="ew", pady=5)

        self.history_list = tk.Listbox(history_frame, height=4)
        self.history_list.pack(fill="both", expand=True)

        # Theme Selector
        ttk.Label(main_frame, text="Theme:").grid(row=6, column=0, sticky="w", pady=5)
        self.theme_var = tk.StringVar()
        theme_selector = ttk.Combobox(
            main_frame, textvariable=self.theme_var, values=list(self.themes.keys())
        )
        theme_selector.grid(row=6, column=0, sticky="e", pady=5)
        theme_selector.bind("<<ComboboxSelected>>", self.change_theme)
        self.theme_var.set("Default")  # Set default theme

    def get_character_set(self):
        """
        Returns the set of characters to be used for password generation based on user preferences.

        Returns:
            str: A string containing all allowed characters.
        """
        chars = string.ascii_letters  # Always include letters

        if self.numbers_var.get():
            chars += string.digits  # Include numbers if selected
        if self.specials_var.get():
            chars += string.punctuation  # Include special characters if selected

        if self.exclude_similar_var.get():
            similar = "il1Lo0O"  # Characters to exclude if selected
            chars = "".join([c for c in chars if c not in similar])

        return chars

    def calculate_strength(self, password):
        """
        Calculates the strength of the password based on entropy.

        Args:
            password (str): The password to evaluate.

        Returns:
            tuple: A tuple containing the strength label and color code.
        """
        char_space = len(set(self.get_character_set()))  # Number of unique characters
        length = len(password)  # Length of the password
        entropy = math.log2(char_space**length)  # Calculate entropy

        # Determine strength based on entropy
        if entropy > 128:
            return "Very Strong", "#4CAF50"  # Green
        elif entropy > 60:
            return "Strong", "#8BC34A"  # Light Green
        elif entropy > 36:
            return "Moderate", "#FFC107"  # Yellow
        elif entropy > 28:
            return "Weak", "#FF9800"  # Orange
        else:
            return "Very Weak", "#F44336"  # Red

    def generate_password(self):
        """
        Generates a password based on user preferences and updates the UI.
        """
        try:
            length = int(self.length_entry.get())
            if not 4 <= length <= 50:  # Validate password length
                raise ValueError
        except ValueError:
            messagebox.showerror(
                "Error", "Please enter a valid length between 4 and 50"
            )
            return

        chars = self.get_character_set()
        if not chars:  # Ensure at least one character type is selected
            messagebox.showerror("Error", "Please select at least one character type")
            return

        # Generate password with guaranteed character types
        password = []
        required_chars = []

        # Add at least one lowercase and uppercase letter
        password.append(random.choice(string.ascii_lowercase))
        password.append(random.choice(string.ascii_uppercase))
        required_chars = password.copy()

        # Add at least one number and special character if selected
        if self.numbers_var.get():
            password.append(random.choice(string.digits))
        if self.specials_var.get():
            password.append(random.choice(string.punctuation))

        # Fill the remaining length with random characters
        remaining = length - len(password)
        password += [random.choice(chars) for _ in range(remaining)]

        # Shuffle the password to ensure randomness
        random.shuffle(password)
        password = "".join(password)

        # Update UI with the generated password
        self.password_var.set(password)
        strength, color = self.calculate_strength(password)
        self.strength_label.config(text=f"Strength: {strength}", foreground=color)

        # Update password history
        self.history.insert(0, password)
        self.history_list.delete(0, tk.END)
        for pwd in self.history[:4]:  # Keep only the last 4 passwords
            self.history_list.insert(tk.END, pwd)

    def copy_password(self):
        """
        Copies the generated password to the clipboard.
        """
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

    def apply_theme(self, theme_name):
        """
        Applies the selected theme to the application.

        Args:
            theme_name (str): The name of the theme to apply.
        """
        theme = self.themes[theme_name]
        self.root.configure(bg=theme["bg"])  # Set background color
        for widget in self.root.winfo_children():
            if isinstance(
                widget, (ttk.Frame, ttk.LabelFrame, ttk.Button, ttk.Entry, ttk.Combobox)
            ):
                continue
            try:
                widget.config(bg=theme["bg"], fg=theme["fg"])  # Set widget colors
            except:
                pass

    def change_theme(self, event):
        """
        Changes the application theme when a new theme is selected.

        Args:
            event: The event triggering the theme change.
        """
        self.apply_theme(self.theme_var.get())


if __name__ == "__main__":
    root = tk.Tk()  # Create the main window
    app = PasswordGenerator(root)  # Initialize the application
    root.mainloop()  # Run the application
