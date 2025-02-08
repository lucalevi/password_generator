# 🔐 Advanced Password Generator with GUI

Welcome to the **Advanced Password Generator**! This is not just any password generator—it's a **GUI-powered**, **themeable**, and **user-friendly** tool that creates passwords so strong, even *you* might forget them! 😅

Whether you're a developer, a security enthusiast, or just someone who hates remembering passwords, this tool is for you. It’s built with Python and Tkinter, and it’s packed with features to make your password-generating experience delightful.

---

## 🎥 Demo

<p align="center">
  <img src="https://github.com/lucalevi/password_generator/raw/main/demo.png" width="400">
</p>



---

## ✨ Features

- **Customizable Password Length**: Choose between 4 and 50 characters. (Because 3 characters is just "123" and we’re better than that. 😎)
- **Include/Exclude Options**:
  - Numbers (because "password123" is still a thing 🤦‍♂️)
  - Special Characters (because why not add some spice? 🌶️)
  - Exclude Similar Characters (no more confusing "l" with "1" or "O" with "0")
- **Password Strength Indicator**: Know exactly how strong your password is with a color-coded strength meter. 💪
- **Copy to Clipboard**: One-click copying so you can paste your password wherever you need it. 📋
- **Password History**: Keep track of your last 4 generated passwords (in case you forget them too quickly 😅).
- **Themes**: Choose from multiple themes to personalize your password-generating experience. 🌈

---

## 🛠️ Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/password_generator.git
   cd password_generator
   ```
2. **Install Dependencies**:
    Make sure you have Python 3.x installed. Then, install the required package:
    ```bash
    pip install pyperclip
    ```
3. Run the Application
    ```bash
    python pwdgen.py
    ```

---

## 🧑‍💻 How It Works
The application uses **Tkinter** for the GUI and **Python's** `random` and `string` modules for password generation. Here’s a quick breakdown:

* **Password Generation**:
  * The tool ensures at least one lowercase and one uppercase letter.
  * It optionally includes numbers and special characters based on user preferences.
  * Similar characters (like "l" and "1") can be excluded to avoid confusion.

* **Password Strength**:
  * Strength is calculated using entropy, which considers the size of the character set and the password length.
  * The strength meter updates dynamically with color-coded feedback.

* **Themes**:
  * The app supports multiple themes (Default, Dark, Ocean, Forest) to suit your mood. 🌟

---

## 🚀 Why Use This?
* **Strong Passwords**: Generate passwords that even a supercomputer would struggle to crack. 🤖
* **User-Friendly**: No command-line nonsense—just a clean, intuitive GUI. 🖥️
* **Customizable**: Tailor your passwords to meet specific requirements. 🛠️
* **Fun Themes**: Because who doesn’t love a little color in their life? 🌈 

---

## 🤝 Contributing
Found a bug? Have a feature request? Want to add a new theme? Contributions are welcome! Here’s how you can help:

1. Fork the repository.
2. Create a new branch (```git checkout -b feature/AmazingFeature```).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (```git push origin feature/AmazingFeature```).
5. Open a Pull Request.

---

📜 License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

🙏 Acknowledgments
* **Python**: For being awesome. 🐍
* **Tkinter**: For making GUI development less painful. 🎨
* **pyperclip**: For making copying to clipboard a breeze. 📋
* **You**: For checking out this project! ❤️

Happy password generating! May your accounts stay secure and your passwords unforgettable (or at least stored in a password manager). 😉
