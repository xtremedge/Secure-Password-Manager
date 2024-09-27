# Secure-Password-Manager
A Secure Password Manager and Generator application built using Python and Tkinter for GUI, with password encryption handled via Cryptography and password hashing using bcrypt. The application allows users to securely store, manage, and generate passwords, as well as import/export passwords to/from CSV files, protected by a master password.

Features
Set and Verify Master Password: Secure the app with a master password to ensure only authorized access.
Add New Passwords: Store website login details securely, encrypting the passwords.
View Saved Passwords: Decrypt and view the stored passwords directly in the application.
Generate Secure Passwords: Automatically generate strong, random passwords.
Export Passwords to CSV: Export saved passwords to a CSV file after verifying the master password.
Import Passwords from CSV: Import passwords from a CSV file into the app.
Password Encryption: Uses Fernet encryption to securely store passwords.
Master Password Hashing: Secure master password using bcrypt hashing.
Prerequisites
Before running this project, ensure you have the following installed:

Python 3.x
pip (Python package manager)
You also need to install the following Python packages:

bash
Copy code
pip install bcrypt cryptography
How to Run the Project
1. Clone the repository
bash
Copy code
git clone https://github.com/yourusername/secure-password-manager.git
cd secure-password-manager
2. Install dependencies
Run the following command to install the required packages:

bash
Copy code
pip install -r requirements.txt
3. Run the application
To start the password manager application, run the following command:

bash
Copy code
python main.py
Project Structure
bash
Copy code
.
├── secure_key.key           # Encryption key for password encryption
├── secure_password_manager.db  # SQLite database storing passwords and master password
├── main.py                  # Main Python script for the password manager
├── README.md                # Project documentation
Usage
Setting the Master Password
When you first run the application, you'll be prompted to set a master password.
The master password is hashed using bcrypt and stored securely in the database.
Adding a New Password
Click on "Add Password."
Enter the website name, username, and password.
Alternatively, generate a password by clicking "Generate Password."
Click "Save Password" to store the credentials.
Viewing Stored Passwords
Click on "View Passwords" to display all the saved passwords, which will be decrypted and shown.
Exporting Passwords to CSV
You can export all saved passwords to a CSV file by selecting "Export to CSV" from the menu.
You will be required to enter your master password to verify before exporting.
Importing Passwords from CSV
You can import passwords from a CSV file using the "Import from CSV" option.
The file must contain columns for Website, Username, and Password.
Security Considerations
Master Password: The master password is hashed using bcrypt, ensuring that even if the database is compromised, the master password remains secure.
Password Encryption: All stored passwords are encrypted using Fernet encryption from the cryptography package, ensuring confidentiality.
Master Password Verification: Before exporting passwords, the user must provide the correct master password for security.
Future Improvements
Password Strength Indicator: Add a feature to indicate the strength of the generated password.
Multi-User Support: Enable multiple users with separate password storage.
Password Search: Add a search feature to quickly find specific saved passwords.
Password Edit: Allow users to edit existing stored passwords.
License
This project is licensed under the MIT License. See the LICENSE file for more details.

Contributions
Contributions are welcome! Please fork this repository and submit a pull request for any improvements or features you'd like to add.
