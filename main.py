import tkinter as tk
from tkinter import filedialog, messagebox
import random
import sqlite3
import bcrypt
from cryptography.fernet import Fernet
import os
import csv

# Database setup
conn = sqlite3.connect('secure_password_manager.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS passwords 
             (id INTEGER PRIMARY KEY, website TEXT, username TEXT, password TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS master_password
             (id INTEGER PRIMARY KEY, password TEXT)''')
conn.commit()

# Generate encryption key if not present
key_file = 'secure_key.key'
if not os.path.exists(key_file):
    key = Fernet.generate_key()
    with open(key_file, 'wb') as key_out:
        key_out.write(key)
else:
    with open(key_file, 'rb') as key_in:
        key = key_in.read()

cipher_suite = Fernet(key)

# Colors and styles
BG_COLOR = "#f0f0f5"
BUTTON_COLOR = "#4CAF50"
BUTTON_TEXT_COLOR = "#FFFFFF"
FONT = ("Helvetica", 12)

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("400x400")
        self.root.config(bg=BG_COLOR)

        # Checking if master password is already set
        self.check_master_password()

    def check_master_password(self):
        c.execute("SELECT * FROM master_password")
        if c.fetchone():
            self.create_login_screen()
        else:
            self.create_master_password_screen()

    def create_master_password_screen(self):
        # Create master password setup screen
        self.clear_screen()
        self.label = tk.Label(self.root, text="Set Master Password:", bg=BG_COLOR, font=FONT)
        self.label.pack(pady=20)

        self.master_password_entry = tk.Entry(self.root, show='*', font=FONT)
        self.master_password_entry.pack(pady=10)

        self.set_password_button = tk.Button(self.root, text="Set Password", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, 
                                             font=FONT, command=self.set_master_password)
        self.set_password_button.pack(pady=10)

    def set_master_password(self):
        master_password = self.master_password_entry.get()
        if len(master_password) < 8:
            messagebox.showwarning("Weak Password", "Master password must be at least 8 characters long")
        else:
            hashed_password = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())
            c.execute("INSERT INTO master_password (password) VALUES (?)", (hashed_password,))
            conn.commit()
            messagebox.showinfo("Success", "Master password set successfully!")
            self.create_login_screen()

    def create_login_screen(self):
        # Create login screen
        self.clear_screen()
        self.label = tk.Label(self.root, text="Enter Master Password:", bg=BG_COLOR, font=FONT)
        self.label.pack(pady=20)

        self.master_password_entry = tk.Entry(self.root, show='*', font=FONT)
        self.master_password_entry.pack(pady=10)

        self.login_button = tk.Button(self.root, text="Login", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, 
                                      font=FONT, command=self.verify_master_password)
        self.login_button.pack(pady=10)

    def verify_master_password(self):
        entered_password = self.master_password_entry.get()
        c.execute("SELECT password FROM master_password WHERE id=1")
        stored_password = c.fetchone()[0]

        if bcrypt.checkpw(entered_password.encode(), stored_password):
            self.main_screen()
        else:
            messagebox.showwarning("Error", "Incorrect Master Password")

    def main_screen(self):
        # Clear screen and create main menu
        self.clear_screen()

        self.add_button = tk.Button(self.root, text="Add Password", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, 
                                    font=FONT, command=self.add_password_screen)
        self.add_button.pack(pady=10)

        self.view_button = tk.Button(self.root, text="View Passwords", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, 
                                     font=FONT, command=self.view_passwords_screen)
        self.view_button.pack(pady=10)

        self.generate_button = tk.Button(self.root, text="Generate Password", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, 
                                         font=FONT, command=self.generate_password_screen)
        self.generate_button.pack(pady=10)

        # Add export and import buttons
        self.export_button = tk.Button(self.root, text="Export to CSV", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, 
                                       font=FONT, command=self.export_to_csv_screen)
        self.export_button.pack(pady=10)

        self.import_button = tk.Button(self.root, text="Import from CSV", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, 
                                       font=FONT, command=self.import_from_csv)
        self.import_button.pack(pady=10)

    def add_password_screen(self):
        self.clear_screen()

        self.website_label = tk.Label(self.root, text="Website:", bg=BG_COLOR, font=FONT)
        self.website_label.pack(pady=5)

        self.website_entry = tk.Entry(self.root, font=FONT)
        self.website_entry.pack(pady=5)

        self.username_label = tk.Label(self.root, text="Username:", bg=BG_COLOR, font=FONT)
        self.username_label.pack(pady=5)

        self.username_entry = tk.Entry(self.root, font=FONT)
        self.username_entry.pack(pady=5)

        self.password_label = tk.Label(self.root, text="Password:", bg=BG_COLOR, font=FONT)
        self.password_label.pack(pady=5)

        self.password_entry = tk.Entry(self.root, show='*', font=FONT)
        self.password_entry.pack(pady=5)

        # Generate Password Button
        self.generate_button = tk.Button(self.root, text="Generate Password", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, 
                                         font=FONT, command=self.generate_and_insert_password)
        self.generate_button.pack(pady=5)

        self.save_button = tk.Button(self.root, text="Save Password", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, 
                                     font=FONT, command=self.save_password)
        self.save_button.pack(pady=10)

        self.back_button = tk.Button(self.root, text="Back", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, font=FONT, 
                                     command=self.main_screen)
        self.back_button.pack(pady=10)

    def generate_and_insert_password(self):
        # Generate a secure password and insert it into the password entry
        length = 12  # Default length for the generated password
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        generated_password = "".join(random.choice(characters) for _ in range(length))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, generated_password)
        messagebox.showinfo("Password Generated", f"Generated Password: {generated_password}")

    def save_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if website and username and password:
            encrypted_password = cipher_suite.encrypt(password.encode()).decode()
            c.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)", 
                      (website, username, encrypted_password))
            conn.commit()
            messagebox.showinfo("Success", "Password saved successfully!")
        else:
            messagebox.showwarning("Error", "Please fill in all fields")

    def view_passwords_screen(self):
        self.clear_screen()

        c.execute("SELECT * FROM passwords")
        rows = c.fetchall()

        for row in rows:
            website = row[1]
            username = row[2]
            encrypted_password = row[3]
            decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
            password_info = f"Website: {website}, Username: {username}, Password: {decrypted_password}"
            tk.Label(self.root, text=password_info, bg=BG_COLOR, font=FONT).pack()

        self.back_button = tk.Button(self.root, text="Back", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, font=FONT, 
                                     command=self.main_screen)
        self.back_button.pack(pady=10)

    def export_to_csv_screen(self):
        # Export passwords to CSV with master password verification
        self.clear_screen()

        self.label = tk.Label(self.root, text="Enter Master Password to Export:", bg=BG_COLOR, font=FONT)
        self.label.pack(pady=20)

        self.master_password_entry = tk.Entry(self.root, show='*', font=FONT)
        self.master_password_entry.pack(pady=10)

        self.export_button = tk.Button(self.root, text="Export to CSV", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, 
                                       font=FONT, command=self.export_to_csv)
        self.export_button.pack(pady=10)

        self.back_button = tk.Button(self.root, text="Back", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, font=FONT, 
                                     command=self.main_screen)
        self.back_button.pack(pady=10)

    def export_to_csv(self):
        entered_password = self.master_password_entry.get()
        c.execute("SELECT password FROM master_password WHERE id=1")
        stored_password = c.fetchone()[0]

        if bcrypt.checkpw(entered_password.encode(), stored_password):
            filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
            if filepath:
                c.execute("SELECT * FROM passwords")
                rows = c.fetchall()

                with open(filepath, 'w', newline='') as csvfile:
                    csvwriter = csv.writer(csvfile)
                    csvwriter.writerow(['Website', 'Username', 'Password'])

                    for row in rows:
                        website = row[1]
                        username = row[2]
                        decrypted_password = cipher_suite.decrypt(row[3].encode()).decode()
                        csvwriter.writerow([website, username, decrypted_password])

                messagebox.showinfo("Success", "Passwords exported successfully!")
        else:
            messagebox.showwarning("Error", "Incorrect Master Password")

    def import_from_csv(self):
        filepath = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if filepath:
            with open(filepath, 'r') as csvfile:
                csvreader = csv.reader(csvfile)
                next(csvreader)  # Skip header row
                for row in csvreader:
                    if len(row) >= 3:  # Ensure there are at least 3 columns
                        website, username, password = row[:3]  # Take only the first three values
                        encrypted_password = cipher_suite.encrypt(password.encode()).decode()
                        c.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)", 
                                    (website, username, encrypted_password))
                    else:
                        messagebox.showwarning("Error", f"Skipping malformed row: {row}")
                conn.commit()
                messagebox.showinfo("Success", "Passwords imported successfully!")


    def generate_password_screen(self):
        self.clear_screen()

        self.length_label = tk.Label(self.root, text="Password Length:", bg=BG_COLOR, font=FONT)
        self.length_label.pack(pady=5)

        self.length_entry = tk.Entry(self.root, font=FONT)
        self.length_entry.pack(pady=5)

        self.generate_button = tk.Button(self.root, text="Generate", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, font=FONT, 
                                         command=self.generate_password)
        self.generate_button.pack(pady=10)

        self.back_button = tk.Button(self.root, text="Back", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, font=FONT, 
                                     command=self.main_screen)
        self.back_button.pack(pady=10)

    def generate_password(self):
        length = int(self.length_entry.get())
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        password = "".join(random.choice(characters) for _ in range(length))
        self.generated_password_label = tk.Label(self.root, text=f"Generated Password: {password}", bg=BG_COLOR, font=FONT)
        self.generated_password_label.pack()

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()


# Main driver code
root = tk.Tk()
password_manager = PasswordManager(root)
root.mainloop()
