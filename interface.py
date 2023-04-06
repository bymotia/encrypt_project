import tkinter as tk
from tkinter import messagebox
import json
import os
import RSA
def check_credentials():
    entered_username = username_entry.get()
    entered_password = password_entry.get()

    if os.path.exists("users.json"):
        with open("users.json", "r") as file:
            user_data = json.load(file)

        if entered_username in user_data and user_data[entered_username] == entered_password:
            messagebox.showinfo("Login", "Login successful!")
        else:
            messagebox.showerror("Login", "Incorrect username or password. Please try again.")
    else:
        messagebox.showerror("Login", "No registered users found. Please register first.")

def register_user():
    new_username = new_username_entry.get()
    new_password = new_password_entry.get()

    if not new_username or not new_password:
        messagebox.showerror("Registration", "Please fill in both fields.")
        return

    user_data = {}

    if os.path.exists("users.json"):
        with open("users.json", "r") as file:
            user_data = json.load(file)

    if new_username in user_data:
        messagebox.showerror("Registration", "This username is already taken.")
    else:
        user_data[new_username] = new_password
        with open("users.json", "w") as file:
            json.dump(user_data, file)
        messagebox.showinfo("Registration", "Registration successful! You can now log in.")
        register_window.destroy()

def open_registration_window():
    global register_window, new_username_entry, new_password_entry

    register_window = tk.Toplevel(root)
    register_window.title("Register")

    register_frame = tk.Frame(register_window)
    register_frame.pack(padx=10, pady=10)

    new_username_label = tk.Label(register_frame, text="Username:")
    new_username_label.grid(row=0, column=0, sticky="w")
    new_username_entry = tk.Entry(register_frame)
    new_username_entry.grid(row=0, column=1)

    new_password_label = tk.Label(register_frame, text="Password:")
    new_password_label.grid(row=1, column=0, sticky="w")
    new_password_entry = tk.Entry(register_frame, show="*")
    new_password_entry.grid(row=1, column=1)

    register_button = tk.Button(register_frame, text="Register", command=register_user)
    register_button.grid(row=2, columnspan=2, pady=10)

# Create the main window
root = tk.Tk()
root.title("Login")

# Create a frame for the login form
frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

# Create the username label and entry
username_label = tk.Label(frame, text="Username:")
username_label.grid(row=0, column=0, sticky="w")
username_entry = tk.Entry(frame)
username_entry.grid(row=0, column=1)

# Create the password label and entry
password_label = tk.Label(frame, text="Password:")
password_label.grid(row=1, column=0, sticky="w")
password_entry = tk.Entry(frame, show="*")
password_entry.grid(row=1, column=1)

# Create the login button
login_button = tk.Button(frame, text="Login", command=check_credentials)
login_button.grid(row=2, column=0, pady=10)

# Create the register button
register_button = tk.Button(frame, text="Register", command=open_registration_window)
register_button.grid(row=2, column=1, pady=10)

# Start the main loop
root.mainloop()
