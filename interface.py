import tkinter as tk
from tkinter import messagebox
import json
import os


def get_user_data_path():
    user_dir = "users"
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)

    return os.path.join(user_dir, "users.json")


def check_credentials(username_entry, password_entry):
    entered_username = username_entry.get()
    entered_password = password_entry.get()

    user_data_path = get_user_data_path()

    if os.path.exists(user_data_path):
        with open(user_data_path, "r") as file:
            user_data = json.load(file)

        if entered_username in user_data and user_data[entered_username] == entered_password:
            messagebox.showinfo("Login", "Login successful!")
        else:
            messagebox.showerror("Login", "Incorrect username or password. Please try again.")
    else:
        messagebox.showerror("Login", "No registered users found. Please register first.")


def register_user(new_username_entry, new_password_entry):
    new_username = new_username_entry.get()
    new_password = new_password_entry.get()

    if not new_username or not new_password:
        messagebox.showerror("Registration", "Please fill in both fields.")
        return

    user_data = {}
    user_data_path = get_user_data_path()

    if os.path.exists(user_data_path):
        with open(user_data_path, "r") as file:
            user_data = json.load(file)

    if new_username in user_data:
        messagebox.showerror("Registration", "This username is already taken.")
    else:
        user_data[new_username] = new_password
        with open(user_data_path, "w") as file:
            json.dump(user_data, file)
        messagebox.showinfo("Registration", "Registration successful! You can now log in.")
        register_window.destroy()


def open_registration_window(username_entry, password_entry):
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

    register_button = tk.Button(register_frame, text="Register",
                                command=lambda: register_user(new_username_entry, new_password_entry))
    register_button.grid(row=2, columnspan=2, pady=10)


def create_login_frame(parent):
    frame = tk.Frame(parent)
    frame.pack(padx=10, pady=10)

    username_label, username_entry = create_label_and_entry(frame, "Username:", 0)
    password_label, password_entry = create_label_and_entry(frame, "Password:", 1, show="*")

    login_button = tk.Button(frame, text="Login", command=lambda: check_credentials(username_entry, password_entry))
    login_button.grid(row=2, column=0, pady=10)

    register_button = tk.Button(frame, text="Register",
                                command=lambda: open_registration_window(username_entry, password_entry))
    register_button.grid(row=2, column=1, pady=10)

    return frame


def create_label_and_entry(parent, text, row, **entry_kwargs):
    label = tk.Label(parent, text=text)
    label.grid(row=row, column=0, sticky="w")

    entry = tk.Entry(parent, **entry_kwargs)
    entry.grid(row=row, column=1)

    return label, entry


def create_main_window():
    root = tk.Tk()
    root.title("Login")

    return root

root = create_main_window()
frame = create_login_frame(root)

root.mainloop()
