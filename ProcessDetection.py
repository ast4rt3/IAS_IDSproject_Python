import psutil
import tkinter as tk
from tkinter import messagebox, simpledialog
from plyer import notification
import threading
import time
import os
import sys
import json
import ctypes
import ttkbootstrap as ttk
import pystray
from pystray import MenuItem as item
from PIL import Image
from supabase import create_client, Client
import pyotp
import qrcode

# Supabase setup
SUPABASE_URL = "https://pfjrjetfqktqxwgskjms.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBmanJqZXRmcWt0cXh3Z3Nram1zIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDUxNTY0NDAsImV4cCI6MjA2MDczMjQ0MH0.j8JWgIj-2EXiDka_wSP3FBtzUhU_ZzaTlM7PSV5XeVc"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Constants
WATCHLIST_FILE = "watchlist.json"
MALICIOUS_PROCESSES = {"trojan.exe", "malware.exe", "keylogger.exe", "ransomware.exe", "Spotify.exe"}

SECRETS_FILE = "2fa_secrets.json"

def load_secrets():
    if os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_secret(email, secret):
    secrets = load_secrets()
    secrets[email] = secret
    with open(SECRETS_FILE, "w") as f:
        json.dump(secrets, f)

# 2FA Setup
def generate_2fa_secret():
    secret = pyotp.random_base32()  # This will be shared with the user's mobile device
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri("IDS_Project_LawrenceHeras@domain.com", issuer_name="IDS_Prjoject_LawrenceHeras")
    return secret, provisioning_uri

def show_qr_code(provisioning_uri):
    qr = qrcode.make(provisioning_uri)
    qr.show()  # This will display the QR code in the default viewer

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " " + " ".join(sys.argv), None, 1)
        sys.exit()

def load_watchlist():
    if os.path.exists(WATCHLIST_FILE):
        with open(WATCHLIST_FILE, "r") as file:
            return set(json.load(file))
    return set(MALICIOUS_PROCESSES)

def save_watchlist():
    with open(WATCHLIST_FILE, "w") as file:
        json.dump(list(watchlist), file)

def user_login():
    login_window = tk.Tk()
    login_window.title("Login")
    login_window.geometry("300x180")
    login_window.resizable(False, False)

    login_window.update_idletasks()
    screen_width = login_window.winfo_screenwidth()
    screen_height = login_window.winfo_screenheight()
    x = (screen_width - 300) // 2
    y = (screen_height - 150) // 2
    login_window.geometry(f"300x180+{x}+{y}")

    tk.Label(login_window, text="Email:").pack()
    username_entry = tk.Entry(login_window)
    username_entry.pack()

    tk.Label(login_window, text="Password:").pack()
    password_entry = tk.Entry(login_window, show="*")
    password_entry.pack()

    def check_credentials():
        email = username_entry.get()
        password = password_entry.get()

        try:
            result = supabase.auth.sign_in_with_password({"email": email, "password": password})
            if result.user:
                secrets = load_secrets()
                if email in secrets:
                    secret = secrets[email]
                else:
                    secret, provisioning_uri = generate_2fa_secret()
                    show_qr_code(provisioning_uri)
                    messagebox.showinfo("2FA Setup", f"Please scan the QR code to set up 2FA on your app.")
                    save_secret(email, secret)

                # Ask the user for the OTP
                otp_window = tk.Toplevel(login_window)
                otp_window.title("Enter 2FA Code")
                otp_window.geometry("300x100")

                tk.Label(otp_window, text="Enter 2FA Code:").pack()
                otp_entry = tk.Entry(otp_window)
                otp_entry.pack()

                def verify_otp():
                    otp = otp_entry.get()
                    totp = pyotp.TOTP(secret)
                    if totp.verify(otp):
                        messagebox.showinfo("Login Success", f"Welcome {email}!")
                        otp_window.destroy()
                        login_window.destroy()
                    else:
                        messagebox.showerror("Invalid 2FA", "Invalid 2FA code. Please try again.")

                tk.Button(otp_window, text="Verify 2FA", command=verify_otp).pack(pady=5)
                otp_window.protocol("WM_DELETE_WINDOW", lambda: sys.exit())
            else:
                messagebox.showerror("Login Failed", "Invalid credentials.")
                sys.exit()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            sys.exit()

    def signup():
        email = username_entry.get()
        password = password_entry.get()
        try:
            result = supabase.auth.sign_up({"email": email, "password": password})
            messagebox.showinfo("Signup Success", f"Check your email to verify {email}.")
        except Exception as e:
            messagebox.showerror("Signup Failed", str(e))

    tk.Button(login_window, text="Login", command=check_credentials).pack(pady=5)
    tk.Button(login_window, text="Sign Up", command=signup).pack()

    login_window.protocol("WM_DELETE_WINDOW", lambda: sys.exit())
    login_window.mainloop()

def get_running_processes():
    return [proc.info['name'] for proc in psutil.process_iter(attrs=['name'])]

def update_process_list(filter_text=""):
    process_listbox.delete(0, tk.END)
    for process in get_running_processes():
        if filter_text.lower() in process.lower():
            process_listbox.insert(tk.END, process)

def update_watchlist_table():
    watchlist_listbox.delete(0, tk.END)
    for process in watchlist:
        watchlist_listbox.insert(tk.END, process)

def kill_process():
    selected_process = process_listbox.get(tk.ACTIVE)
    if selected_process:
        for process in psutil.process_iter(attrs=['pid', 'name']):
            if process.info['name'] == selected_process:
                try:
                    psutil.Process(process.info['pid']).terminate()
                    messagebox.showinfo("Process Terminated", f"{selected_process} has been stopped.")
                    update_process_list()
                    return
                except psutil.AccessDenied:
                    messagebox.showerror("Access Denied", f"Cannot terminate {selected_process}. Try running as administrator.")
                    return
        messagebox.showwarning("Error", "Process not found.")
    else:
        messagebox.showwarning("Selection Error", "Please select a process.")

def watchlist_monitor():
    while True:
        running_processes = get_running_processes()
        for process in watchlist:
            if process in running_processes:
                notification.notify(title="Watchlist Alert", message=f"{process} is running.", timeout=5)
        time.sleep(5)

def add_to_watchlist():
    selected_process = process_listbox.get(tk.ACTIVE)
    if selected_process:
        watchlist.add(selected_process)
        save_watchlist()
        update_watchlist_table()
        messagebox.showinfo("Watchlist", f"{selected_process} has been added to the watchlist.")
    else:
        messagebox.showwarning("Selection Error", "Please select a process.")

def add_custom_process():
    process_name = simpledialog.askstring("Add Process", "Enter process name:")
    if process_name:
        watchlist.add(process_name)
        save_watchlist()
        update_watchlist_table()
        messagebox.showinfo("Watchlist", f"{process_name} has been added to the watchlist.")

def remove_from_watchlist():
    selected_process = watchlist_listbox.get(tk.ACTIVE)
    if selected_process:
        if selected_process in watchlist:
            watchlist.remove(selected_process)
            save_watchlist()
            update_watchlist_table()
            messagebox.showinfo("Watchlist", f"{selected_process} has been removed from the watchlist.")
        else:
            messagebox.showwarning("Watchlist", "Process not found in the watchlist.")
    else:
        messagebox.showwarning("Selection Error", "Please select a process from the watchlist.")

# Start
run_as_admin()
user_login()
watchlist = load_watchlist()

watchlist_thread = threading.Thread(target=watchlist_monitor, daemon=True)
watchlist_thread.start()

root = ttk.Window(themename="vapor")
root.title("Process Manager")
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
window_width = 500
window_height = 1000
x = 1910 - window_width
y = (1000 - window_height)
root.geometry(f"{window_width}x{window_height}+{x}+{y}")
root.resizable(False, False)

ttk.Label(root, text="Search Process:", bootstyle="light").pack()
search_entry = ttk.Entry(root, bootstyle="dark")
search_entry.pack()
ttk.Button(root, text="Search", bootstyle="primary", command=lambda: update_process_list(search_entry.get())).pack(pady=5)

ttk.Label(root, text="Running Processes:", bootstyle="light").pack()
process_listbox = tk.Listbox(root, width=50, height=10, bg="#282c34", fg="white")
process_listbox.pack()
update_process_list()

ttk.Button(root, text="Kill Process", bootstyle="primary", command=kill_process).pack(pady=5)
ttk.Button(root, text="Add to Watchlist", bootstyle="success", command=add_to_watchlist).pack(pady=5)
ttk.Button(root, text="Remove from Watchlist", bootstyle="danger", command=remove_from_watchlist).pack(pady=5)
ttk.Button(root, text="Add Custom Process", bootstyle="info", command=add_custom_process).pack(pady=5)
ttk.Button(root, text="Refresh List", bootstyle="secondary", command=update_process_list).pack(pady=5)

ttk.Label(root, text="Watchlist:", bootstyle="light").pack()
watchlist_listbox = tk.Listbox(root, width=50, height=5, bg="#282c34", fg="white")
watchlist_listbox.pack()
update_watchlist_table()

root.mainloop()
