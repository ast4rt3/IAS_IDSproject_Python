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

# Constants
WATCHLIST_FILE = "watchlist.json"
MALICIOUS_PROCESSES = {"trojan.exe", "malware.exe", "keylogger.exe", "ransomware.exe"}

# Ensure script runs as admin
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " " + " ".join(sys.argv), None, 1)
        sys.exit()

# Load watchlist from file
def load_watchlist():
    if os.path.exists(WATCHLIST_FILE):
        with open(WATCHLIST_FILE, "r") as file:
            return set(json.load(file))
    return set(MALICIOUS_PROCESSES)

# Save watchlist to file
def save_watchlist():
    with open(WATCHLIST_FILE, "w") as file:
        json.dump(list(watchlist), file)

# User login function
def user_login():
    username = simpledialog.askstring("Login", "Enter username:")
    password = simpledialog.askstring("Login", "Enter password:", show="*")
    if username != "admin" or password != "password":
        messagebox.showerror("Login Failed", "Invalid credentials. Exiting...")
        sys.exit()

# Get list of running processes
def get_running_processes():
    return [proc.info['name'] for proc in psutil.process_iter(attrs=['name'])]

# Update process list
def update_process_list(filter_text=""):
    process_listbox.delete(0, tk.END)
    for process in get_running_processes():
        if filter_text.lower() in process.lower():
            process_listbox.insert(tk.END, process)

# Update watchlist table
def update_watchlist_table():
    watchlist_listbox.delete(0, tk.END)
    for process in watchlist:
        watchlist_listbox.insert(tk.END, process)

# Kill selected process
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

# Monitor watchlist processes
def watchlist_monitor():
    while True:
        running_processes = get_running_processes()
        for process in watchlist:
            if process in running_processes:
                notification.notify(title="Watchlist Alert", message=f"{process} is running.", timeout=5)
        time.sleep(5)

# Add process to watchlist
def add_to_watchlist():
    selected_process = process_listbox.get(tk.ACTIVE)
    if selected_process:
        watchlist.add(selected_process)
        save_watchlist()
        update_watchlist_table()
        messagebox.showinfo("Watchlist", f"{selected_process} has been added to the watchlist.")
    else:
        messagebox.showwarning("Selection Error", "Please select a process.")

# Add custom process to watchlist
def add_custom_process():
    process_name = simpledialog.askstring("Add Process", "Enter process name:")
    if process_name:
        watchlist.add(process_name)
        save_watchlist()
        update_watchlist_table()
        messagebox.showinfo("Watchlist", f"{process_name} has been added to the watchlist.")

# Run as admin and login
run_as_admin()
user_login()

# Load watchlist
watchlist = load_watchlist()

# Start monitoring thread
watchlist_thread = threading.Thread(target=watchlist_monitor, daemon=True)
watchlist_thread.start()

# UI Setup
root = tk.Tk()
root.title("Process Manager")
root.geometry("500x500")

tk.Label(root, text="Search Process:").pack()
search_entry = tk.Entry(root)
search_entry.pack()
tk.Button(root, text="Search", command=lambda: update_process_list(search_entry.get())).pack(pady=5)

tk.Label(root, text="Running Processes:").pack()
process_listbox = tk.Listbox(root, width=50, height=10)
process_listbox.pack()
update_process_list()

tk.Button(root, text="Kill Process", command=kill_process).pack(pady=5)
tk.Button(root, text="Add to Watchlist", command=add_to_watchlist).pack(pady=5)
tk.Button(root, text="Add Custom Process", command=add_custom_process).pack(pady=5)
tk.Button(root, text="Refresh List", command=update_process_list).pack(pady=5)

tk.Label(root, text="Watchlist:").pack()
watchlist_listbox = tk.Listbox(root, width=50, height=5)
watchlist_listbox.pack()
update_watchlist_table()

root.mainloop()
