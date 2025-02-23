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

# Constants
WATCHLIST_FILE = "watchlist.json"
MALICIOUS_PROCESSES = {"trojan.exe", "malware.exe", "keylogger.exe", "ransomware.exe", "Spotify.exe"}

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
    login_window = tk.Tk()
    login_window.title("Login")
    login_window.geometry("300x150")
    login_window.resizable(False, False)
    
    # Center window on screen
    login_window.update_idletasks()
    screen_width = login_window.winfo_screenwidth()
    screen_height = login_window.winfo_screenheight()
    x = (screen_width - 300) // 2
    y = (screen_height - 150) // 2
    login_window.geometry(f"300x150+{x}+{y}")

    tk.Label(login_window, text="Username:").pack()
    username_entry = tk.Entry(login_window)
    username_entry.pack()

    tk.Label(login_window, text="Password:").pack()
    password_entry = tk.Entry(login_window, show="*")
    password_entry.pack()

    def check_credentials():
        username = username_entry.get()
        password = password_entry.get()
        if username != "admin" or password != " ":
            messagebox.showerror("Login Failed", "Invalid credentials. Exiting...")
            sys.exit()
        login_window.destroy()

    tk.Button(login_window, text="Login", command=check_credentials).pack(pady=5)

    login_window.protocol("WM_DELETE_WINDOW", lambda: sys.exit())  # Prevent bypassing login
    login_window.mainloop()


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
        time.sleep(60)

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

# Remove process from watchlist
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




# Run as admin and login
run_as_admin()
user_login()

# Load watchlist
watchlist = load_watchlist()

# Start monitoring thread
watchlist_thread = threading.Thread(target=watchlist_monitor, daemon=True)
watchlist_thread.start()

# UI Setup
root = ttk.Window(themename="solar")
root.title("Process Manager")
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
window_width = 500
window_height = 1000

x = 1910 - window_width  
y = (1000 - window_height)    

root.geometry(f"{window_width}x{window_height}+{x}+{y}")

root.resizable(False, False)



# Widgets with themed styling
ttk.Label(root, text="Search Process:", bootstyle="light").pack()
search_entry = ttk.Entry(root, bootstyle="dark")
search_entry.pack()
ttk.Button(root, text="Search", bootstyle="primary", command=lambda: update_process_list(search_entry.get())).pack(pady=5)

ttk.Label(root, text="Running Processes:", bootstyle="light").pack()
process_listbox = tk.Listbox(root, width=50, height=10, bg="#282c34", fg="white")
process_listbox.pack()
update_process_list()

ttk.Button(root, text="Kill Process", bootstyle="danger", command=kill_process).pack(pady=5)
ttk.Button(root, text="Add to Watchlist", bootstyle="success", command=add_to_watchlist).pack(pady=5)
ttk.Button(root, text="Remove from Watchlist", bootstyle="danger", command=remove_from_watchlist).pack(pady=5)
ttk.Button(root, text="Add Custom Process", bootstyle="info", command=add_custom_process).pack(pady=5)
ttk.Button(root, text="Refresh List", bootstyle="secondary", command=update_process_list).pack(pady=5)


ttk.Label(root, text="Watchlist:", bootstyle="light").pack()
watchlist_listbox = tk.Listbox(root, width=50, height=5, bg="#282c34", fg="white")
watchlist_listbox.pack()
update_watchlist_table()

root.mainloop()
