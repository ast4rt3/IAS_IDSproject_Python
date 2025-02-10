import psutil
import tkinter as tk
from tkinter import messagebox
from plyer import notification
import threading
import time

# Function to get the list of running processes
def get_running_processes():
    return [proc.info['name'] for proc in psutil.process_iter(attrs=['name'])]

# Function to update the process list
def update_process_list(filter_text=""):
    process_listbox.delete(0, tk.END)
    for process in get_running_processes():
        if filter_text.lower() in process.lower():
            process_listbox.insert(tk.END, process)

# Function to update the watchlist table
def update_watchlist_table():
    watchlist_listbox.delete(0, tk.END)
    for process in watchlist:
        watchlist_listbox.insert(tk.END, process)

# Function to kill a selected process
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

# Function to blocklist a process
def blocklist_process():
    selected_process = process_listbox.get(tk.ACTIVE)
    if selected_process:
        blocklist.add(selected_process)
        messagebox.showinfo("Process Blocked", f"{selected_process} has been added to the blocklist.")
    else:
        messagebox.showwarning("Selection Error", "Please select a process.")

# Function to handle search input
def search_process():
    filter_text = search_entry.get()
    update_process_list(filter_text)

# Function to monitor watchlist processes
def watchlist_monitor():
    while True:
        running_processes = get_running_processes()
        for process in watchlist:
            if process in running_processes:
                notification.notify(
                    title="Watchlist Alert",
                    message=f"{process} is running.",
                    timeout=5
                )
        time.sleep(5)

# Function to add a process to the watchlist
def add_to_watchlist():
    selected_process = process_listbox.get(tk.ACTIVE)
    if selected_process:
        watchlist.add(selected_process)
        update_watchlist_table()
        messagebox.showinfo("Watchlist", f"{selected_process} has been added to the watchlist.")
    else:
        messagebox.showwarning("Selection Error", "Please select a process.")



# Initialize blocklist and watchlist
blocklist = set()
watchlist = set()

# Start watchlist monitoring thread
watchlist_thread = threading.Thread(target=watchlist_monitor, daemon=True)
watchlist_thread.start()

# UI Setup
root = tk.Tk()
root.title("Process Manager")
root.geometry("500x500")

tk.Label(root, text="Search Process:").pack()
search_entry = tk.Entry(root)
search_entry.pack()
tk.Button(root, text="Search", command=search_process).pack(pady=5)

tk.Label(root, text="Running Processes:").pack()
process_listbox = tk.Listbox(root, width=50, height=10)
process_listbox.pack()
update_process_list()

tk.Button(root, text="Kill Process", command=kill_process).pack(pady=5)
tk.Button(root, text="Blocklist Process", command=blocklist_process).pack(pady=5)
tk.Button(root, text="Add to Watchlist", command=add_to_watchlist).pack(pady=5)
tk.Button(root, text="Refresh List", command=update_process_list).pack(pady=5)

tk.Label(root, text="Watchlist:").pack()
watchlist_listbox = tk.Listbox(root, width=50, height=5)
watchlist_listbox.pack()

root.mainloop()
