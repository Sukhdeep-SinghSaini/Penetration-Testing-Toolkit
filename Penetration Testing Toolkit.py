# Import necessary libraries
import socket, threading, paramiko, requests, json  # Networking, threading, SSH, HTTP requests, and JSON handling
import ttkbootstrap as tb                          # Enhanced GUI theming using ttkbootstrap
import matplotlib.pyplot as plt                    # For drawing port scan heatmaps

# Attempt to import tkinter and necessary GUI components
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, filedialog, messagebox
except ModuleNotFoundError:
    raise ImportError("tkinter is not available.")

# Try to import 'whois' library for domain lookup
try:
    import whois
except ModuleNotFoundError:
    whois = None  # Fallback if 'whois' module is not installed

# Decorator to run functions in a new thread
def threaded(func):
    def wrapper(*args, **kwargs):
        threading.Thread(target=func, args=args, kwargs=kwargs, daemon=True).start()
    return wrapper

# Initialize main application window with 'yeti' theme
app = tb.Window(themename="yeti")
app.title("🛠️ Penetration Testing Toolkit")
app.geometry("1000x800")

# Header label
title_label = ttk.Label(app, text="🛠️Penetration Testing Toolkit", font=("Helvetica", 22, "bold"), foreground="#007BFF")
title_label.pack(pady=(15,5))

# Target input frame
frame_target = tb.Frame(app)
frame_target.pack(fill="x", padx=20, pady=10)
ttk.Label(frame_target, text="🎯 Target IP / URL:").pack(side="left")
target_entry = tb.Entry(frame_target, width=50)
target_entry.pack(side="left", padx=10)

# Tabbed interface for different tools
tabs = tb.Notebook(app)
tabs.pack(fill="both", expand=True, padx=15, pady=10)

# Creating individual tabs
tab_ports = tb.Frame(tabs)
tab_ssh = tb.Frame(tabs)
tab_whois = tb.Frame(tabs)
tab_dirs = tb.Frame(tabs)

# Adding tabs to the notebook
tabs.add(tab_ports, text="🛰️Port Scanner")
tabs.add(tab_ssh, text="🔐 SSH Brute Force")
tabs.add(tab_whois, text="🌐 WHOIS Lookup")
tabs.add(tab_dirs, text="📂 Dir Brute Force")

# Function to build tab UI with progress bar and output box
def make_tab_ui(tab, bg_color):
    frame = tb.Frame(tab)
    frame.pack(fill="x", pady=5)
    progress = tk.DoubleVar()
    bar = tb.Progressbar(tab, variable=progress, maximum=100, bootstyle="info-striped")
    bar.pack(fill="x", padx=10, pady=5)
    output = scrolledtext.ScrolledText(tab, height=18, font=("Courier", 10), bg=bg_color, fg="#222", insertbackground="black", borderwidth=2, relief="groove")
    output.pack(fill="both", expand=True, padx=10, pady=5)
    return output, progress

# Initializing UI for each tab
output_ports, progress_ports = make_tab_ui(tab_ports, "#e7f4fa")
output_ssh, progress_ssh = make_tab_ui(tab_ssh, "#fff4e6")
output_whois, progress_whois = make_tab_ui(tab_whois, "#f1f8e9")
output_dirs, progress_dirs = make_tab_ui(tab_dirs, "#fce4ec")

# Function to display messages in output box
def log_output(output_box, msg):
    output_box.configure(state='normal')
    output_box.insert(tk.END, msg + '\n')
    output_box.configure(state='disabled')
    output_box.see(tk.END)

# Port scanning function using socket
@threaded
def port_scan():
    host = target_entry.get()
    open_ports = []
    scanned = 0
    total = 1005  # Number of ports to scan
    log_output(output_ports, f"🔍 Scanning {host} for open ports...")
    for port in range(20, 1025):  # Scan common ports
        try:
            with socket.socket() as s:
                s.settimeout(0.2)
                s.connect((host, port))
                open_ports.append(port)
                log_output(output_ports, f"[OPEN] Port {port}")
        except:
            pass
        scanned += 1
        progress_ports.set((scanned / total) * 100)
    log_output(output_ports, "✅ Scan complete.")
    draw_heatmap(open_ports)

# Visualization: draw heatmap of open ports using matplotlib
def draw_heatmap(open_ports):
    if not open_ports: return
    plt.figure(figsize=(12, 1))
    for p in open_ports:
        plt.barh(0, 1, left=p, color='lime')
    plt.title("Port Scan Heatmap")
    plt.yticks([])
    plt.xlabel("Ports")
    plt.xlim(0, 1025)
    plt.tight_layout()
    plt.show()

# Button to start port scanning
tb.Button(tab_ports, text="🚀 Start Scan", command=port_scan, bootstyle="success").pack(pady=5)

# SSH brute force input fields
ssh_user_entry = tb.Entry(tab_ssh, width=30)
ssh_user_entry.pack(pady=(5, 0))
ttk.Label(tab_ssh, text="👤 SSH Username").pack()

ssh_wordlist_entry = tb.Entry(tab_ssh, width=40)
ssh_wordlist_entry.pack(pady=(5, 0))
ttk.Label(tab_ssh, text="📂 Wordlist Path").pack()

# File browser for SSH wordlist
def browse_ssh_wordlist():
    path = filedialog.askopenfilename()
    ssh_wordlist_entry.delete(0, tk.END)
    ssh_wordlist_entry.insert(0, path)

tb.Button(tab_ssh, text="📁 Browse", command=browse_ssh_wordlist, bootstyle="secondary").pack(pady=2)

# SSH brute force using paramiko
@threaded
def ssh_brute():
    host = target_entry.get()
    user = ssh_user_entry.get()
    wordlist = ssh_wordlist_entry.get()
    try:
        with open(wordlist, 'r') as file:
            lines = file.readlines()
        total = len(lines)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for i, line in enumerate(lines):
            password = line.strip()
            try:
                ssh.connect(host, username=user, password=password, timeout=3)
                log_output(output_ssh, f"✅ Found password: {password}")
                return
            except paramiko.AuthenticationException:
                log_output(output_ssh, f"❌ Wrong: {password}")
            except Exception as e:
                log_output(output_ssh, f"[ERROR] {e}")
            progress_ssh.set((i+1)/total*100)
        log_output(output_ssh, "❌ Password not found.")
    except FileNotFoundError:
        log_output(output_ssh, "[ERROR] Wordlist not found.")

# Button to start SSH brute force attack
tb.Button(tab_ssh, text="🔥 Start SSH Brute", command=ssh_brute, bootstyle="warning").pack(pady=5)

# WHOIS lookup functionality
@threaded
def run_whois():
    domain = target_entry.get()
    if not whois:
        log_output(output_whois, "[ERROR] WHOIS module not available.")
        return
    try:
        result = whois.whois(domain)
        log_output(output_whois, str(result))
    except Exception as e:
        log_output(output_whois, f"[ERROR] {e}")

# Button to run WHOIS lookup
tb.Button(tab_whois, text="🌐 Run WHOIS", command=run_whois, bootstyle="info").pack(pady=5)

# Directory brute force UI
dir_wordlist_entry = tb.Entry(tab_dirs, width=40)
dir_wordlist_entry.pack(pady=(5, 0))
ttk.Label(tab_dirs, text="📂 Wordlist Path").pack()

# File browser for directory brute-force wordlist
def browse_dir_wordlist():
    path = filedialog.askopenfilename()
    dir_wordlist_entry.delete(0, tk.END)
    dir_wordlist_entry.insert(0, path)

tb.Button(tab_dirs, text="📁 Browse", command=browse_dir_wordlist, bootstyle="secondary").pack(pady=2)

# Directory brute force implementation using HTTP GET requests
@threaded
def dir_brute():
    url = target_entry.get()
    wordlist = dir_wordlist_entry.get()
    try:
        with open(wordlist, 'r') as f:
            lines = f.readlines()
        total = len(lines)
        for i, line in enumerate(lines):
            path = line.strip()
            full_url = f"{url.rstrip('/')}/{path}"
            try:
                r = requests.get(full_url, timeout=2)
                if r.status_code == 200:
                    log_output(output_dirs, f"✅ Found: {full_url}")
            except:
                pass
            progress_dirs.set((i+1)/total*100)
    except Exception as e:
        log_output(output_dirs, f"[ERROR] {e}")

# Button to start directory brute-force
tb.Button(tab_dirs, text="🔍 Start Dir Brute", command=dir_brute, bootstyle="danger").pack(pady=5)

# Session save/load functionality
def save_session():
    path = filedialog.asksaveasfilename(defaultextension=".json")
    if not path: return
    data = {
        "target": target_entry.get(),
        "ssh_user": ssh_user_entry.get(),
        "ssh_wordlist": ssh_wordlist_entry.get(),
        "dir_wordlist": dir_wordlist_entry.get()
    }
    with open(path, "w") as f:
        json.dump(data, f)
    messagebox.showinfo("Saved", "Session saved.")

def load_session():
    path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
    if not path: return
    with open(path, "r") as f:
        data = json.load(f)
    target_entry.delete(0, tk.END)
    target_entry.insert(0, data.get("target", ""))
    ssh_user_entry.delete(0, tk.END)
    ssh_user_entry.insert(0, data.get("ssh_user", ""))
    ssh_wordlist_entry.delete(0, tk.END)
    ssh_wordlist_entry.insert(0, data.get("ssh_wordlist", ""))
    dir_wordlist_entry.delete(0, tk.END)
    dir_wordlist_entry.insert(0, data.get("dir_wordlist", ""))

# Buttons for saving/loading session
btn_frame = tb.Frame(app)
btn_frame.pack(pady=5)
tb.Button(btn_frame, text="💾 Save Session", command=save_session, bootstyle="secondary-outline").pack(side="left", padx=5)
tb.Button(btn_frame, text="📂 Load Session", command=load_session, bootstyle="secondary-outline").pack(side="left", padx=5)

# Run the GUI event loop
app.mainloop()
