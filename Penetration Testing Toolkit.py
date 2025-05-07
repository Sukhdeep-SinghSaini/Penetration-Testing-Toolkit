import socket, threading, paramiko, requests, json
import ttkbootstrap as tb
import matplotlib.pyplot as plt

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, filedialog, messagebox
except ModuleNotFoundError:
    raise ImportError("tkinter is not available.")

try:
    import whois
except ModuleNotFoundError:
    whois = None

def threaded(func):
    def wrapper(*args, **kwargs):
        threading.Thread(target=func, args=args, kwargs=kwargs, daemon=True).start()
    return wrapper

# Main app with bright theme
app = tb.Window(themename="yeti")
app.title("🛠️ Penetration Testing Toolkit")
app.geometry("1000x800")

title_label = ttk.Label(app, text="🛠️Penetration Testing Toolkit", font=("Helvetica", 22, "bold"), foreground="#007BFF")
title_label.pack(pady=(15,5))

frame_target = tb.Frame(app)
frame_target.pack(fill="x", padx=20, pady=10)
ttk.Label(frame_target, text="🎯 Target IP / URL:").pack(side="left")
target_entry = tb.Entry(frame_target, width=50)
target_entry.pack(side="left", padx=10)

tabs = tb.Notebook(app)
tabs.pack(fill="both", expand=True, padx=15, pady=10)

tab_ports = tb.Frame(tabs)
tab_ssh = tb.Frame(tabs)
tab_whois = tb.Frame(tabs)
tab_dirs = tb.Frame(tabs)
tabs.add(tab_ports, text="🛰️Port Scanner")
tabs.add(tab_ssh, text="🔐 SSH Brute Force")
tabs.add(tab_whois, text="🌐 WHOIS Lookup")
tabs.add(tab_dirs, text="📂 Dir Brute Force")

def make_tab_ui(tab, bg_color):
    frame = tb.Frame(tab)
    frame.pack(fill="x", pady=5)
    progress = tk.DoubleVar()
    bar = tb.Progressbar(tab, variable=progress, maximum=100, bootstyle="info-striped")
    bar.pack(fill="x", padx=10, pady=5)
    output = scrolledtext.ScrolledText(tab, height=18, font=("Courier", 10), bg=bg_color, fg="#222", insertbackground="black", borderwidth=2, relief="groove")
    output.pack(fill="both", expand=True, padx=10, pady=5)
    return output, progress

output_ports, progress_ports = make_tab_ui(tab_ports, "#e7f4fa")
output_ssh, progress_ssh = make_tab_ui(tab_ssh, "#fff4e6")
output_whois, progress_whois = make_tab_ui(tab_whois, "#f1f8e9")
output_dirs, progress_dirs = make_tab_ui(tab_dirs, "#fce4ec")

def log_output(output_box, msg):
    output_box.configure(state='normal')
    output_box.insert(tk.END, msg + '\n')
    output_box.configure(state='disabled')
    output_box.see(tk.END)

@threaded
def port_scan():
    host = target_entry.get()
    open_ports = []
    scanned = 0
    total = 1005
    log_output(output_ports, f"🔍 Scanning {host} for open ports...")
    for port in range(20, 1025):
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

tb.Button(tab_ports, text="🚀 Start Scan", command=port_scan, bootstyle="success").pack(pady=5)

# SSH Tab
ssh_user_entry = tb.Entry(tab_ssh, width=30)
ssh_user_entry.pack(pady=(5, 0))
ttk.Label(tab_ssh, text="👤 SSH Username").pack()

ssh_wordlist_entry = tb.Entry(tab_ssh, width=40)
ssh_wordlist_entry.pack(pady=(5, 0))
ttk.Label(tab_ssh, text="📂 Wordlist Path").pack()

def browse_ssh_wordlist():
    path = filedialog.askopenfilename()
    ssh_wordlist_entry.delete(0, tk.END)
    ssh_wordlist_entry.insert(0, path)

tb.Button(tab_ssh, text="📁 Browse", command=browse_ssh_wordlist, bootstyle="secondary").pack(pady=2)

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

tb.Button(tab_ssh, text="🔥 Start SSH Brute", command=ssh_brute, bootstyle="warning").pack(pady=5)

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

tb.Button(tab_whois, text="🌐 Run WHOIS", command=run_whois, bootstyle="info").pack(pady=5)

dir_wordlist_entry = tb.Entry(tab_dirs, width=40)
dir_wordlist_entry.pack(pady=(5, 0))
ttk.Label(tab_dirs, text="📂 Wordlist Path").pack()

def browse_dir_wordlist():
    path = filedialog.askopenfilename()
    dir_wordlist_entry.delete(0, tk.END)
    dir_wordlist_entry.insert(0, path)

tb.Button(tab_dirs, text="📁 Browse", command=browse_dir_wordlist, bootstyle="secondary").pack(pady=2)

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

tb.Button(tab_dirs, text="🔍 Start Dir Brute", command=dir_brute, bootstyle="danger").pack(pady=5)

# Save/Load session
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

btn_frame = tb.Frame(app)
btn_frame.pack(pady=5)
tb.Button(btn_frame, text="💾 Save Session", command=save_session, bootstyle="secondary-outline").pack(side="left", padx=5)
tb.Button(btn_frame, text="📂 Load Session", command=load_session, bootstyle="secondary-outline").pack(side="left", padx=5)

app.mainloop()
