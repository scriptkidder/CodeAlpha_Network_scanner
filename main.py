import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog
from scapy.all import ARP, Ether, srp, conf, ICMP, IP, sr1
import psutil
import requests
import threading
import speedtest

# Helper functions
def get_interfaces():
    interfaces = [iface for iface in psutil.net_if_addrs()]
    return interfaces

def get_ip_range(interface):
    addrs = psutil.net_if_addrs().get(interface, [])
    for addr in addrs:
        if addr.family.name == 'AF_INET':
            ip = addr.address
            netmask = addr.netmask
            if ip and netmask:
                subnet = sum([bin(int(x)).count('1') for x in netmask.split('.')])
                return f"{ip}/{subnet}"
    return None

def lookup_mac(mac_address):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}")
        if response.status_code == 200:
            return response.text
    except Exception:
        pass
    return "Unknown"

def ping_device(ip):
    try:
        pkt = IP(dst=ip)/ICMP()
        reply = sr1(pkt, timeout=2, verbose=False)
        if reply:
            return True
    except Exception:
        pass
    return False

def scan_network():
    def thread_scan():
        selected_interface = combo_interface.get()
        progress_var.set(0)
        progress_bar.update()

        if not selected_interface:
            messagebox.showerror("Error", "Please select a network interface.")
            return

        target_ip = get_ip_range(selected_interface)

        if not target_ip:
            messagebox.showerror("Error", "Unable to determine IP range for the selected interface.")
            return

        try:
            conf.iface = selected_interface
            arp = ARP(pdst=target_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            result = srp(packet, timeout=2, verbose=False)[0]

            devices = []
            total_devices = len(result)

            for i, (sent, received) in enumerate(result):
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'manufacturer': lookup_mac(received.hwsrc),
                    'reachable': ping_device(received.psrc)
                })
                progress_var.set((i + 1) / total_devices * 100)
                progress_bar.update()

            text_output.delete(1.0, tk.END)
            text_output.insert(tk.END, f"{'IP Address':<20}{'MAC Address':<20}{'Manufacturer':<20}{'Reachable':<10}\n")
            text_output.insert(tk.END, f"{'-' * 70}\n")

            for device in devices:
                reachable = "Yes" if device['reachable'] else "No"
                text_output.insert(tk.END, f"{device['ip']:<20}{device['mac']:<20}{device['manufacturer']:<20}{reachable:<10}\n")

            if not devices:
                text_output.insert(tk.END, "No devices found.")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    threading.Thread(target=thread_scan).start()

def save_results():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(text_output.get(1.0, tk.END))
        messagebox.showinfo("Saved", "Results saved successfully!")

def clear_output():
    text_output.delete(1.0, tk.END)

def update_theme():
    current_bg = root.cget("bg")
    if current_bg == "#282C34":
        root.configure(bg="white")
        for widget in root.winfo_children():
            if isinstance(widget, (tk.Label, tk.Button, tk.Frame, ttk.Combobox)):
                widget.configure(bg="white", fg="black")
    else:
        root.configure(bg="#282C34")
        for widget in root.winfo_children():
            if isinstance(widget, (tk.Label, tk.Button, tk.Frame, ttk.Combobox)):
                widget.configure(bg="#282C34", fg="white")

def manual_scan():
    ip_range = entry_ip_range.get().strip()
    if not ip_range:
        text_output.insert(tk.END, "Please enter a valid IP range.\n")
        text_output.see(tk.END)
        return

    try:
        # Start scanning the entered IP range
        text_output.insert(tk.END, f"Starting manual scan for IP range: {ip_range}\n")
        text_output.see(tk.END)
        
        # Simulate a manual scan process (you can integrate your actual scan logic here)
        text_output.insert(tk.END, "Scanning network...\n")
        text_output.see(tk.END)
        
        # Perform the network speed check after the scan
        text_output.insert(tk.END, "Checking network speed...\n")
        text_output.see(tk.END)
        
        # Use the same speedtest logic from `check_network_speed`
        st = speedtest.Speedtest()
        st.get_best_server()
        download_speed = st.download() / 1_000_000  # Convert to Mbps
        upload_speed = st.upload() / 1_000_000      # Convert to Mbps

        # Display scan and speed results
        text_output.insert(tk.END, f"Manual scan completed for {ip_range}.\n")
        text_output.insert(tk.END, f"Download Speed: {download_speed:.2f} Mbps\n")
        text_output.insert(tk.END, f"Upload Speed: {upload_speed:.2f} Mbps\n")
        text_output.insert(tk.END, "-"*50 + "\n")
        text_output.see(tk.END)
    except Exception as e:
        text_output.insert(tk.END, f"Error during manual scan or speed test: {str(e)}\n")
        text_output.see(tk.END)


def check_network_speed():
    try:
        # Display progress in the output area
        text_output.insert(tk.END, "Checking network speed...\n")
        text_output.see(tk.END)
        
        # Initialize speedtest
        st = speedtest.Speedtest()
        st.get_best_server()

        # Measure download and upload speed
        download_speed = st.download() / 1_000_000  # Convert to Mbps
        upload_speed = st.upload() / 1_000_000      # Convert to Mbps
        
        # Display results
        text_output.insert(tk.END, f"Download Speed: {download_speed:.2f} Mbps\n")
        text_output.insert(tk.END, f"Upload Speed: {upload_speed:.2f} Mbps\n")
        text_output.insert(tk.END, "-"*50 + "\n")
        text_output.see(tk.END)
    except Exception as e:
        # Display any error
        text_output.insert(tk.END, f"Error: {str(e)}\n")
        text_output.see(tk.END)

# GUI Setup
root = tk.Tk()
root.title("Network Scanner")
root.geometry("850x750")
root.configure(bg="#282C34")

frame_top = tk.Frame(root, bg="#282C34")
frame_top.pack(pady=10)

label_interface = tk.Label(frame_top, text="Select Network Interface:", bg="#282C34", fg="white")
label_interface.pack(side=tk.LEFT, padx=5)
# Get available network interfaces
interfaces = get_interfaces()

# Top Frame for Auto Scan and Related Controls
frame_top = tk.Frame(root, bg="#282C34")
frame_top.pack(pady=10, padx=10, fill=tk.X)

# Network Interface Dropdown
combo_interface = ttk.Combobox(frame_top, values=interfaces, state="readonly", width=40)
combo_interface.pack(side=tk.LEFT, padx=5)
combo_interface.set(interfaces[0] if interfaces else "")

# Buttons in the Top Frame
btn_scan = tk.Button(frame_top, text="Auto Scan", command=scan_network, bg="#61AFEF", fg="white", width=12)
btn_scan.pack(side=tk.LEFT, padx=5)

btn_clear = tk.Button(frame_top, text="Clear", command=clear_output, bg="#E06C75", fg="white", width=10)
btn_clear.pack(side=tk.LEFT, padx=5)

btn_save = tk.Button(frame_top, text="Save Results", command=save_results, bg="#98C379", fg="white", width=12)
btn_save.pack(side=tk.LEFT, padx=5)

btn_speed = tk.Button(frame_top, text="Network Speed", command=check_network_speed, bg="#D19A66", fg="white", width=12)
btn_speed.pack(side=tk.LEFT, padx=5)

btn_theme = tk.Button(frame_top, text="Toggle Theme", command=update_theme, bg="#C678DD", fg="white", width=12)
btn_theme.pack(side=tk.LEFT, padx=5)

# Manual Scan Frame
frame_manual = tk.Frame(root, bg="#282C34")
frame_manual.pack(pady=10, padx=10, fill=tk.X)

# IP Range Entry
entry_ip_range = tk.Entry(frame_manual, width=30)
entry_ip_range.pack(side=tk.LEFT, padx=5)

# Manual Scan Button
btn_manual_scan = tk.Button(frame_manual, text="Manual Scan", command=manual_scan, bg="#C678DD", fg="white", width=12)
btn_manual_scan.pack(side=tk.LEFT, padx=5)

btn_manual_speed_scan = tk.Button(frame_manual, text="Manual + Speed", command=manual_scan, bg="#56B6C2", fg="white", width=14)
btn_manual_speed_scan.pack(side=tk.LEFT, padx=5)

# Toggle Theme Button (Added in Manual Frame)
btn_theme_manual = tk.Button(frame_manual, text="Toggle Theme", command=update_theme, bg="#56B6C2", fg="white", width=12)
btn_theme_manual.pack(side=tk.LEFT, padx=5)

# Output Display Frame
frame_output = tk.Frame(root, bg="#282C34")
frame_output.pack(pady=10, fill=tk.BOTH, expand=True)

# Scrolled Text for Output
text_output = scrolledtext.ScrolledText(frame_output, wrap=tk.WORD, width=100, height=30, bg="#1E2127", fg="white", font=("Consolas", 10))
text_output.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# Progress Bar
progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100)
progress_bar.pack(fill=tk.X, padx=10, pady=5)

# Start the Application
root.mainloop()

