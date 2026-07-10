[English](README_en.md) | [中文](README.md)

# Auth-WG (WireGuard Dynamic Authentication Platform)

[![Docker Build](https://github.com/unikgyd/wg-auth/actions/workflows/docker-image.yml/badge.svg)](https://github.com/unikgyd/wg-auth/actions/workflows/docker-image.yml)
[![Linux Client](https://github.com/unikgyd/wg-auth/actions/workflows/build-linux.yml/badge.svg)](https://github.com/unikgyd/wg-auth/actions/workflows/build-linux.yml)

Auth-WG is a high-performance, enterprise-grade dynamic identity authentication system built for WireGuard. It rewrites the control plane from the kernel level entirely in C, replacing the traditional `wg-quick` scripts, and endowing WireGuard with commercial VPN capabilities such as dynamic authentication, leak prevention, and lifecycle management.

## ✨ Core Features

* **Dynamic Key Issuance (PFS)**: Automatically generates a brand new WireGuard keypair in memory upon every login (burn-after-reading). A lost device will never threaten intranet security.
* **Argon2id Top-Tier Protection**: Uses the modern cryptographic gold standard, Argon2id, to hash passwords, rendering rainbow tables and brute-force attacks useless.
* **Auto-Reaper (Dead Session Sweeper)**: After a session expires or abnormally disconnects, a background server thread automatically physically removes the expired public key from the Linux kernel, preventing zombie whitelists.
* **Perfect Compatibility with Static Nodes**: Seamlessly compatible with traditional static configuration files (e.g., fixed servers, side routers). Dynamic and static devices coexist peacefully in the same subnet.
* **Senseless Renewal**: A minimalist client built purely in C automatically initiates `/renew` requests in the background. As long as the computer is on, the VPN never disconnects.
* **Ultra-Lightweight Docker Deployment**: Uses a clean, multi-stage build image. Configuration and databases are mounted via native absolute paths for one-click deployment.

---

## 🚀 1. Server Deployment Guide

### Prerequisites
1. Your server has Docker and Docker Compose installed.
2. Ensure the kernel has loaded the WireGuard module (default in Linux 5.6+).
3. **🚨 CRITICAL**: You MUST allow the WireGuard communication port you plan to use (default **UDP 65432**) in your cloud provider's security group or firewall (e.g., AWS, Azure, Aliyun).

### Step 1: Prepare Configuration Directories
Create directories on the host that align with standard Linux systems to store configurations and the persistent database:
```bash
sudo mkdir -p /etc/vpn-authd /etc/wireguard /var/lib/vpn-authd
```

### Step 2: Write Configuration Files
Copy the templates from this project to create your actual configuration files:
```bash
sudo cp authd.conf.example /etc/vpn-authd/authd.conf
sudo cp wg0.conf.example /etc/wireguard/wg0.conf
```
*Make sure to use `wg genkey` to generate the server's private key and insert it into `wg0.conf`. Also, modify the subnets and IP addresses in both configuration files according to your actual network planning!*

### Step 3: Start the Container
Execute the following in the project root directory:
```bash
docker compose up -d --build
```
> **⚠️ Note for CentOS / RHEL / Fedora Users (SELinux Trap)**
> If your system has SELinux enabled, Docker directory mounting will be intercepted, causing read failures. Please modify `docker-compose.yml` and append `:z` or `:Z` to the mount paths (e.g., `- /etc/vpn-authd:/etc/vpn-authd:z`).

---

## 👥 2. Account Management

Account management is handled via the built-in `vpn-add-user` tool inside the container, which directly operates on the mounted SQLite database.

**Add or Reset a User Password:**
```bash
docker exec -it vpn-authd vpn-add-user <username>
```
*Example: `docker exec -it vpn-authd vpn-add-user alice` (It will prompt you to enter a password after execution)*

---

## 💻 3. Client Usage Guide (Linux)

The client is an independent binary written purely in C. There is no need to install bloated WireGuard client software; it automatically takes over kernel-level network interface creation and routing configuration.

### Compile the Client (Linux)
On the computer that needs to connect to the VPN, install the build dependencies and compile:
```bash
# Ubuntu / Debian
sudo apt-get install -y cmake build-essential libcurl4-openssl-dev libcjson-dev

mkdir -p build && cd build
cmake ..
make
```

### Login and Connect
Execute the client program (MUST use `sudo` due to network interface creation and kernel routing table modifications):
```bash
sudo ./client/vpn-client login <username> <password> --server https://<Server_API_IP_or_Domain>:8443
```
*(If the server does not have a TLS certificate configured, change https to http, and append `--insecure` at the end)*

As long as you do not close this terminal, the client will silently guard in the background and automatically renew the lease before expiration.

### Check Status
Open a new terminal to check upstream/downstream traffic and remaining time-to-live at any time:
```bash
sudo ./client/vpn-client status
```

### Logout and Destroy
Press `Ctrl+C` in the terminal running `login`, or manually execute logout:
```bash
sudo ./client/vpn-client logout
```
The client will notify the server to immediately clean up the kernel whitelist and completely destroy the local `wg-vpn` virtual network interface.

---

## 🪟 4. Windows Client Guide (GUI)

The Windows client consists of two parts: the **Core Dynamic Library (`authwg.dll`)** and the **Minimalist Lazarus GUI**.

### Compile the Core Library (C++)
Compile `authwg.dll` on a PC with Visual Studio or MinGW installed:
```bash
cd windows/client
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release
```
This will generate an extremely compact, zero-dependency `authwg.dll`.

### Compile and Package the Single-File Client (Lazarus)
1. Ensure **Lazarus (Free Pascal)** is installed.
2. Copy the `authwg.dll` compiled in the previous step, along with the `wireguard.exe` extracted from the official WireGuard installer, **into the `windows-ui` directory**.
3. Open the `windows-ui/authwgui.lpi` project in Lazarus.
4. From the menu bar, select **Project -> Project Options**. Under **Debugging**, disable all debugging information. Under **Compilation and Linking**, check both `Smart Linkable` and `Strip symbols`.
5. Press **Shift + F9** to build.

Lazarus will automatically trigger the resource script, packaging the `.dll` and `.exe` into the final `authwgui.exe`, producing a perfect, standalone portable client of just a dozen megabytes!

### Using the Windows Client
1. Double-click to run `authwgui.exe` (the program will automatically request Administrator privileges, which is required to install the virtual network adapter).
2. Enter the server URL (e.g., `https://198.51.100.1:8443`), username, and password.
3. Click **Connect**.
4. When exiting, **please right-click the icon in the system tray at the bottom right and click "Exit Auth-WG"**. This will gracefully disconnect and physically destroy the background virtual network adapter. Clicking the X in the top right corner only hides the window.
