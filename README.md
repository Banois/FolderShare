## 📦 How to Install FolderShare

### Prerequisites

Before starting, make sure you have:
- Python installed (along with all required dependencies)
- Internet access
- Terminal / command-line access

---

### Local Testing (Strongly Recommended)

Before exposing your server to the public internet, you should always test locally.

1. Start the server
2. Open the client
3. Attempt to connect locally

IMPORTANT:
If you are running BOTH the server and a client on the SAME computer, do NOT use the LAN IP.

Use:
http://127.0.0.1:9000

Instead of:
http://192.168.x.x:9000

This prevents IP conflicts and ONLY applies to the computer running the server.

---

## 🌍 Exposing FolderShare to the Internet (Portmap.io)

If you want FolderShare accessible from anywhere on the web without router port forwarding, Portmap.io is recommended.

---

### Portmap.io Setup

1. Go to https://portmap.io
2. Create an account and log in
3. Go to Configurations
4. Create a new configuration:
   - Name: anything you want
   - Protocol: TCP
5. Generate and download the configuration file

---

### Mapping Rules

1. Go to Mapping Rules
2. Select the configuration you just created
3. Set "Port on your PC" to 9000
4. Save the rule

---

## 🔐 OpenVPN Setup

This assumes OpenVPN was selected as the tunnel type.

Install OpenVPN using your system’s package manager.

On Linux, run OpenVPN directly from the terminal in the same directory as the config file:

sudo openvpn --config <full-config-file-name>.ovpn

Using NetworkManager to import the VPN config is NOT recommended, as it frequently causes routing and permission issues.

---

## 🔥 Firewall Configuration (Linux)

If you are using ufw, allow traffic through the VPN interface:

sudo ufw allow in on tun0 to any port 9000 proto tcp

Without this rule, external connections will fail.

---

## ▶️ Start the Server

If the server was already running, restart it now.

When started, the server will display:
- Local server URLs
- The access key (also stored in the data directory)

---

## 🔗 Public URL

In Portmap → Mapping Rules, you should see something like:

tcp://test-41659.portmap.host:41659 => 9000

Your public URL will be:

http://test-41659.portmap.host:41659/

This is the URL clients will use to connect.

---

## 🧪 Testing Connectivity

You can test that data is flowing correctly by visiting:

http://test-41659.portmap.host:41659/updates?key=YOUR_KEY_HERE

If configured correctly, this page should load.

---

## 🖥️ Client Setup

1. Open the client
2. Add a new server
3. Enter:
   - Server URL
   - Access key (shown in the server output or data files)
4. Ping the server to test connectivity

NOTE:
If the host machine has a slow internet connection, the ping may time out even if the server is reachable.
You can increase the ping timeout value in client.py inside the ping function.

---

## ⚙️ Additional Settings

Check the settings menu for additional convenience and customization.

---

## 💬 Community & Suggestions

Join the Discord server for suggestions and feedback:
https://discord.gg/xbuRzCXhUX
