# 🐍 ViperFin

### TLS Fingerprinting & JA3 Analysis Tool

![GitHub stars](https://img.shields.io/github/stars/Egyan07/ViperFin?style=social)
![GitHub forks](https://img.shields.io/github/forks/Egyan07/ViperFin?style=social)
![GitHub issues](https://img.shields.io/github/issues/Egyan07/ViperFin)
![GitHub last commit](https://img.shields.io/github/last-commit/Egyan07/ViperFin)
![License](https://img.shields.io/github/license/Egyan07/ViperFin)

**Coded by Egyan**

ViperFin is a **JA3 / JA3S TLS fingerprinting tool written in Go**.

It identifies what software is making TLS connections by analyzing the **raw ClientHello handshake message** — no machine learning, no external APIs, just **pure TLS protocol analysis**.

TLS fingerprinting is widely used by security platforms such as **Cloudflare, Salesforce, and Fastly** to detect malware command-and-control channels and identify suspicious clients.

ViperFin can also be used by red teams to understand **what TLS fingerprints their tools generate** when connecting to servers.

---

# 🧰 Technology

| Component      | Description                      |
| -------------- | -------------------------------- |
| Language       | Go (stdlib only)                 |
| Protocol       | TLS handshake analysis           |
| Fingerprinting | JA3 and JA3S                     |
| Database       | Embedded JSON signature database |
| Output         | Terminal or JSON                 |

No external dependencies.

---

# ✨ Features

| Feature             | Description                                          |
| ------------------- | ---------------------------------------------------- |
| JA3 Fingerprinting  | Identify TLS clients from ClientHello                |
| JA3S Fingerprinting | Identify server infrastructure                       |
| Signature Database  | Detect known tools and malware                       |
| TLS Inspection      | Shows TLS version, cipher suite, certificate details |
| Threat Intelligence | Matches fingerprints against known malicious tools   |
| JSON Output         | Pipe-friendly output for scripting                   |
| Server Mode         | Fingerprint incoming clients                         |
| Lookup Mode         | Query local fingerprint database                     |
| Cross Compilation   | Build for Linux, Windows, macOS                      |
| CI Pipeline         | Automated tests + race detection                     |

---

# 🚀 Installation

Requirements:

```
Go 1.21+
```

Clone the repository:

```bash
git clone <repo>
cd viperfin
```

Build using the included script:

```bash
chmod +x build.sh
./build.sh
```

Or build manually:

```bash
go build -o viperfin .
```

Build Windows executable:

```bash
GOOS=windows GOARCH=amd64 go build -o viperfin.exe .
```

The binary can then be copied between environments such as **Kali Linux → Windows**.

---

# ⚡ Windows Quick Start

After building `viperfin.exe` and transferring it to Windows:

Open Command Prompt:

```
Win + R → type cmd
```

Navigate to the folder:

```cmd
cd "C:\My Projects\Projects\ViperFin"
```

Run against any website:

```cmd
viperfin.exe client google.com:443
```

Examples:

```cmd
viperfin.exe client facebook.com:443
viperfin.exe client github.com:443
viperfin.exe client example.com:443
```

Port `443` indicates a **standard HTTPS TLS connection**.

---

# 🔍 Understanding the Output

| Section             | Meaning                                   |
| ------------------- | ----------------------------------------- |
| TLS Version         | Protocol version used by the server       |
| Cert Subject        | Domain the certificate belongs to         |
| Cert Issuer         | Certificate authority that issued it      |
| Cert Expiry         | When the certificate expires              |
| JA3 Hash            | Fingerprint of the client TLS stack       |
| JA3S Hash           | Fingerprint of the server TLS stack       |
| Threat Intelligence | Database match for known tools or malware |

Indicators:

| Indicator                    | Meaning                                |
| ---------------------------- | -------------------------------------- |
| ✅ TLS 1.3                    | Modern secure configuration            |
| ⚠️ Certificate near expiry   | Certificate about to expire            |
| 🚨 Threat intelligence match | Fingerprint matches known malware/tool |

---

# 🧠 How JA3 Works

Every TLS connection begins with a **ClientHello** message.

Before encryption begins, the client announces:

* supported TLS version
* supported cipher suites
* supported extensions
* supported elliptic curves
* EC point formats

Different software produces **distinct combinations**.

Examples:

* Chrome
* Firefox
* Python requests
* curl
* Cobalt Strike

JA3 concatenates these fields:

```
SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
769,47-53-5-10-49161,0-10-11,23-24,0
```

The resulting string is hashed using **MD5** to create the JA3 fingerprint.

Example:

```
a0e9f5d64349fb13191bc781f81f42e1
```

---

# 🧪 GREASE Filtering

Modern browsers insert random values called **GREASE values** to prevent protocol ossification.

Defined in **RFC 8701**.

Examples:

```
0x0A0A
0x1A1A
...
0xFAFA
```

Because GREASE values change per connection, JA3 filters them out so fingerprints remain deterministic.

---

# ⚡ Usage

## Client Mode

Connect to a TLS server and fingerprint your connection.

```bash
./viperfin client google.com:443
```

Verbose mode:

```bash
./viperfin client example.com:443 --verbose
```

JSON output:

```bash
./viperfin client 10.0.0.1:8443 --json
```

Skip certificate verification:

```bash
./viperfin client internal.corp:8443 --insecure
```

Shows:

* JA3 fingerprint
* JA3S fingerprint
* TLS version and cipher suite
* certificate details
* threat intelligence matches

---

## Server Mode

Listen for TLS connections and fingerprint every client.

Start server:

```bash
./viperfin server
```

Custom port:

```bash
./viperfin server --port 8443
```

JSON output:

```bash
./viperfin server --port 4443 --json >> fingerprints.jsonl
```

Example clients:

```bash
curl -k https://localhost:4443
openssl s_client -connect localhost:4443
```

Use cases:

* security research
* red team infrastructure
* TLS fingerprint collection
* network monitoring

---

## Lookup Mode

Query the local signature database.

Lookup hash:

```bash
./viperfin lookup 6bea65232d17d4884c427918d6c3abf0
```

List all signatures:

```bash
./viperfin lookup --list
```

Filter by threat level:

```bash
./viperfin lookup --list --threat malicious
```

---

# 📚 Signature Database

The embedded database contains fingerprints for:

| Category      | Examples                        |
| ------------- | ------------------------------- |
| Browsers      | Chrome, Firefox, Safari         |
| Tools         | curl, wget, Python requests     |
| Pentest Tools | Metasploit, Nmap                |
| Malware C2    | Cobalt Strike, Emotet, TrickBot |
| Scanners      | Masscan, Shodan                 |

File location:

```
db/ja3_signatures.json
```

Example entry:

```json
{
  "hash": "your_md5_hash_here",
  "label": "Descriptive name",
  "category": "browser",
  "threat_level": "benign",
  "notes": "Context about this fingerprint"
}
```

Community resources:

* https://ja3er.com
* https://github.com/salesforce/ja3

---

# 🏗 Project Structure

```
viperfin/
├── main.go
├── go.mod
├── build.sh
├── cmd/
│   ├── client.go
│   ├── server.go
│   └── lookup.go
├── tls/
│   ├── ja3.go
│   ├── parser.go
│   ├── capture.go
│   └── server.go
├── db/
│   ├── signatures.go
│   └── ja3_signatures.json
└── report/
    └── output.go
```

---

# 🛣 Roadmap

Future improvements:

* PCAP parsing mode
* continuous fingerprint monitoring
* JA3 database auto-sync
* TLS proxy fingerprint collector
* dashboard for fingerprint analytics

---

# 📚 References

Salesforce JA3 paper
https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967

RFC 8701 — GREASE
https://www.rfc-editor.org/rfc/rfc8701

TLS 1.3 specification
https://www.rfc-editor.org/rfc/rfc8446

Wireshark TLS dissector
https://wiki.wireshark.org/TLS

---

# 👨‍💻 Author

**Egyan07**

---

# 🐍 ViperFin

**Protocol-Level TLS Fingerprinting**
