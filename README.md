<p align="center">
  <img src="https://img.shields.io/badge/go-1.21%2B-00ADD8?logo=go&logoColor=white" alt="Go 1.21+">
  <img src="https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen" alt="No dependencies">
  <a href="https://github.com/Egyan07/ViperFin/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Egyan07/ViperFin/ci.yml?label=CI&logo=githubactions&logoColor=white" alt="CI"></a>
</p>

# ViperFin

JA3 and JA3S TLS fingerprinting in Go, standard library only.

## What it does

Every TLS connection opens with a ClientHello, sent in clear, before any encryption exists. That message lists the TLS versions, cipher suites, extensions, curves and point formats the client supports. Different software produces different combinations, and the combination is stable enough to tell Chrome from curl from a Cobalt Strike beacon.

JA3 turns that combination into a string and hashes it with MD5. ViperFin captures the handshake, computes the hash, and matches it against a local signature database. No external API, no machine learning, no agent.

JA3S does the same job for the server side, which is how you tell nginx from an appliance you did not know was there.

## Modes

**client** connects to a target, captures your own ClientHello, and reports what the connection looks like from the outside.

```bash
./viperfin client google.com:443
./viperfin client example.com:443 --verbose
./viperfin client 10.0.0.1:8443 --insecure --json
```

**server** listens, generates a self-signed certificate, and fingerprints every client that connects. Useful for seeing what a tool actually sends.

```bash
./viperfin server --port 4443
./viperfin server --port 8443 --json >> fingerprints.jsonl
```

```bash
curl -k https://localhost:4443
```

**lookup** queries the signature database directly.

```bash
./viperfin lookup 6bea65232d17d4884c427918d6c3abf0
./viperfin lookup --list
./viperfin lookup --list --threat malicious
```

## Flags

| Mode | Flag | Effect |
|---|---|---|
| client | `--json` | One JSON object instead of the text report |
| client | `--verbose` | Prints cipher suites, extensions and curves in full |
| client | `--insecure` | Skips certificate verification, and says so in the output |
| server | `--port` | Listen port, default 4443 |
| server | `--json` | One JSON object per connection, pipe friendly |
| server | `--verbose` | Full cipher suite details per connection |

`--insecure` prints a warning every time it is used. A certificate mismatch is itself worth seeing, and silencing it without a trace is how a MITM goes unnoticed in a lab.

## Signature database

22 fingerprints embedded in the binary, each with a label, a category and a threat level.

| Category | Examples |
|---|---|
| Browsers | Chrome 107+, Firefox 105+, Safari 16, Tor Browser |
| Tools | curl, wget, Python requests, Go net/http, OpenSSL s_client, Java HttpsURLConnection |
| Penetration testing | Metasploit, Nmap SSL scan |
| Scanners | Masscan, Shodan crawler |
| Malware C2 | Cobalt Strike (two variants), Sliver, Brute Ratel C4, Emotet, TrickBot, Dridex, QakBot |

The list is small on purpose. A JA3 hash is only useful if the label is right, and a wrong label is worse than no label.

## How the hash is built

The ClientHello fields are joined in order:

```
SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
769,47-53-5-10-49161,0-10-11,23-24,0
```

that string is hashed with MD5, and the hex digest is the JA3 fingerprint.

GREASE values (RFC 8701) are removed before hashing. Browsers insert random GREASE values on every connection to stop the protocol ossifying, so leaving them in would produce a different hash each time and the fingerprint would be worthless.

## Build

Go 1.21 or later, no dependencies to download.

```bash
./build.sh
```

or cross-compile directly:

```bash
GOOS=windows GOARCH=amd64 go build -o viperfin.exe .
GOOS=linux   GOARCH=amd64 go build -o viperfin .
```

The binary moves between environments without a runtime, so building on Linux and running the capture on a Windows host works fine.

## Tests

19 test functions across the JA3 computation, handshake parser and signature database. Most are table driven, so the case count is higher than the function count.

```bash
go test ./...
go test -race ./...
```

CI runs the suite with the race detector and cross-compiles for Windows, Linux and macOS.

## Limits

| Limit | Detail |
|---|---|
| Fingerprints drift | Browser and malware TLS stacks change between releases. A hash older than a year is a guess |
| TLS 1.3 and ECH | The extension list is thinner and Encrypted Client Hello hides what used to be visible. Fingerprinting gets harder every year |
| No live capture | It fingerprints the connection it makes or receives, not traffic already on the wire. Pair it with a pcap tool for that |
| Self-signed server cert | The server mode certificate is generated at start. Clients must skip verification to connect |
| Small database | 22 entries is a starting point, not threat intelligence |

## Author

Egyan07, [github.com/Egyan07](https://github.com/Egyan07)
