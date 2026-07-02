# SignalTrail

SignalTrail is a local-first iPhone privacy violation detector for macOS.

The goal is to answer one question:

> Is an app behaving in a way that looks privacy-invasive, unexpected, or worth
> investigating?

SignalTrail uses network evidence to look for privacy-risk signals such as
sensor-related uploads, tracker calls, background chatter, plaintext leakage,
unexpected high-volume transfers, and suspicious changes between app sessions.
It runs a proxy on your Mac, points your iPhone at it, and builds an audit from
observable metadata:

- domains contacted by the phone
- HTTP methods and paths for plaintext HTTP
- HTTPS `CONNECT` tunnel destinations without decrypting content
- byte counts, timing, duration, and background chatter hints
- privacy audit scoring for trackers, analytics, plaintext HTTP, high volume,
  and repeated idle traffic
- possible sensor-related network activity such as location, audio,
  camera/photo, contacts, and nearby-device endpoint hints
- AI analysis that explains the privacy evidence in plain language

SignalTrail does **not** bypass TLS, certificate pinning, app sandboxing, iCloud
security, or device protections. It is intended for debugging and privacy review
on devices you own or administer.

## What It Detects

SignalTrail is designed to detect **privacy violation signals**, not to make
unsupported accusations. The audit engine currently looks for:

- possible location use: `location`, `gps`, `lat`, `longitude`, `nearby`,
  `places`
- possible audio/microphone use: `audio`, `voice`, `speech`, `transcribe`,
  `recording`
- possible camera/photo/media use: `camera`, `photo`, `image`, `media/upload`,
  `vision`, `ocr`
- possible contacts use: `contacts`, `addressbook`, `friends/import`,
  `contact-sync`
- possible Bluetooth/nearby-device use: `bluetooth`, `ble`, `beacon`,
  `nearby-devices`
- tracking and ad-tech endpoints
- plaintext HTTP requests
- repeated activity while the phone should be idle
- unusually high data volume

Each signal includes evidence, risk, and confidence. For example, a plaintext
HTTP request containing `lat` or `speech/transcribe` is stronger evidence than
an encrypted HTTPS tunnel to a vaguely named domain.

## Sensor Detection Limits

On a normal iPhone, a Mac-side proxy cannot directly know when the microphone,
camera, GPS, Bluetooth, contacts, or photos were accessed. iOS keeps that sensor
state inside the device.

SignalTrail can still flag **possible sensor-related network traffic** when
domains or paths contain evidence-like words such as `location`, `lat`,
`speech`, `transcribe`, `photo`, `contacts`, or `bluetooth`. Treat those as
leads for debugging, not proof. Direct sensor usage detection would require one
of these:

- instrumentation inside an app you control
- MDM/device-management telemetry where Apple exposes it
- user-visible iOS privacy indicators and App Privacy Report correlation
- jailbreak/private APIs, which this project will not use

The correct workflow is: capture traffic, review SignalTrail's evidence, then
verify against iOS app permissions, App Privacy Report, and controlled tests
where you open one app at a time.

## Why Python?

The MVP is Python 3 because macOS already ships with enough runtime support for
a local proxy, web dashboard, JSON export, and analysis rules. No Node, database,
packet-capture driver, or root privileges are required for the default flow.

## Quick Start

```bash
python3 -m signaltrail
```

Then open the privacy audit dashboard printed in the terminal, usually:

```text
http://<your-mac-ip>:8765
```

On the iPhone:

1. Connect the iPhone and Mac to the same Wi-Fi.
2. Open iPhone `Settings -> Wi-Fi -> current network -> Configure Proxy`.
3. Choose `Manual`.
4. Set `Server` to your Mac IP and `Port` to `9090`.
5. Keep authentication off.
6. Use one app at a time and watch the SignalTrail privacy audit.

The dashboard also exposes a `.mobileconfig` profile to help configure the proxy.
iOS still asks you to review and install profiles manually.

## Dashboard Endpoints

- `/` live dashboard
- `/events` recent traffic events as JSON
- `/report` local audit report as JSON
- `/audit` privacy audit object as JSON
- `/ai` AI analysis as JSON
- `/export` complete session export as JSON
- `/profile.mobileconfig` iOS global HTTP proxy configuration profile

## AI Layer

SignalTrail always includes an offline rule-based privacy explanation. To enable
a cloud AI model that analyzes the structured audit, set an API key before
starting the app:

```bash
export SIGNALTRAIL_AI_API_KEY="..."
export SIGNALTRAIL_AI_MODEL="gpt-5.5"
python3 -m signaltrail
```

The AI layer is intentionally evidence-first. It sends only the structured audit
report by default: event counts, privacy signals, top domains, and findings. It
does not send packet bodies. Use `SIGNALTRAIL_AI_ENDPOINT` to point at another
OpenAI-compatible Responses API endpoint.

The AI is instructed to avoid overclaiming. It should say “possible location
traffic” or “possible microphone-related upload” unless the evidence is strong
enough to support a firmer conclusion.

## Notes

- HTTPS content remains encrypted. SignalTrail records the destination host,
  port, byte counts, and timing for HTTPS tunnels.
- Some apps ignore Wi-Fi proxy settings or use certificate pinning. That is
  normal.
- Disable VPNs while testing because they can route traffic away from the proxy.
- Remove the iOS proxy/profile after debugging so normal traffic resumes.
