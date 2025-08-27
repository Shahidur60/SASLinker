
---

# 📄 `README` (Java desktop web server)

```markdown
# SASLinker Desktop (Java, Embedded Web UI)

A lightweight Java server that:
- Generates a **QR** (Diffie–Hellman pub + nonce).
- Orchestrates SAS verification with the phone.
- Enforces **mutual code comparison** on desktop (type the **last 2** SAS characters) before **Accept** is possible.
- Serves a **WhatsApp-style** web page for the whole flow.

---

## Features

- Generates `sas_qr.png` and serves a modern web UI at `http://<host>:8889/`.
- Endpoints for mobile:
  - `POST /start` — phone posts its pub & nonce (`"<phone_pub>:<phone_nonce>"`)
  - `POST /verify` — phone submits its 6-char SAS
  - `GET  /poll` — phone polls for `accepted|rejected|waiting`
- Endpoints for web UI:
  - `GET  /` — desktop UI (QR/instructions → SAS mutual check → result)
  - `GET  /qr.png` — QR image
  - `GET  /state` — returns JSON `{status, sas?}` to drive the web UI
  - `POST /confirm` — desktop accept/reject when mutual check passes

> The desktop page **hides the QR** after scan and shows the **actual SAS**.  
> Desktop **must** type the **last 2 characters** (or pass your “codes match” rule) to enable accept.

---

## Build & Run

This project uses only JDK (no external frameworks required).

1. **Compile**
   ```bash
   javac -cp .:core-3.5.3.jar:javase-3.5.3.jar com/example/saslinkerjava/SASLinker.java
