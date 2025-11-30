# SCI (Secure Channel Injection)

Implementation of Secure Channel Injection (SCI) protocol for anonymous proof of account ownership (PAO).

**Source Paper:** [Blind Certificate Authorities](https://eprint.iacr.org/2018/1022.pdf)

## Overview

SCI enables a prover to demonstrate ownership of an email account to a verifier without revealing their identity to either the server or the verifier. The protocol uses multi-party computation (MPC) to inject secure channel messages into TLS traffic, allowing anonymous authentication.

## Components

- **`proxy.py`**: TLS proxy that intercepts and modifies TLS records using MPC protocols
- **`smtp-client.py`**: SMTP client that initiates the anonymous PAO protocol
- **`smtp-server.py`**: SMTP server for testing (uses aiosmtpd)
- **`customSHA256.py`**: Custom SHA-256 implementation for protocol-specific hashing
- **`utils.py`**: Utility functions for message creation and protocol handling
- **`constants.py`**: Protocol constants and configuration
- **`tlslite/`**: Modified TLS library for SCI protocol support

## Usage

1. Configure `inputs.json` with email credentials and verifier information
2. Run the SMTP server:
   ```bash
   python smtp-server.py
   ```
3. Run the proxy (verifier side):
   ```bash
   python proxy.py
   ```
4. Run the SMTP client (prover side):
   ```bash
   python smtp-client.py
   ```

## Requirements

- Python 3.x
- Compliled [2P-AES](https://github.com/osu-crypto/batchDualEx) for MPC operations to be put in `./bin` directory
- Modified tlslite library (included in `tlslite/` directory)
