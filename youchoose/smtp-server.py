import os
import ssl
import subprocess
from aiosmtpd.smtp import SMTP
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Debugging, Sink

import logging
import sys

def configure_logging():
    file_handler = logging.FileHandler("tmp/aiosmtpd.log", "a")
    stderr_handler = logging.StreamHandler(sys.stderr)
    logger = logging.getLogger("tmp/mail.log")
    fmt = "[%(asctime)s %(levelname)s] %(message)s"
    datefmt = None
    formatter = logging.Formatter(fmt, datefmt, "%")
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.setLevel(logging.INFO)

configure_logging()

# Create cert and key if they don't exist
if not os.path.exists('./assets/cert.pem') and not os.path.exists('./assets/key.pem'):
    subprocess.call('openssl req -x509 -newkey rsa:4096 -keyout ./assets/key.pem -out ./assets/cert.pem ' +
                    '-days 365 -nodes -subj "/CN=localhost"', shell=True)

# Load SSL context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain('./assets/cert.pem', './assets/key.pem')

# Pass SSL context to aiosmtpd

class MessageHandler:
    def __init__(self):
        self.logger = logging.getLogger("mail.log")
    
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        print(f"Recipient: {address}")
        self.logger.info(f"Recipient: {address}")
        envelope.rcpt_tos.append(address)
        return '250 OK'
    
    async def handle_DATA(self, server, session, envelope):
        print(f"\n--- New Message ---")
        print(f"From: {envelope.mail_from}")
        print(f"To: {envelope.rcpt_tos}")
        print(f"Message content:")
        with open('tmp/message.txt', 'w') as f:
            f.write(envelope.content.decode('utf-8'))
        print(f"--- End Message ---\n")
        
        # Log to file as well
        self.logger.info(f"Message from {envelope.mail_from} to {envelope.rcpt_tos}")
        self.logger.info(f"Content: {envelope.content.decode('utf-8')}")
        
        return '250 Message accepted for delivery'
class ControllerStarttls(Controller):
    def factory(self):
        smtp = SMTP(self.handler, require_starttls=True, tls_context=context, auth_callback=self.auth_callback)
        return smtp

    def auth_callback(self, mechanism, auth_data, server):
        return True

# Start server
controller = ControllerStarttls(MessageHandler(), hostname="localhost", port=1025)
controller.start()
# Test using swaks (if available)
# subprocess.call('swaks -tls -t test --server localhost:1025', shell=True)
input('Running STARTTLS server. Press enter to stop.\n')
controller.stop()

# Alternatively: Use TLS-on-connect
# controller = Controller(Debugging(), port=1025, ssl_context=context)
# controller.start()
# # Test using swaks (if available)
# subprocess.call('swaks -tlsc -t test --server localhost:1025', shell=True)
# input('Running TLSC server. Press enter to stop.\n')
# controller.stop()