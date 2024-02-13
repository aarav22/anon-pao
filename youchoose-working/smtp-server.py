import os
import ssl
import subprocess
from aiosmtpd.smtp import SMTP
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Debugging, Sink

import logging
import sys

def configure_logging():
    file_handler = logging.FileHandler("aiosmtpd.log", "a")
    stderr_handler = logging.StreamHandler(sys.stderr)
    logger = logging.getLogger("mail.log")
    fmt = "[%(asctime)s %(levelname)s] %(message)s"
    datefmt = None
    formatter = logging.Formatter(fmt, datefmt, "%")
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    # logger.setLevel(logging.DEBUG)

configure_logging()

# Create cert and key if they don't exist
if not os.path.exists('cert.pem') and not os.path.exists('key.pem'):
    subprocess.call('openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem ' +
                    '-days 365 -nodes -subj "/CN=localhost"', shell=True)

# Load SSL context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain('cert.pem', 'key.pem')

# Pass SSL context to aiosmtpd
class ControllerStarttls(Controller):
    def factory(self):
        smtp = SMTP(self.handler, require_starttls=True, tls_context=context, auth_callback=self.auth_callback)
        return smtp

    def auth_callback(self, mechanism, auth_data, server):
        return True

# Start server
controller = ControllerStarttls(Sink(), hostname="localhost", port=1025)
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