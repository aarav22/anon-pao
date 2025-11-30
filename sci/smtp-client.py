# standard imports
import json
import logging
import time
import base64

logging.basicConfig(filename='client-logs.log', level=logging.DEBUG)

# local imports
import constants
import utils

# third party imports
from tlslite import SMTP_TLS as Client, HandshakeSettings
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage


class MAILClient(Client):
    def __init__(self, hostname, port, email, password, num_chals, cipher="cbc", mode="youchoose", optimize=False): 
        super().__init__(hostname, port)

        # create config for tlslite:
        config = {
            "cipher": cipher,
            "mode": mode,
            "num_chals": num_chals,
            "optimize": optimize,
        }
        config = json.dumps(config)

        # save config to file
        with open('config.json', 'w') as f:
            f.write(config)

        handshake = None
        #aes cbc with hmac sha256
        if cipher == "cbc":
            handshake = HandshakeSettings()
            handshake.minVersion = (3,3)
            handshake.maxVersion = (3,3)
            handshake.cipherNames = ['aes128']
            handshake.macNames = ['sha256']
            handshake.useEncryptThenMAC = False

        # self.set_debuglevel(3)
        self.ehlo("localhost")
        self.starttls(settings=handshake)
        self.ehlo("localhost")
        self.login(email, password)

    def createMsgBody(self, receiver, sender, msg_type, image_path, num_chals=1, optimize=False):
        subject = "PAO Challenge"
        body = "BEGIN PAO CHALLENGE"

        if msg_type == "text":
            return utils.create_msg_body(subject, body, receiver, sender, num_msgs=num_chals, optimize=optimize)
        
        elif msg_type == "image":
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = receiver
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            # Attach image
            with open(image_path, 'rb') as image_file:
                image_data = image_file.read()
                image_attachment = MIMEImage(image_data)
                msg.attach(image_attachment)

            msg = msg.as_string()
            return msg


    def sendmail(self, sender, receiver, msg):
        super().sendmail(sender, receiver, msg)


def main():
    from optparse import OptionParser
    parser = OptionParser()

    # youchoose or standard
    parser.add_option("-m", "--mode", dest="mode", default="youchoose",
                        help="standard or youchoose")
    parser.add_option("-o", "--optimize", dest="optimize", default="no",
                        help="yes or no")
    # encryption mode (aead or cbc)
    parser.add_option("-e", "--encryption", dest="encryption", default="cbc",
                        help="cbc or aead")
    
    # verifier ip and port:
    parser.add_option("-i", "--ip", dest="ip", default="localhost", 
                        help="ip address of verifier")
    parser.add_option("-p", "--port", dest="port", default=5000, 
                        help="port of verifier")
    
    # sender email and password
    parser.add_option("-s", "--sender", dest="sender", default="sender@localhost", 
                        help="sender email")
    
    parser.add_option("-w", "--password", dest="password", default="password",
                        help="sender password")
    
    # receiver email
    parser.add_option("-r", "--receiver", dest="receiver", default="receiver@localhost",
                        help="receiver email")
    
    # email body:
    parser.add_option("-t", "--msg-type", dest="msg_type", default="text",
                        help="text or image")
    parser.add_option("-n", "--image-path", dest="image_path", default="login_image.bmp",
                        help="path to image")
    parser.add_option("-c", "--num-chals", dest="num_chals", default=160,
                        help="number of challenges to send")
    


    (options, args) = parser.parse_args()
    optimize = True if options.optimize == "yes" else False

    # create mail client
    client = MAILClient(options.ip, options.port,
                        options.sender, options.password,
                        int(options.num_chals), optimize=optimize,
                        cipher=options.encryption, mode=options.mode)
    
    # create email body
    msg = client.createMsgBody(options.receiver, options.sender, 
                               options.msg_type, options.image_path, int(options.num_chals), 
                               optimize=optimize)
    
    # send mail
    timer = time.time()
    client.sendmail(options.sender, options.receiver, msg)
    timer = time.time() - timer

    print(f'Time taken: {timer}')


if __name__ == '__main__':
    main()

