# standard imports
import json
import logging
import time
logging.basicConfig(filename='client-logs.log', encoding='utf-8', level=logging.DEBUG)

# local imports
import constants
import utils

# third party imports
from tlslite import SMTP_TLS as Client, HandshakeSettings

class MAILClient(Client):
    def __init__(self, hostname, port, email, password, is_registered, settings=HandshakeSettings()): 
        super().__init__(hostname,port)
        self.ehlo()
        self.starttls(settings=settings)
        self.ehlo()

        # self.debuglevel = 1
        self.authenticated = False
        self.user = self.sign_user(email, password, is_registered)
        self.inbox = ''

    def sign_user(self, email, password, is_registered):
        while(not self.authenticated):
            if is_registered:
                if self.login(email,password):
                    self.authenticated = True
                    return True
                else:
                    raise 'Invalid Credentials'


if __name__ == '__main__':
    timer = time.time()

    config = None

    logging.info(utils.prep_log_msg('Starting client...'))
    # read config file
    try:
        with open('inputs.json') as f:
            inputs = json.load(f)
    except Exception as e:
        logging.critical(utils.prep_log_msg(e.__str__()))
        exit(1)

    sender = inputs['sender']
    receiver = inputs['receiver']
    email_body = inputs['email-body']
    verifier = inputs['verifier']
# 
    if email_body['type'] in constants.MSG_TYPES:
        # create mail body
        msg = utils.create_msg_body(email_body['subject'], \
                                    email_body['msg'], \
                                    receiver['email'], sender['email'], \
                                    email_body['type'], \
                                    num_msgs=email_body['num-msgs'])
        
    else:
        logging.critical(utils.prep_log_msg('Invalid message type'))
        exit(1)

    # print(msg)
    
    # send mail
    def standard_email():
        print("Sending email...")
        import smtplib
        s = smtplib.SMTP(sender['host'], 587)
        s.debuglevel = 3
        s.ehlo()
        s.starttls()
        s.login(sender['email'], sender['pwd'])
        s.sendmail(sender['email'], receiver['email'], msg)
        s.quit()

    # @profile
    def youchoose_email():
        try:
            handshake = HandshakeSettings()
            #aes cbc with hmac sha256
            # handshake.minVersion = (3,3)
            # handshake.maxVersion = (3,3)
            # handshake.cipherNames = ['aes128']
            # handshake.macNames = ['sha256']
            # handshake.useEncryptThenMAC = False
            client = MAILClient(verifier['ip'], verifier['port'], \
                                sender['email'], sender['pwd'], \
                                    is_registered=True, settings=handshake)
            # logging.debug(utils.prep_log_msg(f'Connected to {verifier["ip"]}:{verifier["port"]}'))
        
        except Exception as e:
            # logging.critical(utils.prep_log_msg(e.__str__())) # most likely missing inputs
            exit(1)

        try:
            client.sendmail(sender['email'], receiver['email'], msg)
            # logging.info(utils.prep_log_msg('Message sent successfully!'))

        except Exception as e:
            # logging.critical(utils.prep_log_msg(e.__str__()))
            exit(1)

    for i in range(1):
        youchoose_email()
    # standard_email()

    print(f'Client took {time.time() - timer} seconds to run')



    
