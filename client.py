# standard imports
import json
import logging
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

        # self.debuglevel = 3
        self.authenticated = False
        self.user = self.sign_user(email, password, is_registered)
        self.inbox = ''


if __name__ == '__main__':
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

    try:
        client = MAILClient(verifier['ip'], verifier['port'], \
                            sender['email'], sender['pwd'], \
                                is_registered=True)
        logging.debug(utils.prep_log_msg(f'Connected to {verifier["ip"]}:{verifier["port"]}'))
        
    except Exception as e:
        logging.critical(utils.prep_log_msg(e.__str__())) # most likely missing inputs
        exit(1)
    

    if email_body['type'] in constants.MSG_TYPES:
        # create mail body
        msg = utils.create_msg_body(email_body['subject'], \
                                    email_body['msg'], \
                                    receiver, sender, \
                                    email_body['type'], \
                                    num_msgs=email_body['num-msgs'])
        
    else:
        logging.critical(utils.prep_log_msg('Invalid message type'))
        exit(1)

    try:
        client.sendmail(sender['address'], receiver['address'], msg)
        logging.info(utils.prep_log_msg('Message sent successfully!'))

    except Exception as e:
        logging.critical(utils.prep_log_msg(e.__str__()))
        exit(1)



    
