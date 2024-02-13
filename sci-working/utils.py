import constants
import random
import datetime


def prep_log_msg(msg, prefix=''):
    """
    Prepare the log message.

    :param msg: 
        message to be logged
    
    :return:
        log message
    """
    if type(msg) == bytes:
        try:
            msg = msg.decode('utf-8')
        except Exception as e:
            msg = f'{msg}'

    log_msg = datetime.datetime.now().time().isoformat() + ' ' + prefix + msg
    return log_msg

def calc_padding_len(msg):
    """
    Calculate the padding length for the message.

    :param msg: 
        message to be padded

    :return:
        padding length
    """

    return constants.TLS_RECORD_SIZE_LIMIT - len(msg)

def create_msg_body(subject, msg, receiver, sender, msg_type, num_msgs=160):
    """
    Create a message body for the email.

    :param subject: 
        subject of the email

    :param msg: 
        a small message to be sent

    :param receiver: 
        receiver of the email

    :param sender: 
        sender of the email
    
    :param msg_type:
        type of the message to be constructed

    :param num_msgs:
        number of messages to be constructed

    :return:
        message body
    """

    # message headers + body
    msg_body = f"""\
Subject: {subject}
To: {receiver}
From: {sender}

{msg}
"""
    
    # pad the message body to fit the TLS record size limit
    msg_body += ' ' * calc_padding_len(msg_body)
    print(f'Pre len(msg_body): {len(msg_body)}')

    if msg_type in constants.MSG_TYPES:
        if msg_type == constants.MSG_TYPES[0]: # numeric
            # the random characters are numeric
            for i in range(1, num_msgs):
                msg_body += ''.join([str(random.randint(0,9))\
                                      for j in range(0, constants.TLS_RECORD_SIZE_LIMIT)])
        
        elif msg_type == constants.MSG_TYPES[1]: # text
            # the random characters are alphabetic
            for i in range(1, num_msgs):
                msg_body += ''.join([chr(random.randint(65,90))\
                                      for j in range(0, constants.TLS_RECORD_SIZE_LIMIT)])
                
        elif msg_type == constants.MSG_TYPES[2]: # secret
            for i in range(1, num_msgs+1): 
                new_msg = f"""{i%2}"""
                msg_body += new_msg + ' ' * calc_padding_len(new_msg)
        
        # for every 100 characters add a new line
        # msg_body = '\n'.join(msg_body[i:i+100] for i in range(0, len(msg_body), 101))
    print(f'Post len(msg_body): {len(msg_body)}')
    return msg_body


def parse_tls_packets(tlspackets):
    """
    Parse the TLS packets from the email body.

    :param tlspackets:
        TLS packets from the email body

    :return:
        list of TLS packets
    """

    packets = []
    tlspackets_hex = tlspackets.hex()
    while len(tlspackets_hex) > 0:
        # look for the start of the packet: 17 03 03
        START = constants.TLS_APP_DATA_HDR
        start_idx = tlspackets_hex.find(START)
        # print(f'start_idx: {start_idx}')
        if start_idx == -1:
            break
        
        # size of the packet is 2 bytes after the start
        size = int(tlspackets_hex[start_idx+len(START):start_idx+len(START)+4], 16)
        # print(f'size: {size}')
        # the packet is the size of the packet + 5 bytes
        if start_idx+len(START)+4+size*2 > len(tlspackets_hex):
            break
        packet = tlspackets_hex[start_idx:start_idx+len(START)+4+size*2]
        packets.append(bytes.fromhex(packet))
        tlspackets_hex = tlspackets_hex[start_idx+len(START)+4+size*2:]
    
    tlspackets = bytes.fromhex(tlspackets_hex)
    return packets, tlspackets
