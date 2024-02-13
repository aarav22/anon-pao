import constants
import re
import datetime

CRLF = '\r\n'

def calc_padding_len(msg):
    return constants.TLS_RECORD_SIZE_LIMIT - len(msg)

def _fix_eols(data):
    return  re.sub(r'(?:\r\n|\n|\r(?!\n))', CRLF, data)

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


def create_msg_body(subject, msg, receiver, sender, num_msgs=160, optimize=False):

    # message headers + body
    msg_body = f"""\
Subject: {subject}
To: {receiver}
From: {sender}

{msg}
"""
    
    if not optimize:
    # pad the message body to fit the TLS record size limit
        msg_body += ' ' * (calc_padding_len(msg_body) - len(msg_body.split('\n')) + 1)
        msg_body = '\n'.join(msg_body[i:i+100] for i in range(0, len(msg_body), 102))

    print(f'Pre len(msg_body): {len(msg_body)}', len(_fix_eols(msg_body)))

    for i in range(0, num_msgs): 
        new_msg = f"""{i%2}"""

        if not optimize:
            # new_msg = new_msg + 97 bytes of padding + \n
            # new_msg += 98 bytes of padding + \n
            # till 16384 - number of \n - len(new_msg) = 0
            new_msg += ' ' * (constants.TLS_RECORD_SIZE_LIMIT - len(new_msg))
            new_msg = '\n'.join(new_msg[i:i+100] for i in range(0, len(new_msg), 102))

            if i == num_msgs - 1:
                # remove last 6 characters
                new_msg = new_msg[:-6] + ' '
            else:
                # remove the last newline
                new_msg = new_msg[:-1] + ' '

        msg_body += new_msg

    print(f'Post len(msg_body): {len(msg_body)}', len(msg_body.split('\n')))

    return msg_body



def parse_replies(replies):
    beginHdr = b'REPLYBEGIN'

    # parse the replies
    print("Parsing replies...", len(replies))
    replies = replies.split(beginHdr)[1:]

    return replies




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

        # the packet is the size of the packet + 5 bytes
        if start_idx+len(START)+4+size*2 > len(tlspackets_hex):
            break
        packet = tlspackets_hex[start_idx:start_idx+len(START)+4+size*2]
        packets.append(bytes.fromhex(packet))
        tlspackets_hex = tlspackets_hex[start_idx+len(START)+4+size*2:]
    
    tlspackets = bytes.fromhex(tlspackets_hex)
    return packets, tlspackets
