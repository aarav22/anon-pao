MSG_TYPES = ['numeric', 
                  'text',
                    'secret'
                  ]

ENTITIES = ['Client', 'Email Server', 'Verifier']

TLS_RECORD_SIZE_LIMIT = 16384 # 2^14
bCRLF = b"\r\n"
CRLF = "\r\n"
TLS_APP_DATA_HDR = '170303'
START_MSG = 'START: Blind Certificate Protocol'
VERIFY_MSG = 'VERIFY: Blind Certificate Protocol'
bDROP_MSG_BEGIN = b'DROP: BEGIN DROPPING'
bDROP_MSG_END = b'DROP: END DROPPING'
bSUBJECT =  b'Subject'
DROP_MODES = ['drop', 'done', 'none']
SERVER_TIMEOUT = 1
CLIENT_TIMEOUT = 1
# TLS_ENC_MODE = 2 # CBC mode
