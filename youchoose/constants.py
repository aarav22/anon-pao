MSG_TYPES = ['numeric', 
                  'text',
                    'secret'
                  ]

ENTITIES = ['Client', 'Email Server', 'Verifier']

bCRLF = b"\r\n"
CRLF = "\r\n"
TLS_APP_DATA_HDR = '170303'
START_MSG = 'START: Blind Certificate Protocol'
VERIFY_MSG = 'VERIFY: Blind Certificate Protocol'
DROP_MSG_BEGIN = 'begin'
DROP_MSG_END = 'end'
bSUBJECT =  b'Subject'

# Config
CONFIG_AEAD = "aead"
CONFIG_CBC = "cbc"


# TLS Protocol Constants
TLS_RECORD_SIZE_LIMIT = 1500  # Maximum size for TLS records (reduced from 16384)
TLS_APPLICATION_DATA_HEADER = '170303'  # TLS 1.2 Application Data record header
TLS_MAX_RECORD_SIZE = 16384  # Standard maximum TLS record size (2^14 bytes)

# Challenge Collection Control Markers
CHALLENGE_DROP_BEGIN = b'DROP: BEGIN DROPPING'  # Marker to start challenge collection
CHALLENGE_DROP_END = b'DROP: END DROPPING'      # Marker to end challenge collection

# Operation Mode Constants
NON_AEAD_MODE = 1  # Simple bit-based challenge selection
AEAD_MODE = 2 # OT-based challenge selection

# Proxy Drop Mode Constants
START_DROP = 0  # Currently collecting challenges to drop
STOP_DROP = 1   # Finished collecting challenges
DO_NOTHING = 2  # Normal forwarding mode (no dropping)

# Network and Protocol Configuration
SERVER_TIMEOUT = 0.6  # Timeout for server connections in seconds
CLIENT_TIMEOUT = 0.5  # Timeout for client connections in seconds
DEFAULT_SOCKET_BACKLOG = 200  # Maximum number of pending connections

# Default Configuration Values
DEFAULT_BUFFER_SIZE = 4 * 1024  # 4KB socket buffer
DEFAULT_LOOP_DELAY = 0.0001     # Small delay in main event loop
DEFAULT_LISTEN_ADDRESS = ('0.0.0.0', 0)  # Listen on all interfaces
DEFAULT_CHALLENGE_COUNT = 160   # Default number of challenges to generate

# Protocol Parsing Constants
OT_REPLY_BEGIN_MARKER = b'REPLYBEGIN'  # Marker for oblivious transfer replies
MAX_LINE_LENGTH = 100  # Maximum line length for email formatting
PADDING_CHARACTER = ' '  # Character used for padding messages