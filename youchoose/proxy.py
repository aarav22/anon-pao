import socket
import time
import logging
import sys
import select
import pickle
import json

import libraries.otc as otc
import utils
import constants

# Configure logging
logging.basicConfig(
    level=logging.DEBUG, 
    format='%(asctime)s - %(levelname)-8s - %(message)s', 
    filename='tmp/proxy.log'
)
logger = logging.getLogger(__name__)


class SessionTerminatedException(Exception):
    """Raised when a proxy session needs to be terminated"""
    pass


class ProtocolViolationException(Exception):
    """Raised when protocol rules are violated during communication"""
    pass


class TcpSocketBuffer(object):
    """
    Wrapper for TCP Socket that maintains buffers for sent/received data
    
    This class wraps a socket to provide access to the last sent and received data,
    which is useful for protocol analysis and debugging.
    """
    
    def __init__(self, socket_conn, peer_address=None):
        self.socket = None
        self.ssl_socket = None
        self.receive_buffer = ''
        self.send_buffer = ''
        self.peer_address = peer_address
        self._initialize_socket(socket_conn)
        
    def _initialize_socket(self, socket_conn):
        """Initialize the wrapped socket"""
        self.socket = socket_conn
        
    def connect(self, target_address=None):
        """Connect to target address"""
        target_address = target_address or self.peer_address
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return self.socket.connect(target_address)
    
    def accept(self):
        """Accept incoming connections"""
        return self.socket.accept()
                
    def recv(self, buffer_length=8*1024, *args, **kwargs):
        """Receive data from socket with SSL support"""
        if self.ssl_socket:
            chunks = []
            chunk = True
            data_pending = buffer_length
            while chunk and data_pending:
                chunk = self.ssl_socket.read(data_pending)
                chunks.append(chunk)
                data_pending = self.ssl_socket.pending()
            self.receive_buffer = ''.join(chunks)
        else:
            self.receive_buffer = self.socket.recv(buffer_length, *args, **kwargs)
        return self.receive_buffer
    
    def sendall(self, data):
        """Send all data through socket"""
        self.socket.sendall(data)
        self.send_buffer = data


class ProxySession(object):
    """
    Represents a proxy session handling client <-> proxy <-> server communication
    
    This class manages the flow of data between a client and server through the proxy,
    implementing selective dropping of TLS records.
    
    Args:
        proxy_socket: The proxy's listening socket
        client_socket: Socket connected to the client (inbound)
        server_socket: Socket connected to the server (outbound)  
        target_address: Target server address tuple ('ip', port)
        buffer_size: Size of socket buffers for data transfer
        operation_mode: 1 for non-AEAD mode, 2 for AEAD mode
    """
    
    def __init__(self, proxy_socket, client_socket=None, server_socket=None, 
                 target_address=None, buffer_size=4096, 
                 operation_mode=constants.NON_AEAD_MODE):
        self.proxy_socket = proxy_socket
        self.proxy_bind_address = proxy_socket.getsockname()
        
        # Wrap sockets with buffers for data tracking
        self.client_connection = TcpSocketBuffer(client_socket)
        self.server_connection = TcpSocketBuffer(server_socket, 
                                                 peer_address=target_address)
        
        self.buffer_size = buffer_size
        self.session_data_store = {}
        
        # Initialize dropping mode - determines how to handle TLS records
        self.current_drop_mode = constants.DO_NOTHING  # Start in normal forwarding mode 

        self.operation_mode = operation_mode
        self.challenge_count = 0
        self.collected_challenges = []  # TLS records collected during drop mode
        
        # Initialize oblivious transfer receiver for cryptographic operations
        self.ot_receiver = otc.receive()
        self.verifier_selection_bits = []

        # Load configuration data needed for selective dropping
        self._load_verifier_selection_bits()
        if self.operation_mode == constants.AEAD_MODE:
            self._load_OT_keys()

    def _load_verifier_selection_bits(self):
        """
        Load selection bits that determine which TLS records the verifier should drop
        
        These bits are used in oblivious transfer to decide which of paired challenges
        should be forwarded to the server vs dropped by the proxy.
        """
        with open('assets/keys/selection-bits.log', 'r') as f:
            self.verifier_selection_bits = json.load(f)
    
    def _load_OT_keys(self):
        """
        Load cryptographic keys for oblivious transfer operations (operation mode 2)
        
        These keys enable the proxy to perform OT protocol
        for secure selective dropping of TLS records.
        """
        with open('assets/keys/s_public.pem', 'rb') as f:
            self.sender_public_key = pickle.load(f)
        with open('assets/keys/r_publics.pem', 'rb') as f:
            self.receiver_public_keys = pickle.load(f)
        with open('assets/keys/r_secrets.pem', 'rb') as f:
            self.receiver_secret_keys = pickle.load(f)
    
    def __repr__(self):
        return ("<ProxySession %s [client: %s] --> [proxy: %s] --> [server: %s]>" % 
                (hex(id(self)), self.client_connection.peer_address, 
                 self.proxy_bind_address, self.server_connection.peer_address))
        
    def __str__(self):
        return "<ProxySession %s>" % hex(id(self))
        
    def connect_to_server(self, target_address):
        """Establish connection to the target server"""
        self.server_connection.peer_address = target_address
        logger.info("%s connecting to target %s" % (self, repr(target_address)))
        return self.server_connection.connect(target_address)
    
    def accept_client_connection(self):
        """Accept incoming client connection"""
        client_socket, client_address = self.proxy_socket.accept()
        self.client_connection = TcpSocketBuffer(client_socket)
        self.client_connection.peer_address = client_address
        logger.info("%s client %s has connected" % (
            self, repr(self.client_connection.peer_address)))
        return client_socket, client_address
    
    def get_active_sockets(self):
        """Return list of active sockets for this session"""
        return [self.client_connection.socket, self.server_connection.socket]
    
    def handle_socket_ready(self, ready_socket: socket.socket):
        """Handle data ready to read on a socket"""
        if ready_socket == self.proxy_socket:
            # New client connection
            self.accept_client_connection()
            self.connect_to_server(self.server_connection.peer_address)
        elif ready_socket == self.client_connection.socket:
            # Data from client to server
            self.on_data_peek(self.client_connection, self)
            self.on_data_received(self.client_connection, self.server_connection, 
                                  self, data_source="client")
        elif ready_socket == self.server_connection.socket:
            # Data from server to client  
            self.on_data_received(self.server_connection, self.client_connection, 
                                  self, data_source="server")
        return 
    
    def close_session(self):
        """Clean up and close the proxy session"""
        try:
            self.server_connection.socket.shutdown(2)
            self.server_connection.socket.close()
            self.client_connection.socket.shutdown(2)
            self.client_connection.socket.close()
        except socket.error as socket_exception:
            logger.warning("session.close(): Exception: %s" % repr(socket_exception))
        raise SessionTerminatedException()
    
    def on_data_received(self, 
                         source_socket: TcpSocketBuffer, 
                         destination_socket: TcpSocketBuffer, 
                         session: 'ProxySession', 
                         data_source: str="server"):
        """
        Handle data received from client or server
        
        This is the core method that implements selective TLS record dropping.
        """
        received_data = source_socket.recv(session.buffer_size)
        processed_data = received_data
        
        # Only process client data for selective dropping
        if (data_source == "client" and 
            self.operation_mode in (constants.AEAD_MODE, constants.NON_AEAD_MODE)
        ):
            processed_data = self._process_client_data_for_dropping(
                received_data, source_socket, session)
            
        # Close session if no data received
        if not len(processed_data):
            return session.close_session()
       
        # Forward processed data to destination
        if processed_data:
            destination_socket.sendall(processed_data)
        return processed_data
    
    def _process_client_data_for_dropping(self, 
                                          received_data: bytes, 
                                          source_socket: TcpSocketBuffer, 
                                          session: 'ProxySession'):
        """
        Process client data to implement selective TLS record dropping
        
        This method identifies drop mode markers in the data stream and collects
        TLS records that should be subject to dropping.
        """
        # Check if data contains drop mode control signals
        self.current_drop_mode = self._determine_drop_mode(received_data) 
        output_stream = b''
        
        # Normal mode: forward data as-is
        if self.current_drop_mode == constants.DO_NOTHING:  # 'none'
            output_stream = received_data
        # Drop mode: collect challenges for selective forwarding
        elif self.current_drop_mode == constants.START_DROP:  # 'drop'
            output_stream = self._handle_challenge_collection(
                received_data, source_socket, session)
            
        return output_stream
    
    def _handle_challenge_collection(self, 
                                      initial_data: bytes, 
                                      source_socket: TcpSocketBuffer, 
                                      session: 'ProxySession'):
        """
        Handle collection of TLS records (challenges) during drop mode
        
        Collects TLS records between DROP_BEGIN and DROP_END markers,
        then processes them according to the operation mode.
        """
        # Pass the inital subject data as is
        # subject data is before the drop begin marker and challenge data is after it
        subject_data = initial_data.split(constants.CHALLENGE_DROP_BEGIN)[0]
        challenge_data = initial_data.split(constants.CHALLENGE_DROP_BEGIN)[1]
        challenge_data += source_socket.recv(session.buffer_size)
        
        # Collect all challenge data until drop end marker
        while challenge_data:
            self.current_drop_mode = self._determine_drop_mode(challenge_data)
            if self.current_drop_mode == constants.STOP_DROP:  # 'done'
                # Found end marker - split and process
                split_data = challenge_data.split(constants.CHALLENGE_DROP_END)
                self.collected_challenges.append(split_data[0])
                remaining_data = split_data[1]
                logger.info('Challenge collection completed')
                break
            # Continue collecting challenges
            self.collected_challenges.append(challenge_data)
            challenge_data = source_socket.recv(8 * 1024)
            
        # Process collected challenges if we found the end marker
        if self.current_drop_mode == constants.STOP_DROP:  # 'done'
            processed_stream = subject_data
            processed_stream += self._apply_selective_dropping()
            processed_stream += remaining_data
            self.current_drop_mode = constants.DO_NOTHING  # back to 'none'
            return processed_stream
        
        return b''
    
    def _apply_selective_dropping(self):
        """
        Apply selective dropping to collected challenges based on operation mode
        
        Mode 1: Simple bit-based selection of TLS record pairs
        Mode 2: Oblivious transfer based selection of TLS record pairs
        """
        combined_challenges = b''.join(self.collected_challenges)
        output_stream = b''
        try:
            if self.operation_mode == constants.AEAD_MODE:
                # AEAD mode with oblivious transfer
                output_stream = self._process_aead_challenges(combined_challenges)
            elif self.operation_mode == constants.NON_AEAD_MODE:
                # Non-AEAD mode with simple pair selection
                output_stream = self._process_non_aead_challenges(combined_challenges)
        except Exception as e:
            logger.error(f"Error applying selective dropping: {e}")
        return output_stream
    
    def _process_aead_challenges(self, challenge_data: bytes):
        """
        Process challenges in AEAD mode using oblivious transfer
        
        In this mode, challenges can be either:
        1. OT replies (prefixed with REPLYBEGIN + 4-byte length) - 
        processed with OT receiver
        2. Normal TLS records - forwarded as-is
        
        The data stream may contain a mix of both types. OT replies are prefixed with
        REPLYBEGIN followed by a 4-byte big-endian length of the pickled data.
        """
        output_stream = b''
        pair_index = 0
        num_blocks = 0
        # Check if data contains OT replies
        if constants.OT_REPLY_BEGIN_MARKER in challenge_data:
            # Process data sequentially to handle mixed streams correctly
            remaining_data = challenge_data
            
            while constants.OT_REPLY_BEGIN_MARKER in remaining_data:
                # Find the next REPLYBEGIN marker
                marker_pos = remaining_data.find(constants.OT_REPLY_BEGIN_MARKER)
                # Add data before the marker (normal TLS records)
                if marker_pos > 0:
                    data_before_marker = remaining_data[:marker_pos]
                    # Find the first TLS record in the data before the marker
                    tls_start = data_before_marker.find(b'\x17\x03\x03')
                    if tls_start >= 0:
                        # Found TLS data - add only the TLS portion 
                        # (skip any pickled data before it)
                        tls_data = data_before_marker[tls_start:]
                        output_stream += tls_data
                        num_blocks += len(tls_data) / 1522
                        
                # Extract OT reply using length prefix
                ot_reply_start = marker_pos + len(constants.OT_REPLY_BEGIN_MARKER)
                ot_reply_data, data_after = self._extract_ot_reply_by_length(
                    remaining_data[ot_reply_start:]
                )
                
                if ot_reply_data:
                    # Process the OT reply
                    self.ot_receiver.public = self.receiver_public_keys[pair_index]
                    self.ot_receiver.secret = self.receiver_secret_keys[pair_index]
                    
                    deserialized_reply = pickle.loads(ot_reply_data)
                    processed_message = self.ot_receiver.elect(
                        self.sender_public_key, 
                        self.verifier_selection_bits[pair_index], 
                        *deserialized_reply
                    )
                    output_stream += processed_message
                    num_blocks += 1
                    pair_index += 1
                
                # Continue with remaining data 
                remaining_data = data_after
            
            # Add any remaining normal data
            if remaining_data:
                num_blocks += len(remaining_data) / 1522
                output_stream += remaining_data
        else:
            # No OT replies found, treat as normal TLS records
            output_stream = challenge_data

        return output_stream
    
    def _extract_ot_reply_by_length(self, data: bytes) -> tuple[bytes, bytes]:
        """
        Extract a single OT reply from data using length prefix.
        
        Format: [4-byte_length][pickled_reply][remaining_data]
        
        Args:
            data: Data starting after REPLYBEGIN marker
            
        Returns:
            Tuple of (ot_reply_data, remaining_data)
        """
        if len(data) < 4:
            # Not enough data for length prefix
            return b'', data
        
        # Read 4-byte big-endian length
        length = int.from_bytes(data[:4], 'big')
        
        if len(data) < 4 + length:
            # Not enough data for the complete OT reply
            return b'', data
        
        # Extract the pickled OT reply and remaining data
        ot_reply_data = data[4:4 + length]
        remaining_data = data[4 + length:]
        
        return ot_reply_data, remaining_data
                
    def _process_non_aead_challenges(self, challenge_data: bytes):
        """
        Process challenges in non-AEAD mode using simple pair selection
        
        Challenges are assumed to come in pairs. For each pair, the selection bit
        determines which challenge is forwarded and which is dropped.
        """
        tls_records, leftover_data = utils.parse_tls_record_packets(challenge_data)
        output_stream = b''  # Reconstruct the stream
        idx = 0
        pair_index = 0

        while idx < len(tls_records):
            if idx in self.blocks_to_modify:
                selection_bit_for_pair = self.verifier_selection_bits[pair_index] 
                if selection_bit_for_pair == 0:
                    output_stream += tls_records[idx]
                else:
                    output_stream += tls_records[idx + 1]
                pair_index += 1
                idx += 1
            else:
                output_stream += tls_records[idx]
            idx += 1
                
        # Add any remaining data that wasn't part of TLS records        
        output_stream += leftover_data
        return output_stream
    
    def _determine_drop_mode(self, data):
        """
        Determine the current drop mode based on control markers in data
        
        Returns:
        - 'drop': Found DROP_BEGIN marker - start collecting challenges
        - 'done': Found DROP_END marker - finish collecting challenges  
        - 'none': No control markers - normal forwarding mode
        """
        new_drop_mode = constants.DO_NOTHING  # default to 'none'
        
        if constants.CHALLENGE_DROP_BEGIN in data:
            logger.debug(utils.format_log_message(
                'Challenge collection mode activated'))
            new_drop_mode = constants.START_DROP  # 'drop'
            # Extract and process the blocks_to_modify data
            split_data = data.split(constants.CHALLENGE_DROP_BEGIN)
            if len(split_data) > 1:
                self.blocks_to_modify = pickle.loads(split_data[1])
                # Don't include the control data in challenge collection
                # The actual challenge data starts after the control data
        elif constants.CHALLENGE_DROP_END in data:
            logger.debug(utils.format_log_message(
                'Challenge collection mode deactivated'))
            new_drop_mode = constants.STOP_DROP  # 'done'
            
        # Return new mode if it changed, otherwise keep current mode
        if new_drop_mode != constants.DO_NOTHING:
            return new_drop_mode
        else:
            return self.current_drop_mode
    
    def on_data_peek(self, source_socket, session): 
        """Hook for inspecting data before processing - currently unused"""
        pass
        
    def modify_client_data(self, session, data): 
        """Hook for modifying client data - currently unused"""
        return data
        
    def modify_server_data(self, session, data): 
        """Hook for modifying server data - currently unused"""
        return data


class ProxyServer(object):
    """
    Main proxy server implementing selective TLS record dropping
    
    This proxy sits between clients and servers, selectively dropping
    TLS application data records based on oblivious transfer protocols
    to enable privacy-preserving email verification.
    """
    
    def __init__(self, listen_address, target_address, buffer_size=4096, 
                 loop_delay=0.0001, operation_mode=constants.NON_AEAD_MODE):
        self.monitored_sockets = set([])
        self.active_sessions = {}  # socket -> ProxySession mapping
        self.event_callbacks = {}  # callback name -> function mapping
        
        self.listen_address = listen_address
        self.target_address = target_address
        self.operation_mode = operation_mode  # 1: non-AEAD, 2: AEAD
        
        self.buffer_size = buffer_size
        self.loop_delay = loop_delay
        
        # Set up the listening socket
        self.listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listening_socket.bind(listen_address)
        self.listening_socket.listen(200)
        
    def __str__(self):
        return ("<Proxy %s listen=%s target=%s>" % 
                (hex(id(self)), self.listen_address, self.target_address))
                
    def get_session_for_socket(self, socket_conn):
        """Get the proxy session associated with a socket"""
        return self.active_sessions.get(socket_conn)
        
    def register_event_callback(self, event_name, callback_function):
        """Register a callback function for proxy events"""
        self.event_callbacks[event_name] = callback_function
        
    def run_proxy_loop(self):
        """
        Main event loop for the proxy server
        
        Uses select() to monitor sockets for incoming data and handles
        new connections and data forwarding between clients and servers.
        """
        self.monitored_sockets.add(self.listening_socket)
        
        while True:
            time.sleep(self.loop_delay)
            ready_to_read, _, _ = select.select(self.monitored_sockets, [], [])
            
            for ready_socket in ready_to_read:
                # Skip sockets that were removed during processing
                if ready_socket not in self.monitored_sockets: 
                    continue
                    
                current_session = None
                try:
                    if ready_socket == self.listening_socket:
                        current_session = self._handle_new_client_connection(
                            ready_socket)
                    else:
                        self._handle_existing_session_data(ready_socket)
                        
                except Exception as error:
                    logger.error("main loop error: %s" % repr(error))
                    self._handle_session_error(current_session, ready_socket, error)
    
    def _handle_new_client_connection(self, listening_socket):
        """
        Handle new client connection to the proxy
        
        Creates a new proxy session and establishes connection to target server.
        """
        new_session = ProxySession(
            listening_socket, 
            target_address=self.target_address, 
            operation_mode=self.operation_mode, 
            buffer_size=self.buffer_size
        )
        new_session.handle_socket_ready(listening_socket)
        
        # Register session for both client and server sockets
        for session_socket in new_session.get_active_sockets():
            self.active_sessions[session_socket] = new_session
        self.monitored_sockets.update(new_session.get_active_sockets())
        
        return new_session
    
    def _handle_existing_session_data(self, data_ready_socket):
        """Handle incoming data on existing session sockets"""
        try:
            session = self.get_session_for_socket(data_ready_socket)
            session.handle_socket_ready(data_ready_socket)
        except SessionTerminatedException:
            # Session ended normally - clean up
            self.monitored_sockets.difference_update(session.get_active_sockets())
            logger.warning("%s terminated." % session)
    
    def _handle_session_error(self, session, problematic_socket, error):
        """Handle errors that occur during session processing"""
        if session:
            logger.error("Removing sockets for session that raised exception: %s" % repr(session))
            try:
                session.close_session()
            except SessionTerminatedException: 
                pass
            self.monitored_sockets.difference_update(session.get_active_sockets())
        elif problematic_socket and problematic_socket != self.listening_socket:
            # Error on client/server socket - safe to close
            logger.error("Removing problematic socket from monitoring")
            problematic_socket.close()
            self.monitored_sockets.remove(problematic_socket)
        else:
            # Fatal error on listening socket
            raise


def main():
    """
    Main entry point for the TLS selective dropping proxy
    
    Parses command line arguments and starts the proxy server.
    """
    from optparse import OptionParser
    return_code = 0
    usage = """usage: %prog [options]
    
       example: %prog --listen 0.0.0.0:25 --remote mail.server.tld:25 
    """
    parser = OptionParser(usage=usage)
    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose", default=True,
                      help="reduce logging output [default: %default]")
    parser.add_option("-l", "--listen", dest="listen", 
                      help=("proxy listen address ip:port"
                            "[default: 0.0.0.0:<remote_port>]"))
    parser.add_option("-r", "--remote", dest="remote", 
                      help="target server address ip:port to forward connections to")
    parser.add_option("-k", "--key", dest="key", default="server.pem", 
                      help=("SSL certificate and private key file, PEM format"
                            "[default: %default]"))
    parser.add_option("-b", "--buffer-size", dest="buffer_size", type="int", 
                      default=4*1024,
                      help="socket buffer size in bytes [default: %default]")
    parser.add_option("-m", "--mode", dest="mode", type="str", default="non-AEAD",
                      help=("operation mode: non-AEAD, AEAD [default: %default]")) 
    
    # Parse and validate command line arguments
    (options, args) = parser.parse_args()
    
    if not options.verbose:
        logger.setLevel(logging.DEBUG)
        
    if not options.remote:
        parser.error("--remote option is required")
        
    # Parse target server address
    if ":" not in options.remote and options.listen and ":" in options.listen:
        # No port in remote, use port from listen address
        options.remote = (options.remote.strip(), int(options.listen.strip().split(":")[1]))
        logger.warning("No remote port specified - using listen port: %s:%d" % options.remote)
    elif ":" in options.remote:
        remote_parts = options.remote.strip().split(":")
        options.remote = (remote_parts[0], int(remote_parts[1]))
    else:
        parser.error("Remote address must be in format <host>:<port>")
        
    # Parse proxy listen address
    if not options.listen:
        logger.warning("No listen address specified - using 0.0.0.0:%d" % options.remote[1])
        options.listen = ("0.0.0.0", options.remote[1])
    elif ":" in options.listen:
        listen_parts = options.listen.strip().split(":")
        options.listen = (listen_parts[0], int(listen_parts[1]))
    else:
        options.listen = (options.listen.strip(), options.remote[1])
        logger.warning("No listen port specified - using remote port: %s:%d" % options.listen)
        
    
    if options.mode == "AEAD":
        operation_mode = constants.AEAD_MODE
    else:
        operation_mode = constants.NON_AEAD_MODE

    # Initialize and start the proxy server
    proxy_server = ProxyServer(
        listen_address=options.listen, 
        target_address=options.remote, 
        operation_mode=operation_mode,
        buffer_size=options.buffer_size, 
        loop_delay=0
    )
    logger.info("%s ready." % proxy_server)
    
    # Set up profiling
    import cProfile
    import pstats
    import io
    from pstats import SortKey
    
    profiler = cProfile.Profile()
    profiler.enable()
    try:
        proxy_server.run_proxy_loop()
    except KeyboardInterrupt:
        logger.warning("Received Ctrl+C - Shutting down proxy server")
        return_code += 1
    profiler.disable()
    
    # Save profiling results
    string_buffer = io.StringIO()
    sort_by = SortKey.CUMULATIVE
    profile_stats = pstats.Stats(profiler, stream=string_buffer).sort_stats(sort_by)
    profile_stats.dump_stats("tmp/proxy_performance.txt")
    print(string_buffer.getvalue())
        
    sys.exit(return_code)
    
    
if __name__ == '__main__':
    main()