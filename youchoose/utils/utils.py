import constants
import datetime

def format_log_message(message, prefix=''):
    """
    Format a message for logging with timestamp and optional prefix
    
    Args:
        message: The message to be logged
        prefix: Optional prefix to add to the message
        
    Returns:
        Formatted log message with timestamp
    """
    if isinstance(message, bytes):
        try:
            message = message.decode('utf-8')
        except Exception:
            message = str(message)
    
    timestamp = datetime.datetime.now().time().isoformat()
    log_message = f'{timestamp} {prefix}{message}'
    return log_message


def parse_ot_replies(reply_data: bytes) -> list[bytes]:
    """
    Parse oblivious transfer replies from collected challenge data
    
    Args:
        reply_data: Raw reply data containing OT responses
        
    Returns:
        List of parsed OT reply messages
    """
    reply_begin_marker = constants.OT_REPLY_BEGIN_MARKER
    
    # Split on the begin marker and remove the first empty element
    parsed_replies = reply_data.split(reply_begin_marker)[1:]
    return parsed_replies

def parse_tls_record_packets(tls_packet_data: bytes) -> tuple[list[bytes], bytes]:
    """
    Parse TLS application data packets from raw byte stream
    
    This function extracts individual TLS application data records from
    a stream of TLS packets, identifying them by their headers.
    
    Args:
        tls_packet_data: Raw bytes containing TLS packet data
        
    Returns:
        Tuple of (parsed_packets_list, remaining_unparsed_data)
    """
    parsed_packets = []
    hex_data = tls_packet_data.hex()
    
    while len(hex_data) > 0:
        # Look for TLS Application Data record header (0x17 0x03 0x03)
        tls_app_data_start = constants.TLS_APPLICATION_DATA_HEADER
        header_position = hex_data.find(tls_app_data_start)
        
        if header_position == -1:
            # No more TLS records found
            break
        
        # Extract packet length from the 2-byte length field after header
        length_field_start = header_position + len(tls_app_data_start)
        length_field_end = length_field_start + 4  # 2 bytes = 4 hex chars
        
        if length_field_end > len(hex_data):
            # Not enough data for complete length field
            break
            
        # Parse the length field (big-endian 16-bit integer)
        packet_length = int(hex_data[length_field_start:length_field_end], 16)
        
        # Calculate total packet size (header + length field + data)
        packet_end_position = (
            header_position + len(tls_app_data_start) + 4 + (packet_length * 2)
        )
        
        if packet_end_position > len(hex_data):
            # Not enough data for complete packet
            break
        
        # Extract the complete packet
        complete_packet_hex = hex_data[header_position:packet_end_position]
        parsed_packets.append(bytes.fromhex(complete_packet_hex))
        
        # Move to next packet
        hex_data = hex_data[packet_end_position:]
    
    # Return parsed packets and any remaining unparsed data
    remaining_data = bytes.fromhex(hex_data)
    return parsed_packets, remaining_data
