import re
import constants

CRLF = '\r\n'

def _fix_eols(data):
    return  re.sub(r'(?:\r\n|\n|\r(?!\n))', CRLF, data)

def _calc_padding_len(msg):
    return constants.TLS_RECORD_SIZE_LIMIT - len(msg)

def create_text_email(
        subject: str, 
        msg: str, 
        receiver: str, 
        sender: str, 
        num_msgs: int = 160, 
        optimize: bool = False
    ) -> str:
    """
    Create an email message body structured for YouChoose selective dropping protocol.
    
    The email is structured in three parts:
    1. Email headers + user message (non-droppable)
    2. Challenge sequence (selectively droppable by verifier) 
    3. Dummy termination message (non-droppable)
    
    Args:
        subject: Email subject line
        msg: User's actual message content
        receiver: Recipient email address
        sender: Sender email address  
        num_msgs: Number of challenge records to generate (default: 160)
        optimize: If True, skip padding for compact output; if False, pad each 
                 part to TLS record size limits for precise record control
    
    Returns:
        Complete email body as string, ready for SMTP transmission
    """
    
    # Part 1: Standard email headers and user content
    # This section cannot be selectively dropped by the verifier
    msg_body = f"""\
Subject: {subject}
To: {receiver}
From: {sender}

{msg}
"""
    
    if not optimize:
        # Pad email headers/content to exactly one TLS record
        # This ensures predictable record boundaries for selective dropping
        msg_body = _pad_to_record_size(msg_body)
        assert len(msg_body) == constants.TLS_RECORD_SIZE_LIMIT

    # Part 2: Challenge sequence for selective dropping
    # Each challenge alternates between "0" and "1" 
    # Verifier can selectively drop records containing either value
    for i in range(1, num_msgs + 1): 
        challenge_bit = str(i % 2)  # Alternates: "0", "1", "0", "1", ...
        
        if optimize:
            # Compact mode: just append the bit without padding
            msg_body += challenge_bit
        else:
            # Structured mode: pad each challenge to exactly one TLS record
            # This creates num_msgs records, each containing a single bit
            padded_challenge = _pad_to_record_size(challenge_bit)
            assert len(padded_challenge) == constants.TLS_RECORD_SIZE_LIMIT
            msg_body += padded_challenge

    # Part 3: Termination message 
    # Absorbs CRLF.CRLF bytes that mark end of email body
    # This section cannot be selectively dropped by the verifier
    if not optimize:
        msg_body += "dummy msg"

    return msg_body

def _pad_to_record_size(content: str) -> str:
    """
    Pad content to exactly TLS_RECORD_SIZE_LIMIT bytes with proper formatting.
    
    Handles SMTP constraints:
    - Lines must not exceed 100 characters  
    - Proper CRLF line endings required
    
    Args:
        content: String content to pad
        
    Returns:
        Padded content of exactly TLS_RECORD_SIZE_LIMIT bytes
    """
    # Calculate required padding accounting for line breaks
    target_length = _calc_padding_len(content) - len(content.split('\n')) + 1
    padded_content = content + ' ' * target_length
    
    # Wrap lines to 100 characters (using 102 to account for CRLF insertion)
    wrapped_content = '\n'.join(
        padded_content[i:i+100] 
        for i in range(0, len(padded_content), 102)
    )
    
    # Ensure proper CRLF line endings for SMTP compliance
    return _fix_eols(wrapped_content)
    