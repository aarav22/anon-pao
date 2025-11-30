import base64
import os
import random
import constants
import json

from PIL import Image
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage

# Account for \r\n line breaks every 76 base64 characters
# 1460 base64 chars (= 1460 bytes) # ASCII encoding
# 19 lines of 76 characters = 1444 bytes
# (1460/76 - 19) lines of 76 characters = 16 bytes

# 1460 bytes
# + 19 line breaks (\r\n) (= 38 bytes) 
# + 16 bytes
# + 1 line break (\r\n) (= 2 bytes) for remaining bytes

# = 1500 bytes total
MAX_BASE64_CHARS = 1460

def create_interleaved_image_email(
    subject: str,
    msg: str, 
    receiver: str,
    sender: str,
    image_path: str,
    num_different_blocks: int = 160,
    optimize: bool = False
) -> str:
    """
    Create email with interleaved image blocks that align with TLS records.
    
    Key insight: Base64 encoding happens AFTER block creation, so we need to:
    1. Create interleaved raw image blocks
    2. Base64 encode the entire interleaved data
    3. Ensure the base64 output aligns with TLS record boundaries
    """
    
    # Create interleaved image blocks
    interleaved_blocks, block_info = create_interleaved_image_blocks(
        image_path, num_different_blocks
    )

    test_saving_images(block_info, interleaved_blocks)

    # Create MIME message
    mime_msg = MIMEMultipart()    
    mime_msg['From'] = sender
    mime_msg['To'] = receiver  
    mime_msg['Subject'] = subject
    
    # Add text part
    text_part = MIMEText(
        f"{msg}\n\nInterleaved image blocks: {len(interleaved_blocks)} pairs")
    mime_msg.attach(text_part)

    # copy mime_msg to mime_msg_2
    mime_msg_2 = MIMEMultipart()
    mime_msg_2['From'] = mime_msg['From']
    mime_msg_2['To'] = mime_msg['To']
    mime_msg_2['Subject'] = mime_msg['Subject']
    
    # Copy all existing parts
    for part in mime_msg.get_payload():
        mime_msg_2.attach(part)

    # attach mime image attachment; attach the original image
    original_attachment = MIMEImage(open('tmp/img_a.bmp', 'rb').read(), _subtype='bmp')
    original_attachment.add_header('Content-Disposition', 'attachment',
                                   filename=os.path.basename(image_path))
    mime_msg.attach(original_attachment)

    # Manual base64 encoding with TLS record alignment
    aligned_attachment = create_tls_aligned_attachment(
        interleaved_blocks, image_path, block_info
    )
    mime_msg_2.attach(aligned_attachment)

    # Save both messages to separate files for comparison
    with open('tmp/mime_msg_original.txt', 'wb') as f:
        f.write(mime_msg.as_bytes())
    
    with open('tmp/mime_msg_with_aligned.txt', 'wb') as f:
        f.write(mime_msg_2.as_bytes())
    
    print(f"Saved messages to:")
    print(f"  - mime_msg_original.txt ({len(mime_msg.as_bytes())} bytes)")
    print(f"  - mime_msg_with_aligned.txt ({len(mime_msg_2.as_bytes())} bytes)")

    return mime_msg_2.as_string()

def create_interleaved_image_blocks(image_path: str, num_different_blocks: int):
    """
    Create two image variants and interleave their blocks.
    
    Returns:
        List of block_a and block_b and metadata
    """
    # Read the entire BMP file including headers
    with open(image_path, 'rb') as f:
        original_bmp_data = f.read()
    
    # Also open with PIL to get dimensions and verify format
    with Image.open(image_path) as original_img:
        if original_img.mode != 'RGB':
            print(f"Converting image to RGB mode: {image_path}")
            original_img = original_img.convert('RGB')
        
        width, height = original_img.size
            
        # Convert to raw bytes
        img_a_bytes = bytearray(original_bmp_data)
        img_b_bytes = bytearray(original_bmp_data)

        # Base64 encodes 3 raw bytes into 4 base64 characters
        # So max raw bytes = (1460 * 3) / 4 = 1095
        target_raw_size = (MAX_BASE64_CHARS * 3) // 4

        # Ensure block size is multiple of 3 for clean base64 encoding
        target_raw_size = (target_raw_size // 3) * 3  # Should be 1095

        total_bytes = len(img_a_bytes)
        num_blocks = max(1, total_bytes // target_raw_size)
        actual_block_size = target_raw_size # total_bytes // num_blocks

        # Make it multiple of 3 for base64 alignment
        actual_block_size = (actual_block_size // 3) * 3

        # Select blocks to make different (skip first 1 block)
        # first block contains the headers of the image
        offset = 1  # Skip first 1 block
        available_blocks = max(0, num_blocks - offset)
        different_blocks = min(num_different_blocks, available_blocks)
        if different_blocks > 0:
            blocks_to_modify = random.sample(range(
                offset, num_blocks
            ), different_blocks)
        else:
            blocks_to_modify = []
        
        # Modify selected blocks
        for block_idx in blocks_to_modify:
            start_pos = block_idx * actual_block_size
            end_pos = min(start_pos + actual_block_size, len(img_a_bytes))
            
            # modify_block_intensity(img_a_bytes, start_pos, end_pos, +30)  # Brighter
            # modify_block_intensity(img_b_bytes, start_pos, end_pos, -30)  # Darker
            modify_block_color(img_a_bytes, start_pos, end_pos, 'red')    # Red
            modify_block_color(img_b_bytes, start_pos, end_pos, 'green')  # Green
        
        # Create interleaved block pairs
        interleaved_blocks = []

        # This will contain updated indices of blocks that are to be dropped
        # based on their ordering in interleaved blocks.
        # 
        # Example: if blocks_to_modify is [0, 2, 4] (original block indices)
        # Original structure: 
        # 0(block_a_0, block_b_0), 
        # 1(block_a_1), 
        # 2(block_a_2, block_b_2), 
        # 3(block_a_3), 
        # 4(block_a_4, block_b_4)
        # Interleaved structure: 
        # 0(block_a_0), 
        # 1(block_b_0), 
        # 2(block_a_1), 
        # 3(block_a_2), 
        # 4(block_b_2), 
        # 5(block_a_3), 6(block_a_4), 7(block_b_4)
        # Then blocks_to_modify_updated will be [0, 3, 6] (indices of block_a positions 
        # in interleaved structure)

        blocks_to_modify_updated = []
        order_idx = 0
        for block_idx in range(num_blocks):                
            start_pos = block_idx * actual_block_size
            end_pos = min(start_pos + actual_block_size, len(img_a_bytes))

            block_a = bytes(img_a_bytes[start_pos:end_pos])
            block_b = bytes(img_b_bytes[start_pos:end_pos])
            
            # if block_idx is not in blocks_to_modify, then only save block_a
            # and block_b will be the same as block_a
            interleaved_blocks.append(block_a)
            if block_idx in blocks_to_modify:
                interleaved_blocks.append(block_b)
                blocks_to_modify_updated.append(order_idx)
                order_idx += 1 # increment order_idx for block_b

            order_idx += 1 # increment order_idx for block_a

        assert len(blocks_to_modify_updated) == len(blocks_to_modify)

        if os.path.exists('tmp/config.json'):
            with open('tmp/config.json', 'r') as f:
                config = json.load(f)
            config['blocks_to_modify'] = blocks_to_modify_updated
            with open('tmp/config.json', 'w') as f:
                json.dump(config, f)

        # remaining_bytes
        start_pos = num_blocks * actual_block_size
        end_pos = len(img_a_bytes)

        def pad_to_tls_record(data: bytes, target_size: int) -> bytes:
            current_size = len(data)
            if current_size >= target_size:
                return data[:target_size]
            padding_needed = target_size - current_size
            padding = b'\x00' * padding_needed
            return data + padding

        # pad the remaining bytes
        block_a = pad_to_tls_record(bytes(img_a_bytes[start_pos:end_pos]), 
                                    actual_block_size)
        interleaved_blocks.append(block_a)

        print(f"actual_block_size: {actual_block_size}")
        print(f"len(img_a_bytes): {len(img_a_bytes)}")
        print(f"num_blocks: {num_blocks}")
        print(f"len(blocks_to_modify_updated): {len(blocks_to_modify_updated)}")
        print(f"len(interleaved_blocks): {len(interleaved_blocks)}")

        block_info = {
            'total_blocks': num_blocks,
            'num_different_blocks': different_blocks,
            'block_size': actual_block_size,
            'modified_blocks': blocks_to_modify_updated,
            'image_dimensions': (width, height)
        }
        
        return interleaved_blocks, block_info


def create_tls_aligned_attachment(interleaved_blocks, image_path, block_info):
    """
    Create attachment with manual base64 encoding aligned to TLS records.
    
    This is the key function that ensures each base64-encoded block
    fits exactly in one TLS record.
    """
    
    # Create the interleaved data with TLS record alignment
    aligned_data = bytearray()
    
    for block in interleaved_blocks:
        encoded_block = base64.b64encode(block)
        aligned_data.extend(encoded_block)
        
    # Create MIME attachment with pre-encoded data
    attachment = MIMEBase('image', 'bmp')
    
    # Add proper MIME line breaks (76 characters per line)
    base64_string = aligned_data.decode('ascii')

    def _wrap_base64_custom(base64_string, num_blocks):
        max_line_length = 76
        num_lines = len(base64_string) // max_line_length # 1460 // 76 = 19 lines
        remaining_bytes = (
            num_blocks * constants.TLS_RECORD_SIZE_LIMIT
            - num_lines * max_line_length 
            - 2 * num_lines # 76 * 19 + 2 * 19 = 1482 = 1500 - 18 # 2 bytes for crlf
        ) # 3122 - 40 * 76 - 2 * 40 = 16
        result = []
        i = 0
        while i < len(base64_string):
            # num_lines_in_a_record lines of 76 characters
            for _ in range(num_lines):
                if i >= len(base64_string):
                    break
                result.append(base64_string[i:i+max_line_length])
                i += max_line_length
            
            # 1 line of 16 characters
            if i < len(base64_string):
                result.append(base64_string[i:i+remaining_bytes])
                i += remaining_bytes
        
        return '\r\n'.join(result) 

    num_blocks = len(interleaved_blocks)
    wrapped_base64 = _wrap_base64_custom(base64_string, num_blocks).encode('ascii')
    
    attachment.set_payload(wrapped_base64)
    
    # Important: Don't let MIME re-encode it
    attachment.add_header('Content-Transfer-Encoding', 'base64')
    
    filename = os.path.basename(image_path).replace('.bmp', '_interleaved.bmp')
    attachment.add_header('Content-Disposition', 'attachment', filename=filename)

    test_dropping(
        wrapped_base64, block_info, image_path
    ) # saving the simulated dropped image

    return attachment

def modify_block_intensity(raw_bytes: bytearray, start_pos: int, end_pos: int, intensity_delta: int):
    """Modify pixel intensity in a raw byte block."""
    for i in range(start_pos, end_pos):
        old_value = raw_bytes[i]
        new_value = max(0, min(255, old_value + intensity_delta))
        raw_bytes[i] = new_value


def modify_block_color(raw_bytes: bytearray, start_pos: int, end_pos: int, color: str):
    """
    Modify pixel color in a raw byte block.
    
    Args:
        raw_bytes: The raw BMP data
        start_pos: Start position in the byte array
        end_pos: End position in the byte array
        color: Either 'red' or 'green'
    """
    # BMP stores pixels in BGR format (Blue, Green, Red)
    if color == 'red':
        # Set all pixels to red: B=0, G=0, R=255
        for i in range(start_pos, end_pos, 3):
            if i + 2 < end_pos:  # Ensure we have 3 bytes for BGR
                raw_bytes[i] = 0      # Blue = 0
                raw_bytes[i + 1] = 0  # Green = 0  
                raw_bytes[i + 2] = 255  # Red = 255
    elif color == 'green':
        # Set all pixels to green: B=0, G=255, R=0
        for i in range(start_pos, end_pos, 3):
            if i + 2 < end_pos:  # Ensure we have 3 bytes for BGR
                raw_bytes[i] = 0      # Blue = 0
                raw_bytes[i + 1] = 255  # Green = 255
                raw_bytes[i + 2] = 0  # Red = 0


def test_dropping(wrapped_base64, block_info, image_path):
    # saves the simulated dropped image as {base_name}_after_simulated_dropping.bmp
    try:
        # Convert aligned_data to string for processing
        full_base64 = wrapped_base64.decode('ascii')
        
        # Split into TLS record-sized blocks
        block_size = constants.TLS_RECORD_SIZE_LIMIT
        blocks = []
        offset = 0
        
        while offset < len(full_base64):
            block_end = min(offset + block_size, len(full_base64))
            block = full_base64[offset:block_end]
            blocks.append(block)
            offset = block_end

        blocks_to_modify = block_info['modified_blocks']
        # Simulate selective dropping: 
        # For modified blocks, alternately keep block_a or block_b
        # For non-modified blocks, keep the single block
        selected_blocks = []
        pair_index = 0  # Track which pair we're in
        idx = 0
        while idx < len(blocks):
            if idx in blocks_to_modify:
                if pair_index % 2 == 0:
                    selected_blocks.append(blocks[idx])
                else:
                    selected_blocks.append(blocks[idx + 1])
                pair_index += 1
                idx += 1
            else:
                selected_blocks.append(blocks[idx])
            idx += 1

        # Reconstruct the base64 data from selected blocks
        reconstructed_base64 = ''.join(selected_blocks)

        # Clean and decode
        # cleaned_base64 = ''.join(reconstructed_base64.split())
        decoded_data = base64.b64decode(reconstructed_base64)
        
        # Save the dropped result
        base_name = os.path.splitext(os.path.basename(image_path))[0]
        
        output_filename = f"tmp/{base_name}_after_simulated_dropping.bmp"
        with open(output_filename, 'wb') as f:
            f.write(decoded_data)
        print(f"Saved selectively dropped image as: {output_filename}")
        
    except Exception as e:
        print(f"Selective dropping test failed: {e}")


def test_saving_images(block_info, interleaved_blocks):
    interleaved_image_data = bytearray()
    img_a_data = bytearray()
    img_b_data = bytearray()
    blocks_to_modify = block_info['modified_blocks']

    idx = 0
    while idx < len(interleaved_blocks):
        modified = True if idx in blocks_to_modify else False
        img_a_block_idx = idx
        img_b_block_idx = None

        if modified:
            img_b_block_idx = img_a_block_idx + 1
            idx += 1 # increment idx for block_b
        else:
            img_b_block_idx = img_a_block_idx

        idx += 1 # increment idx for block_a

        img_a_data.extend(interleaved_blocks[img_a_block_idx])
        img_b_data.extend(interleaved_blocks[img_b_block_idx])
        interleaved_image_data.extend(interleaved_blocks[img_a_block_idx])
        if modified:
            interleaved_image_data.extend(interleaved_blocks[img_b_block_idx])

    print(f"len(img_a_data): {len(img_a_data)}")
    print(f"len(img_b_data): {len(img_b_data)}")
    print(f"len(interleaved_image_data): {len(interleaved_image_data)}")

    # save the bmp image
    with open('tmp/img_a.bmp', 'wb') as f:
        f.write(bytes(img_a_data))
    with open('tmp/img_b.bmp', 'wb') as f:
        f.write(bytes(img_b_data))
    with open('tmp/interleaved_image.bmp', 'wb') as f:
        f.write(bytes(interleaved_image_data))