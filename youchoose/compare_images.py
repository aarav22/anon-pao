#!/usr/bin/env python3
"""
Script to compare two BMP images and find blocks that differ.
Based on the blocking algorithm from utils/image.py
"""

import os

def calculate_block_parameters(image_path):
    """Calculate block parameters using the same logic as image.py"""
    with open(image_path, 'rb') as f:
        original_bmp_data = f.read()
    
    # Same calculation as in image.py
    max_base64_chars = 1460
    target_raw_size = (max_base64_chars * 3) // 4
    target_raw_size = (target_raw_size // 3) * 3  # Should be 1095
    
    total_bytes = len(original_bmp_data)
    num_blocks = max(1, total_bytes // target_raw_size)
    actual_block_size = total_bytes // num_blocks
    actual_block_size = (actual_block_size // 3) * 3

    return {
        'total_bytes': total_bytes,
        'num_blocks': num_blocks,
        'actual_block_size': actual_block_size,
        'target_raw_size': target_raw_size
    }

def compare_image_blocks(img_a_path, img_b_path, output_image_path):
    """Compare two images block by block and find differences"""
    
    challenge_string = ""
    # Read both images
    with open(img_a_path, 'rb') as f:
        img_a_data = f.read()
    
    with open(img_b_path, 'rb') as f:
        img_b_data = f.read()
    
    with open(output_image_path, 'rb') as f:
        output_image_data = f.read()
    
    # Calculate block parameters
    params = calculate_block_parameters(img_a_path)
    
    print(f"Image A size: {len(img_a_data)} bytes")
    print(f"Image B size: {len(img_b_data)} bytes")
    print(f"Output image size: {len(output_image_data)} bytes")
    print(f"Block size: {params['actual_block_size']} bytes")
    print(f"Number of blocks: {params['num_blocks']}")
    print(f"Target raw size: {params['target_raw_size']} bytes")
    print()
    
    # Compare blocks
    different_blocks = []
    
    for block_idx in range(params['num_blocks']):
        start_pos = block_idx * params['actual_block_size']
        end_pos = min(start_pos + params['actual_block_size'], len(img_a_data))
        
        # Extract blocks
        block_a = img_a_data[start_pos:end_pos]
        block_b = img_b_data[start_pos:end_pos]
        block_output = output_image_data[start_pos:end_pos]
        
        # Compare blocks
        if block_output != block_a and block_output == block_b:
            challenge_string += "1"
            different_blocks.append({
                'block_index': block_idx,
                'start_pos': start_pos,
                'end_pos': end_pos,
                'size': end_pos - start_pos,
            })
        elif block_output == block_a and block_output != block_b:
            challenge_string += "0"
            different_blocks.append({
                'block_index': block_idx,
                'start_pos': start_pos,
                'end_pos': end_pos,
                'size': end_pos - start_pos,
            })

    return different_blocks, challenge_string


def main():
    img_a_path = ''
    img_b_path = ''
    output_image_path = ''
    
    print("Comparing images:")
    print(f"Image A: {img_a_path}")
    print(f"Image B: {img_b_path}")
    print(f"Output image: {output_image_path}")
    print()
    
    # Check if files exist
    if not os.path.exists(img_a_path):
        print(f"Error: {img_a_path} not found!")
        return
    
    if not os.path.exists(img_b_path):
        print(f"Error: {img_b_path} not found!")
        return
    
    if not os.path.exists(output_image_path):
        print(f"Error: {output_image_path} not found!")
        return
    
    # Compare the images
    different_blocks, challenge_string = compare_image_blocks(
        img_a_path, img_b_path, output_image_path)
    
    print(f"Different blocks: {len(different_blocks)}")
    print(f"challenge string:  {challenge_string}")

if __name__ == "__main__":
    main()
