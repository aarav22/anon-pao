"""Gives users direct access to module classes."""
import sys
import os

# Add the libraries directory to the Python path so that tlslite can be imported
# as a top-level module from within the library itself
current_dir = os.path.dirname(os.path.abspath(__file__))
libraries_dir = os.path.dirname(current_dir)
if libraries_dir not in sys.path:
    sys.path.insert(0, libraries_dir)
    
from otc.otc import common, receive, send
