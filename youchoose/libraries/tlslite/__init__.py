# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""TLS Lite is a free python library that implements SSL and TLS. TLS Lite
supports RSA and SRP ciphersuites. TLS Lite is pure python, however it can use
other libraries for faster crypto operations. TLS Lite integrates with several
stdlib neworking libraries.

API documentation is available in the 'docs' directory.

If you have questions or feedback, feel free to contact me.

To use, do::

    from tlslite import TLSConnection, ...

If you want to import the most useful objects, the cleanest way is::

    from tlslite.api import *

Then use the :py:class:`TLSConnection` class with a socket.
(Or, use one of the integration classes in :py:mod:`tlslite.integration`).
"""

import sys
import os

# Add the libraries directory to the Python path so that tlslite can be imported
# as a top-level module from within the library itself
current_dir = os.path.dirname(os.path.abspath(__file__))
libraries_dir = os.path.dirname(current_dir)
if libraries_dir not in sys.path:
    sys.path.insert(0, libraries_dir)

from tlslite.api import *
from tlslite.api import __version__ # Unsure why this is needed, but it is
