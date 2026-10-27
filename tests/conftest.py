import os
import sys

# Make the app's top-level modules (app, storage, parser, capture) importable from tests
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
