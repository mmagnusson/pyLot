import os
import yaml

FINGERPRINTS_DIR = os.path.join(os.path.dirname(__file__), '../fingerprints')

def load_fingerprints():
    fingerprints = []
    for fname in os.listdir(FINGERPRINTS_DIR):
        if fname.endswith('.yaml'):
            path = os.path.join(FINGERPRINTS_DIR, fname)
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                fingerprints.append(data)
    return fingerprints 