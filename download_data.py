"""
download_data.py
================
Downloads the complete Wazuh alerts dataset from Hugging Face.
Run it once:   python download_data.py
"""

from core.preprocessor import download_dataset

# force=False means: skip the download if the file is already here.
# Change to force=True if you ever want a fresh copy.
download_dataset(force=False)