#!/usr/bin/env python3
"""
Email Hasher Script

This script takes an email address as a command line argument,
hashes it using the SHA-256 algorithm, and writes the hash to a file.

Usage:
    python email_hasher.py <email_address>

Example:
    python email_hasher.py example@email.com
"""

import sys
import hashlib

def hash_email(email):
    """
    Hash an email address using SHA-256 and return the hexadecimal digest.
    
    Args:
        email (str): The email address to hash
        
    Returns:
        str: The SHA-256 hash of the email in hexadecimal format
    """
    encoded_email = email.encode('utf-8')
    sha256_hash = hashlib.sha256(encoded_email).hexdigest()
    return(sha256_hash)

def write_hash_to_file(hash_value, filename = "hash.email"):
    """
    Write a hash value to a file.
    
    Args:
        hash_value (str): The hash value to write
        filename (str): The name of the file to write to (default: "hash.email")
    """
    with open(filename, "w") as file:
        file.write(hash_value)

def main():
    """
    Main function to process command line arguments and execute the script.
    """
    if len(sys.argv) == 2:
        email = sys.argv[1]
        hashed_email = hash_email(email)
        write_hash_to_file(hashed_email)
        print("Hashed email written to hash.email")
    else:
        print("Error. No email provided as command line argument")
        sys.exit(1)

if __name__ == "__main__":
    main()
