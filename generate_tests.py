import csv
import random
import os
import ascon  # Make sure you have installed this library

# Define constants
KEY = bytes.fromhex("0123456789abcdef123456789abcdef0")           # Constant 128-bit key
PLAINTEXT = bytes.fromhex("bc0261a21587b022dee4f13179e098ff")     # Constant 128-bit plaintext
ASSOC_DATA = bytes.fromhex("0001020304050607")                    # Constant 64-bit associated data
NONCE = bytes.fromhex("6aaabf06687b743f3bbd61319873db12")         # Constant 128-bit nonce

# Number of rows to generate
NUM_ROWS = 2000

# Function to generate a random 128-bit hex value
def generate_random_128bit_hex():
    return os.urandom(16)

# Function to generate a random 64-bit hex seed
def generate_random_64bit_hex():
    return os.urandom(8).hex()

# Function to generate a random 32-bit hex seed
def generate_random_32bit_hex():
    return os.urandom(4).hex()

print("len(key) = " + str(len(KEY)))

# Generate data
rows = []
for i in range(NUM_ROWS):
    group = random.randint(0, 1)               # Random group bit (0 or 1)
    if group == 1:
        nonce = generate_random_128bit_hex()       # Random 128-bit nonce
    else:
        nonce = NONCE
    seed = generate_random_64bit_hex()         # Random 64-bit seed

    # Perform Ascon-128 encryption to get the ciphertext
    ciphertext = ascon.encrypt(KEY, nonce, ASSOC_DATA, PLAINTEXT, variant="Ascon-128").hex()
    
    # Append row data
    rows.append([KEY.hex(), PLAINTEXT.hex(), nonce.hex(), ASSOC_DATA.hex(), ciphertext, group, seed])

# Write to CSV file
with open("ascon_test_data.csv", mode="w", newline="") as file:
    writer = csv.writer(file)
    # Write header
    writer.writerow(["key", "plaintext", "nonce", "assoc_data", "ciphertext", "group", "seed"])
    # Write rows
    writer.writerows(rows)

print("CSV file 'ascon_test_data.csv' generated successfully.")
