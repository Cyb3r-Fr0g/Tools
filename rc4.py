from Crypto.Cipher import ARC4
import binascii
import string
import time
import sys

def is_readable_text(text, threshold=0.8):
    printable = set(string.printable)
    printable_ratio = sum(c in printable for c in text) / len(text)
    return printable_ratio > threshold

def rc4_cracker(ciphertext, wordlist):
    total_words = len(wordlist)
    try:
        for i, password in enumerate(wordlist):
            if i % 1000 == 0:  # Print progress every 1000 attempts
                print(f"Tried {i}/{total_words} passwords... ({i/total_words*100:.2f}%)")
                sys.stdout.flush()  # Ensure the output is displayed immediately
            
            cipher = ARC4.new(password.encode())
            plaintext = cipher.decrypt(ciphertext)
            try:
                decoded = plaintext.decode('utf-8')
                if is_readable_text(decoded):
                    return password, decoded
            except UnicodeDecodeError:
                pass
    except KeyboardInterrupt:
        print("\nCracking interrupted by user.")
        return None, None
    return None, None

def main():
    start_time = time.time()
    print("Starting password cracking...")

    # Load the wordlist from a file
    with open('/home/kali/words.txt', 'r') as f:
        wordlist = [line.strip() for line in f.readlines()]

    print(f"Loaded {len(wordlist)} words from the wordlist.")

    # Define the RC4-encrypted ciphertext
    ciphertext_hex = '6fce38f8836e82d446c3af46eb3a945a97bb8088256751e47f73a02943883165'
    ciphertext = binascii.unhexlify(ciphertext_hex)

    # Crack the password
    password, plaintext = rc4_cracker(ciphertext, wordlist)

    if password:
        print(f"\nSuccess! Password found: {password}")
        print(f"Decrypted text: {plaintext}")
    else:
        print("\nNo readable plaintext found with any password in the wordlist.")

    end_time = time.time()
    print(f"Time taken: {end_time - start_time:.2f} seconds")

if __name__ == '__main__':
    main()
