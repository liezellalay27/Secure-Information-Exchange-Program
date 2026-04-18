"""
Secure Information Exchange Program Simulation
Uses Diffie-Hellman for key exchange and AES-128 for encryption
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sys


class SecureExchangeSimulation:
    def __init__(self, p=199, g=127):
        """Initialize with prime p and generator g"""
        if p <= 1:
            raise ValueError("Prime p must be greater than 1")
        if g <= 1 or g >= p:
            raise ValueError(f"Generator g must be between 1 and {p-1}")
        
        self.p = p
        self.g = g
        self.exchange_log = []
        
    def ascii_to_private_key(self, char):
        """Convert ASCII character to private key (decimal value)"""
        if not isinstance(char, str) or len(char) != 1:
            raise ValueError("Input must be a single character")
        return ord(char)
    
    def compute_public_value(self, private_key):
        """Compute public value: g^private_key mod p"""
        if not isinstance(private_key, int) or private_key < 0:
            raise ValueError("Private key must be a non-negative integer")
        return pow(self.g, private_key, self.p)
    
    def compute_shared_key(self, public_value, private_key):
        """Compute shared key: public_value^private_key mod p"""
        if not isinstance(public_value, int) or public_value < 0:
            raise ValueError("Public value must be a non-negative integer")
        if not isinstance(private_key, int) or private_key < 0:
            raise ValueError("Private key must be a non-negative integer")
        return pow(public_value, private_key, self.p)
    
    def transform_shared_key_to_aes_key(self, shared_key):
        """
        Transform shared key to 128-bit AES key according to rules:
        - 1 char: alternate char and 'C' (16 chars total)
        - 2 chars: alternate chars and 'DD' (16 chars total)
        - 3 chars: chars separated by 'F' (16 chars total)
        """
        shared_key_str = str(shared_key)
        length = len(shared_key_str)
        
        if length == 1:
            # Single character: alternate with 'C'
            # Pattern: 1C1C1C1C1C1C1C1C (16 chars)
            key_str = (shared_key_str + 'C') * 8
        elif length == 2:
            # Two characters: alternate with 'DD'
            # Pattern: 58DD58DD58DD58DD (16 chars)
            key_str = (shared_key_str + 'DD') * 4
        elif length == 3:
            # Three characters: separated by 'F'
            # Pattern: 109F109F109F109F109F (20 chars, but we need 16)
            # Based on example: 109F109F109F109F109F is 20 chars
            # Let's truncate to 16 chars: 109F109F109F109F
            key_str = ((shared_key_str + 'F') * 5)[:16]
        else:
            # For other lengths, just repeat to fill 16 chars
            key_str = (shared_key_str * (16 // length + 1))[:16]
        
        # Convert to bytes (ASCII encoding)
        return key_str.encode('ascii')
    
    def chunk_message(self, message):
        """
        Split message into 16-character chunks (128 bits)
        Pad last chunk with '@' if needed
        """
        if not isinstance(message, str):
            raise ValueError("Message must be a string")
        if not message:
            raise ValueError("Message cannot be empty")
        
        chunks = []
        for i in range(0, len(message), 16):
            chunk = message[i:i+16]
            if len(chunk) < 16:
                chunk = chunk + '@' * (16 - len(chunk))
            chunks.append(chunk)
        return chunks
    
    def encrypt_message(self, message, aes_key):
        """Encrypt message using AES-128 in ECB mode"""
        if len(aes_key) != 16:
            raise ValueError("AES key must be exactly 16 bytes (128 bits)")
        
        chunks = self.chunk_message(message)
        encrypted_chunks = []
        
        for chunk in chunks:
            cipher = AES.new(aes_key, AES.MODE_ECB)
            chunk_bytes = chunk.encode('ascii')
            encrypted = cipher.encrypt(chunk_bytes)
            encrypted_chunks.append(encrypted)
        
        # Concatenate all encrypted chunks
        return b''.join(encrypted_chunks)
    
    def decrypt_message(self, encrypted_message, aes_key):
        """Decrypt message using AES-128 in ECB mode"""
        if len(aes_key) != 16:
            raise ValueError("AES key must be exactly 16 bytes (128 bits)")
        
        # Split into 16-byte chunks
        decrypted_chunks = []
        
        for i in range(0, len(encrypted_message), 16):
            encrypted_chunk = encrypted_message[i:i+16]
            cipher = AES.new(aes_key, AES.MODE_ECB)
            decrypted = cipher.decrypt(encrypted_chunk)
            decrypted_chunks.append(decrypted.decode('ascii'))
        
        # Concatenate and remove padding
        decrypted_message = ''.join(decrypted_chunks)
        # Remove '@' padding from the end
        return decrypted_message.rstrip('@')
    
    def simulate_exchange(self, user_a_char, user_b_char, message):
        """
        Simulate full information exchange between User A and User B
        Based on Diffie-Hellman key exchange and AES-128 encryption
        """
        print("=" * 70)
        print("SECURE INFORMATION EXCHANGE SIMULATION")
        print("=" * 70)
        print()
        
        # Step 1: Private Keys
        print("STEP 1: PRIVATE KEYS")
        print("-" * 70)
        private_key_a = self.ascii_to_private_key(user_a_char)
        private_key_b = self.ascii_to_private_key(user_b_char)
        
        print(f"User A's character: '{user_a_char}' -> Private Key: {private_key_a}")
        print(f"  Binary: {bin(private_key_a)[2:].zfill(8)}, Hex: {hex(private_key_a)[2:].upper()}")
        print()
        print(f"User B's character: '{user_b_char}' -> Private Key: {private_key_b}")
        print(f"  Binary: {bin(private_key_b)[2:].zfill(8)}, Hex: {hex(private_key_b)[2:].upper()}")
        print()
        
        # Step 2: Public Values
        print("STEP 2: PUBLIC VALUES (Diffie-Hellman)")
        print("-" * 70)
        public_value_a = self.compute_public_value(private_key_a)
        public_value_b = self.compute_public_value(private_key_b)
        
        print(f"User A's Public Value: g^a mod p = {self.g}^{private_key_a} mod {self.p} = {public_value_a}")
        print(f"User B's Public Value: g^b mod p = {self.g}^{private_key_b} mod {self.p} = {public_value_b}")
        print()
        
        # Step 3: Shared Key
        print("STEP 3: SHARED KEY COMPUTATION")
        print("-" * 70)
        shared_key_a = self.compute_shared_key(public_value_b, private_key_a)
        shared_key_b = self.compute_shared_key(public_value_a, private_key_b)
        
        print(f"User A computes: {public_value_b}^{private_key_a} mod {self.p} = {shared_key_a}")
        print(f"User B computes: {public_value_a}^{private_key_b} mod {self.p} = {shared_key_b}")
        
        if shared_key_a == shared_key_b:
            print(f"[OK] Shared keys match! Shared Key = {shared_key_a}")
        else:
            print("[ERROR] Shared keys don't match!")
            return None
        
        shared_key = shared_key_a
        print()
        
        # Step 4: AES Key Generation
        print("STEP 4: AES-128 KEY TRANSFORMATION")
        print("-" * 70)
        aes_key = self.transform_shared_key_to_aes_key(shared_key)
        aes_key_str = aes_key.decode('ascii')
        print(f"Shared Key: {shared_key}")
        print(f"Shared Key String: '{str(shared_key)}'")
        print(f"Transformation Rule:")
        shared_key_str = str(shared_key)
        if len(shared_key_str) == 1:
            print(f"  Length = 1: alternate '{shared_key_str}' and 'C' → '{aes_key_str}'")
        elif len(shared_key_str) == 2:
            print(f"  Length = 2: alternate '{shared_key_str}' and 'DD' → '{aes_key_str}'")
        elif len(shared_key_str) == 3:
            print(f"  Length = 3: '{shared_key_str}' separated by 'F' → '{aes_key_str}'")
        print(f"Hex representation: {aes_key.hex().upper()}")
        print(f"Key length: {len(aes_key)} bytes (128 bits)")
        print()
        
        # Step 5: Message Chunking
        print("STEP 5: MESSAGE CHUNKING")
        print("-" * 70)
        print(f"Original Message: \"{message}\"")
        print(f"Message length: {len(message)} characters")
        chunks = self.chunk_message(message)
        print(f"Number of chunks: {len(chunks)}")
        print()
        
        for i, chunk in enumerate(chunks, 1):
            hex_values = ' '.join([f"{ord(c):02X}" for c in chunk])
            print(f"Sub-message {i}: \"{chunk}\"")
            print(f"  Hex: [{hex_values}]")
            print()
        
        # Step 6: Encryption
        print("STEP 6: ENCRYPTION")
        print("-" * 70)
        encrypted_message = self.encrypt_message(message, aes_key)
        print(f"Encrypted message (hex): {encrypted_message.hex().upper()}")
        print(f"Encrypted message length: {len(encrypted_message)} bytes")
        print()
        
        # Step 7: Decryption
        print("STEP 7: DECRYPTION")
        print("-" * 70)
        decrypted_message = self.decrypt_message(encrypted_message, aes_key)
        print(f"Decrypted message: \"{decrypted_message}\"")
        print()
        
        # Verification
        print("STEP 8: VERIFICATION")
        print("-" * 70)
        if decrypted_message == message:
            print("[OK] SUCCESS! Decrypted message matches original message!")
        else:
            print("[ERROR] Decrypted message doesn't match!")
            print(f"Original:  \"{message}\"")
            print(f"Decrypted: \"{decrypted_message}\"")
        
        print("=" * 70)
        print()
        
        return {
            'private_key_a': private_key_a,
            'private_key_b': private_key_b,
            'public_value_a': public_value_a,
            'public_value_b': public_value_b,
            'shared_key': shared_key,
            'aes_key': aes_key,
            'encrypted_message': encrypted_message,
            'decrypted_message': decrypted_message
        }


def main():
    # Initialize the simulation
    sim = SecureExchangeSimulation(p=199, g=127)
    
    print("\n" + "=" * 70)
    print("SECURE INFORMATION EXCHANGE PROGRAM")
    print("=" * 70)
    print()
    print("What would you like to do?")
    print("1. Run Example 1 (From Assignment: '9' and '§')")
    print("2. Run Example 2 (Custom: 'A' and 'B')")
    print("3. Enter Your Own Characters and Message")
    print("=" * 70)
    
    choice = input("\nSelect option (1, 2, or 3): ").strip()
    
    if choice == "1":
        print("\nEXAMPLE 1: From Assignment")
        print("User A: '9' (ASCII 57), User B: '§' (ASCII 167)")
        print()
        result = sim.simulate_exchange('9', '§', "The Mandalorian Must Always Recite, This is The Way!")
        
    elif choice == "2":
        print("\nEXAMPLE 2: Custom Test")
        print("User A: 'A' (ASCII 65), User B: 'B' (ASCII 66)")
        print()
        result = sim.simulate_exchange('A', 'B', "Hello World!")
        
    elif choice == "3":
        print("\n" + "-" * 70)
        print("CUSTOM EXCHANGE")
        print("-" * 70)
        print()
        
        # Get User A's character
        while True:
            user_a = input("Enter User A's character (single character): ").strip()
            if len(user_a) == 1:
                break
            print("Error: Please enter exactly ONE character")
        
        # Get User B's character
        while True:
            user_b = input("Enter User B's character (single character): ").strip()
            if len(user_b) == 1:
                break
            print("Error: Please enter exactly ONE character")
        
        # Get message
        while True:
            message = input("Enter message to encrypt: ").strip()
            if message:
                break
            print("Error: Message cannot be empty")
        
        print()
        result = sim.simulate_exchange(user_a, user_b, message)
    
    else:
        print("\nInvalid option. Please select 1, 2, or 3.")
    

if __name__ == "__main__":
    main()