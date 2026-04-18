# Secure Information Exchange Program Simulation

## Overview
This program simulates secure information exchange between two users (User A and User B) using:
- **Diffie-Hellman key exchange** for establishing a shared secret
- **AES-128 encryption** for securing messages

## Specifications

### Cryptographic Parameters
- **Prime (p)**: 199
- **Generator (g)**: 127
- **Encryption**: AES-128 in ECB mode
- **Block size**: 128 bits (16 characters)
- **Padding character**: '@' (ASCII 0x40)

### How It Works

#### 1. Private Keys
Each user's private key is derived from the decimal ASCII value of a character:
- User A: Character '9' → ASCII 57 → Private Key = 57
- User B: Character '§' → ASCII 167 → Private Key = 167

#### 2. Public Value Calculation (Diffie-Hellman)
Each user computes their public value:
- **User A**: g^a mod p = 127^57 mod 199 = **17**
- **User B**: g^b mod p = 127^167 mod 199 = **75**

#### 3. Shared Key Computation
Both users compute the same shared key using each other's public values:
- **User A**: 75^57 mod 199 = **109**
- **User B**: 17^167 mod 199 = **109**

#### 4. AES Key Transformation
The shared key is transformed into a 128-bit (16-character) AES key:

| Shared Key Length | Transformation Rule | Example |
|-------------------|---------------------|---------|
| 1 character | Alternate with 'C' (8 times) | Shared Key: 1 → Key: `1C1C1C1C1C1C1C1C` |
| 2 characters | Alternate with 'DD' (4 times) | Shared Key: 58 → Key: `58DD58DD58DD58DD` |
| 3 characters | Separate with 'F' (5 times, truncate to 16) | Shared Key: 109 → Key: `109F109F109F109F` |

#### 5. Message Processing
Messages are split into 16-character chunks (128 bits):
- **Sub-message 1**: "The Mandalorian " (16 chars)
- **Sub-message 2**: "Must Always Reci" (16 chars)
- **Sub-message 3**: "te, This is The " (16 chars)
- **Sub-message 4**: "Way!@@@@@@@@@@@@" (12 chars + 4 '@' padding)

#### 6. Encryption/Decryption
Each sub-message is encrypted separately using AES-128, then concatenated. The receiver decrypts each chunk and removes padding.

## Usage

### Running the Program

```bash
python secure_exchange_simulation.py
```

This will run two examples:
1. The example from the assignment (User A: '9', User B: '§')
2. A custom test (User A: 'A', User B: 'B')

### Using the SecureExchangeSimulation Class

```python
from secure_exchange_simulation import SecureExchangeSimulation

# Create simulation instance
sim = SecureExchangeSimulation(p=199, g=127)

# Simulate exchange between two users
result = sim.simulate_exchange(
    user_a_char='9',  # User A's character
    user_b_char='§',  # User B's character
    message="The Mandalorian Must Always Recite, This is The Way!"
)

# Access results
print(f"Shared Key: {result['shared_key']}")
print(f"AES Key: {result['aes_key'].decode('ascii')}")
print(f"Encrypted (hex): {result['encrypted_message'].hex().upper()}")
```

### Class Methods

#### `ascii_to_private_key(char)`
Converts an ASCII character to its decimal value (private key).

#### `compute_public_value(private_key)`
Computes the Diffie-Hellman public value: g^private_key mod p

#### `compute_shared_key(public_value, private_key)`
Computes the shared key: public_value^private_key mod p

#### `transform_shared_key_to_aes_key(shared_key)`
Transforms the shared key into a 128-bit AES key according to the rules.

#### `chunk_message(message)`
Splits a message into 16-character chunks, padding the last chunk with '@' if needed.

#### `encrypt_message(message, aes_key)`
Encrypts a message using AES-128 in ECB mode.

#### `decrypt_message(encrypted_message, aes_key)`
Decrypts an encrypted message and removes padding.

#### `simulate_exchange(user_a_char, user_b_char, message)`
Runs a complete simulation and prints detailed output for each step.

## Example Output

```
======================================================================
SECURE INFORMATION EXCHANGE SIMULATION
======================================================================

STEP 1: PRIVATE KEYS
----------------------------------------------------------------------
User A's character: '9' → Private Key: 57
  Binary: 00111001, Hex: 39

User B's character: '§' → Private Key: 167
  Binary: 10100111, Hex: A7

STEP 2: PUBLIC VALUES (Diffie-Hellman)
----------------------------------------------------------------------
User A's Public Value: 127^57 mod 199 = 17
User B's Public Value: 127^167 mod 199 = 75

STEP 3: SHARED KEY COMPUTATION
----------------------------------------------------------------------
User A computes: 75^57 mod 199 = 109
User B computes: 17^167 mod 199 = 109
✓ Shared keys match! Shared Key = 109

STEP 4: AES-128 KEY TRANSFORMATION
----------------------------------------------------------------------
Shared Key: 109
Transformed to: '109F109F109F109F'
Hex representation: 31303946313039463130394631303946
Key length: 16 bytes (128 bits)

STEP 5: MESSAGE CHUNKING
----------------------------------------------------------------------
Original Message: "The Mandalorian Must Always Recite, This is The Way!"
Message length: 52 characters
Number of chunks: 4

Sub-message 1: "The Mandalorian "
  Hex: [54 68 65 20 4D 61 6E 64 61 6C 6F 72 69 61 6E 20]

[... additional sub-messages ...]

STEP 6: ENCRYPTION
----------------------------------------------------------------------
Encrypted message (hex): 7A0358E30A9CDD20AB3BC2B855EF7369...

STEP 7: DECRYPTION
----------------------------------------------------------------------
Decrypted message: "The Mandalorian Must Always Recite, This is The Way!"

STEP 8: VERIFICATION
----------------------------------------------------------------------
✓ SUCCESS! Decrypted message matches original message!
```

## Requirements

- Python 3.x
- pycryptodome library

Install dependencies:
```bash
pip install pycryptodome
```

## Security Notes

- This simulation uses ECB mode for educational purposes. In production, use CBC, GCM, or other secure modes.
- The Diffie-Hellman parameters (p=199, g=127) are small and for demonstration only.
- Real-world implementations should use much larger primes (at least 2048 bits).

## Key Insights

1. **Diffie-Hellman**: Both parties can compute the same shared key without transmitting it.
2. **AES-128**: Symmetric encryption ensures efficient message encryption/decryption.
3. **Block Cipher**: Messages are processed in fixed-size blocks (128 bits).
4. **Padding**: Ensures all blocks are complete, even if the message isn't a multiple of block size.

## License

Educational use only.