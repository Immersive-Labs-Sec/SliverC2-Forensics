import argparse
import base64
import gzip
import re
import json
from binascii import hexlify, unhexlify

from chacha20poly1305 import ChaCha20Poly1305
import base58
from protobufs import dns_pb2, sliver_pb2

encoders = {
    
    13: "b64",
    31: "words",
    22: "png",
    43: "b58",
    45: "gzip-words",
    49: "gzip",
    64: "gzip-b64",
    65: "b32",
    92: "hex"

}


msg_types = {
    0: "NOP",
    1: "TOTP",
    2: "Init",
    3: "Poll",
    4: "close",
    6: "manifest",
    7: "Data to implant",
    8: "Data from implant",
    9: "clear",

}


base64_standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
base64_modified = "a0b2c5def6hijklmnopqr_st-uvwxyzA1B3C4DEFGHIJKLM7NO9PQR8ST+UVWXYZ"

base32_standard = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
base32_modified = 'ab1c2d3e4f5g6h7j8k9m0npqrtuvwxyz'

base58_standard = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
base58_modified = '213465789aBcDeFgHjKLMNPQRSTUVWXYZAbCdEfGhiJkmnopqrstuvwxyz'


def decrypt_chacha(key, data):
    """Decrypt and Decompress Sliver Payload"""
    cip = ChaCha20Poly1305(key)
    nonce = data[:12]
    ciphertext = data[12:]
    compressed = cip.decrypt(nonce, ciphertext)
    return gzip.decompress(compressed)


def parse_output(decrypted):
    envelope = sliver_pb2.Envelope()
    envelope.ParseFromString(decrypted)
    print(f'  [-] Message Type: {envelope.Type}')
    print('[=] Message Data')
    print(envelope.Data)


def decode_nonce(nonce_value):
    """Takes a nonce value from a HTTP Request and returns the encoder that was used"""
    nonce_value = int(re.sub('[^0-9]','', nonce_value))
    encoder_id = nonce_value % 101
    return encoders[encoder_id]


def decode_b64(slv_data, compressed=False):
    """Uses the modifed alphabet from Sliver C2 to decode Base64"""
    table = slv_data.maketrans(base64_modified, base64_standard)
    std_data = slv_data.translate(table)
    padded = f"{std_data}{'=' * (len(std_data) % 4)}"
    decoded = base64.standard_b64decode(padded)
    if compressed:
        decoded = decode_gzip(decoded)
    return decoded


def decode_b32(slv_data):
    """Uses the modifed alphabet from Sliver C2 to decode Base32"""
    table = slv_data.maketrans(base32_modified, base32_standard)
    std_data = slv_data.translate(table)

    # Correctly Pad the encoded string
    while len(std_data) % 8 != 0:
        std_data = std_data + b'='

    decoded = base64.b32decode(std_data)
    return decoded


def decode_b58(slv_data):
    """Uses the modifed alphabet from Sliver C2 to decode Base58"""
    table = slv_data.maketrans(base58_modified, base58_standard)
    std_data = slv_data.translate(table)
    decoded = base58.b58decode(std_data)
    return decoded


def decode_words(word_list, compressed=False):
    """Decodes the sliver English Words Encoder without needing a wordlist"""
    decoded = []
    for word in word_list.split():
        
        value = 0
        for char in word:
            value += ord(char)
        value = value %256
        decoded.append(value)
    
    decoded = bytes(decoded)
    if compressed:
        decoded = decode_gzip(decoded)

    return decoded

def decode_gzip(slv_data):
    "Uncompress standard gzip compression"

    # Some Polling messsages have a GZIP nonce but are not actuall compressed. 
    try:
        return gzip.decompress(slv_data)
    except: 
        return slv_data


def decode_dns(possible_keys, file_data):
    encoded_payloads = file_data.split(b'\n')

    sessions = {}
    print("[+] Collecting Sessions")
    # reassemble each session based on session IDs
    for payload in encoded_payloads:
        # remove any `.`
        payload = payload.replace(b'.', b'')

        # First Try to determine the encoder
        encoder = 32

        for char in payload:
            if char not in base32_modified:
                encoder = 58

        decoded = None

        # Decode using the encoder we detected
        if encoder == 32:
            #print('  [-] Identified Base32 Encoder')
            decoded = decode_b32(payload)
        
        if encoder == 58:
            #print('  [-] Identified Base58 Encoder')
            decoded = decode_b58(payload)

        # Once we have decoded we need to parse out the encrypted data
        if decoded:
            dns_protobuf = dns_pb2.DNSMessage()
            dns_protobuf.ParseFromString(decoded)

            #print(dns_protobuf)

            if dns_protobuf.ID in sessions:
                sessions[dns_protobuf.ID]['segments'].append(dns_protobuf)
            else:
                sessions[dns_protobuf.ID] = {
                    'msg_type': dns_protobuf.Type,
                    'segments': [dns_protobuf]
                    }


    # Parse Sessions
    print("[+] Parsing Session Data")
    for session_id, session in sessions.items():
        print(f"[+] Session ID: {session_id}")
        segment_count = len(session['segments'])
        message_type = msg_types[session["msg_type"]]
        print(f'  [-] Message Type: {message_type}')
        print(f'  [-] Segments: {segment_count}')

        if message_type in ['TOTP', 'Poll', 'NOP']:
            # These message don't have a body
            continue
        
        #print(session['segments'])
        cipher_text = None

        # Init seems to have an extra session element a response from the server. 
        if message_type == 'Init' and len(session['segments']) > 1:
            if len(session['segments'][0].Data) == session['segments'][0].Size:
                cipher_text = session['segments'][0].Data
            else:
                print('[!] Session missing payloads!')
                continue

        # Check we have all the parts
        if len(session['segments']) == 1:
            if len(session['segments'][0].Data) == session['segments'][0].Size:
                cipher_text = session['segments'][0].Data
            else:
                print('[!] Session missing payloads!')
                continue

        # Handle Multi Segment Sessions
        if not cipher_text:
            combined = b''
            middle = {}
            for segment in session['segments']:
                middle[segment.Start] = segment.Data
            
            # Order our dict so we can reassemble
            middle = dict(sorted(middle.items()))
            for order, data in middle.items():
                combined = combined + data
            cipher_text = combined
            #continue

        #print(f'Cipher Text: {cipher_text}')
        decrypted = None

        # Process the payload data
        for chacha_key in possible_keys:
            # Ensure key is correct length, only an issues with some regex queries. 
            chacha_key = chacha_key[:32]

            try:
                decrypted = decrypt_chacha(chacha_key, cipher_text)
                # Stop if we get a valid decryption
                break
            except Exception as err:
                #print(err)
                # Silently pass so the brute force is not noisy
                pass
        if decrypted:
                print(f'  [-] Session Key: {hexlify(chacha_key).decode()}')
                parse_output(decrypted)
        else:
            print("  [!] Session Key: Unable to find a valid key for this session")


def decode_http(possible_keys, file_data):
    session_key = None
    print('[+] Running HTTP Decoder')

    sessions = json.loads(file_data)

    for session in sessions:
        decrypted = None
        encoder = session.get('encoder')
        payload_data = session.get('body')

        print(f'[+] Processing: {session.get("request_uri")}')
        print(f'  [-] Decoding: {encoder}')
    
        if encoder == 'hex':
            cipher_text = unhexlify(payload_data)
        elif encoder == 'words':
            cipher_text = decode_words(payload_data)
        elif encoder == 'gzip-words':
            cipher_text = decode_words(payload_data, compressed=True)
        elif encoder == 'b64':
            cipher_text = decode_b64(payload_data)
        elif encoder == 'gzip-b64':
            cipher_text = decode_b64(payload_data, compressed=True)
        elif encoder == 'b32':
            cipher_text = decode_b32(payload_data)
        elif encoder == 'gzip':
            cipher_text = decode_gzip(payload_data)

        if not cipher_text:
            print(f'[!] No Cipher Text found in message for encoder {encoder}')
            return

        for chacha_key in possible_keys:
            # Ensure key is correct length, only an issues with some regex queries. 
            chacha_key = chacha_key[:32]
            decrypted = None
            try:
                decrypted = decrypt_chacha(chacha_key, cipher_text)
                # Stop if we get a valid decryption
                break
            except Exception as err:
                #print(err)
                # Silently pass so the brute force is not noisy
                pass

        if decrypted:
            # Update our possible keys to the valid key so we dont brute force every payload
            possible_keys = [chacha_key]
            print(f'  [-] Session Key: {hexlify(chacha_key).decode()}')
            try:
                parse_output(decrypted)
            except:
                pass
        else:
            print("  [!] Session Key: Unable to find a valid key for this session")


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Sliver C2 Decryptor')

    parser.add_argument(
        '--key',
        help='Session Key extracted from memory as hex',
        required=False)

    parser.add_argument(
        '--encoder',
        help='Encoding Mode',
        choices=['dns', 'http'],
        required=True
    )

    parser.add_argument(
        '--file_path',
        help='path to file with encoded data',
        required=True
    )

    parser.add_argument(
        '--force',
        help='Brute Force Key given a procdump file',
        required=False,
        default=False
    )

    args = parser.parse_args()


    with open(args.file_path, 'rb') as input_file:
        file_data = input_file.read()

    if args.force and args.key:
        print('[!] If you have the key there is no need to brute force?!?')
        exit(0)

    if args.force:
        print(f'[+] Finding all possible keys in {args.force}')
        with open(args.force, 'rb') as input_file:
            proc_dump_data = input_file.read()
            # This is going to be a large list
            key_pattern = b'\x00\x00(.{32}).{3}\x00\xc0\x00'
            old_pattern = b'(.{32})[^\x00]{3}\x00\xc0\x00'
            possible_keys = re.findall(key_pattern, proc_dump_data, re.DOTALL)

        # Dedup
        possible_keys = list(dict.fromkeys(possible_keys))

        # removat statisticly unlikley keys
        for key in possible_keys:
            if b'\x00\x00\x00' in key:
                possible_keys.remove(key)

        print(f'  [-] Found {len(possible_keys)} possible keys')
        print(f'  [*] Keys will be tested during first decryption attempt')

    else:
        possible_keys = [unhexlify(args.key)]

    if args.encoder == 'dns':
        # Special Handling for DNS
        decode_dns(possible_keys, file_data)
    else:
        decode_http(possible_keys, file_data)


