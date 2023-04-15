import argparse
import os
import re
import json

base64_alphabet = r'[A-Za-z0-9-_]'
base64_pattern = r'(?:(?:{}{{4}})*(?:{}{{2}}==|{}{{3}}=)?)'.format(base64_alphabet, base64_alphabet, base64_alphabet)


def is_valid_hex_string(match):
    char_match = match.decode('utf-8')
    has_digit = any(c.isdigit() for c in char_match)
    has_letter = any(c.isalpha() for c in char_match)
    return has_digit and has_letter

def duplicate_check(sessions, target_value):
    for s in sessions:
        if 'body' in s and s['body'] == target_value.decode():
            return True

    return False


def extract_http(raw_data):
    sessions = []

    print(f'[+] Scanning for Word encoded payloads')
    
    words_pattern = rb'\x00((?:(?:\s*[A-Z]+(?:\s|$)){9,}\S+?))(?=\x00)'

    words = re.findall(words_pattern, raw_data)
    for encoded in words:
        sessions.append(
            {
                "request_uri": "In Memory Capture",
                "body": encoded.decode(),
                "encoder": "words"

            }
        )

    print(f'[+] Scanning for Hex encoded payloads')
    hex_pattern =  rb'[0-9a-f]{20,}'


    matches = re.findall(hex_pattern, raw_data)

    filtered_matches = [match for match in matches if is_valid_hex_string(match)]

    for encoded in filtered_matches:
        if not duplicate_check(sessions, encoded):
            sessions.append(
                {
                    "request_uri": "In Memory Capture",
                    "body": encoded.decode(),
                    "encoder": "hex"

                }
            )

    print(f'  [-] Found {len(sessions)} probable Sliver Payloads')

    with open('memory-sessions.json', 'w') as json_file:
        json.dump(sessions, json_file)

# sliver-dns.the-briar-patch.cc

def extract_dns(raw_data, domain_name):
    print(f'[+] Scanning for DNS traffic')
    dns_pattern = f'\x00([213465789aBcDeFgHjKLMNPQRSTUVWXYZAbCdEfGhiJkmnopqrstuvwxyz.]{{5,254}})\.{domain_name}\.'
    
    encoded_payloads = re.findall(dns_pattern.encode(), raw_data)
    
    print(f"  [-] Found {len(encoded_payloads)} Possible encoded values")
    print(f"  [-] Writing encoded payloads to dns-{domain_name}.txt")
    with open(f'dns-{domain_name}.txt', 'w') as output_file:
        for payload in encoded_payloads:
            output_file.write(f'{payload.decode()}\n')

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Extract Sliver C2 from a memory dump file')

    parser.add_argument(
        '--dumpfile',
        help='Path to dump file',
        required=True)

    parser.add_argument(
        '--filter',
        help='Filter for HTTP, or DNS',
        choices=['http', 'dns'],
        dest='packet_filter',
        required=True)

    parser.add_argument(
        '--domain_name',
        help='DNS Filter requires the C2 domain name',
        default=None,
        required=False)

    args = parser.parse_args()


    if args.packet_filter == 'dns' and not args.domain_name:
        print('[!] You must provice the domain name for DNS extraction')
        exit()

    if not os.path.exists(args.dumpfile):
        print('[!] Error reading dumpfile {args.dumpfile}')

    with open(args.dumpfile, 'rb') as input_file:
        raw_data = input_file.read()

    print('[!] Important Notes:')
    print('  [*] There will be duplicate entries')
    print('  [*] We make assumptions about the encoder. We can not tell if its a gzip varient')

    if args.packet_filter == 'http':
        extract_http(raw_data)
    elif args.packet_filter == 'dns':
        extract_dns(raw_data, args.domain_name)
