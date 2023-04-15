import argparse
from binascii import unhexlify
import os
import re
import gzip
import json

import pyshark


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

def decode_nonce(nonce_value):
    """Takes a nonce value from a HTTP Request and returns the encoder that was used"""
    nonce_value = int(re.sub('[^0-9]','', nonce_value))
    encoder_id = nonce_value % 101
    if encoder_id in encoders:
        return encoders[encoder_id]
    else:
        return None


def extract_http(packets, domain_name):
    print(f'[+] Filtering for HTTP traffic')
    payload_counter = 0

    if not os.path.exists('captures'):
        os.mkdir('captures')

    sessions = []
    print('[+] Collecting Sessions')
    for packet in packets:
        packet_data = {
            'request_uri': ''
        }

        if hasattr(packet.http, 'request_method'):
            packet_data['request_method'] = packet.http.request_method
        if hasattr(packet.http, 'request_full_uri'):
            packet_data['request_uri'] = packet.http.request_full_uri
        if hasattr(packet.http, 'file_data'):
            packet_data['body'] = packet.http.file_data

        # Extract the HTTP response data
        if hasattr(packet.http, 'response_for_uri'):
            packet_data['request_uri'] = packet.http.response_for_uri
        if hasattr(packet.http, 'response_code'):
            packet_data['response_code'] = packet.http.response_code
        if hasattr(packet.http, 'file_data'):
            packet_data['body'] = packet.http.file_data

        # Filter against our domain 
        if domain_name not in packet_data['request_uri']:
            continue

        # Parse the query params from the URI
        # We can not use 'request_uri_query' as it doesnt exist on req and resp
        encoder = None

        if '?' in packet_data['request_uri']:
            query_params = packet_data['request_uri'].split('?')[1]
            for possible in query_params.split('='):
                try:
                    encoder = decode_nonce(possible)
                    packet_data['encoder'] = encoder
                except Exception as err:
                    pass

        # Append to our sessions
        if packet_data.get('body', None) and encoder:
            sessions.append(packet_data)

    
    print(f'  [-] Found {len(sessions)} probable Sliver Payloads')

    with open('http-sessions.json', 'w') as json_file:
        json.dump(sessions, json_file)

    print('[!] Extraction Complete, if you have a key or process dump use the sliver-decrypy.py script')


def extract_dns(packets, domain_name):
    print(f'[+] Filtering for DNS traffic')
    encoded_payloads = []
    payload_counter = 0
    for p in packets:
        if hasattr(p.dns, 'resp_name'):
            # responses also include the request data so ignore
            continue

        if domain_name in p.dns.qry_name:
            payload_counter += 1
            
            encoded_value = p.dns.qry_name.split(domain_name)[0]
            encoded_payloads.append(encoded_value)
    
    print(f"  [-] Found {payload_counter} Possible encoded values")
    # DNS Needs recombining before we can decrypt the values correctly 
    # So we put them all in to a single file
    print(f"  [-] Writing encoded payloads to dns-{domain_name}.txt")
    with open(f'dns-{domain_name}.txt', 'w') as output_file:
        for payload in encoded_payloads:
            output_file.write(f'{payload}\n')
    print('[!] Extraction Complete, if you have a key or process dump use the sliver-decrypy.py script')



if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Extract Sliver C2 from a PCAP file')

    parser.add_argument(
        '--pcap',
        help='Path to pcap file',
        required=True)

    parser.add_argument(
        '--filter',
        help='Filter for HTTP, or DNS',
        choices=['http', 'dns'],
        dest='packet_filter',
        required=True)

    parser.add_argument(
        '--domain_name',
        help='Filter traffic to a specific DNS or IP address',
        default=None,
        required=True)

    args = parser.parse_args()


    #if args.packet_filter == 'dns' and not args.domain_name:
    #    print('[!] You must provice the domain name for DNS extraction')
    #    exit()

    packets = pyshark.FileCapture(args.pcap, display_filter=args.packet_filter)

    if args.packet_filter == 'http':
        extract_http(packets, args.domain_name)
    elif args.packet_filter == 'dns':
        extract_dns(packets, args.domain_name)
