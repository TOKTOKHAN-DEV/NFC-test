import os
from smartcard.System import readers
from smartcard.util import toHexString, toBytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def connect_to_reader():
    r = readers()
    if len(r) == 0:
        print("No reader found")
        return None
    print("Available readers:", r)
    return r[0].createConnection()

def send_apdu(connection, apdu):
    data, sw1, sw2 = connection.transmit(apdu)
    print(f"Response: data:{toHexString(data)} sw:0x{sw1:02X} sw2:0x{sw2:02X}")
    return data, sw1, sw2

def authenticate(connection, key):
    # Generate random number for challenge
    challenge = os.urandom(16)
    
    # Send authentication command with challenge
    apdu = [0x00, 0x70, 0x00, 0x00, 0x10] + list(challenge)
    response, sw1, sw2 = send_apdu(connection, apdu)
    
    if sw1 != 0x90 or sw2 != 0x00:
        print(f"Authentication failed: sw:0x{sw1:02X} sw2:0x{sw2:02X}")
        return False
    
    # Decrypt the response
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes([0]*16)), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(bytes(response)) + decryptor.finalize()
    
    # Verify the decrypted response
    if decrypted[:16] != challenge:
        print("Authentication failed: Invalid response")
        return False
    
    print("Authentication successful")
    return True

def read_ndef_data(connection):
    # Select NTAG 424 DNA application
    apdu = [0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]
    _, sw1, sw2 = send_apdu(connection, apdu)
    if sw1 != 0x90 or sw2 != 0x00:
        print(f"Error selecting application: sw:0x{sw1:02X} sw2:0x{sw2:02X}")
        return None

    # Authenticate
    key = b'00000000000000000000000000000000'  # Replace with your actual key
    if not authenticate(connection, key):
        return None

    # Read NDEF data from the tag
    apdu = [0x00, 0xB0, 0x00, 0x00, 0x00]  # Read binary command
    data, sw1, sw2 = send_apdu(connection, apdu)
    
    if sw1 == 0x90 and sw2 == 0x00:
        return parse_ndef_message(data)
    else:
        print(f"Error reading data: sw:0x{sw1:02X} sw2:0x{sw2:02X}")
        if sw1 == 0x69 and sw2 == 0x85:
            print("Security status not satisfied. Authentication may be required.")
        return None

def parse_ndef_message(data):
    if len(data) < 2:
        return None
    
    message_length = (data[0] << 8) | data[1]
    if len(data) < message_length + 2:
        return None
    
    ndef_data = data[2:message_length+2]
    
    # Parse NDEF record
    record_type_length = ndef_data[2]
    payload_length = ndef_data[1]
    record_type = ndef_data[3:3+record_type_length]
    payload = ndef_data[3+record_type_length:3+record_type_length+payload_length]
    
    if bytes(record_type) == b'U':  # URL record
        return parse_url_record(payload)
    else:
        return f"Unknown record type: {record_type}"

def parse_url_record(payload):
    url_prefixes = [
        "", "http://www.", "https://www.", "http://", "https://",
        "tel:", "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.",
        "ftps://", "sftp://", "smb://", "nfs://", "ftp://", "dav://",
        "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop:",
        "sip:", "sips:", "tftp:", "btspp://", "btl2cap://", "btgoep://",
        "tcpobex://", "irdaobex://", "file://", "urn:epc:id:", "urn:epc:tag:",
        "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:"
    ]
    
    if payload[0] < len(url_prefixes):
        return url_prefixes[payload[0]] + payload[1:].decode('utf-8')
    else:
        return payload[1:].decode('utf-8')

def write_url(connection, url):
    # Authenticate first (same as in read_ndef_data)
    key = b'YOUR_16_BYTE_KEY'  # Replace with your actual key
    if not authenticate(connection, key):
        return

    ndef_message = create_ndef_url_message(url)
    
    # Select NTAG 424 DNA application
    apdu = [0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]
    send_apdu(connection, apdu)
    
    # Write NDEF message to the tag
    apdu = [0x00, 0xD6, 0x00, 0x00, len(ndef_message)] + ndef_message
    _, sw1, sw2 = send_apdu(connection, apdu)
    
    if sw1 == 0x90 and sw2 == 0x00:
        print("URL written successfully")
    else:
        print(f"Error writing URL: sw:0x{sw1:02X} sw2:0x{sw2:02X}")

def create_ndef_url_message(url):
    record_type = [0x55]  # 'U' for URL
    payload = [0x00] + list(url.encode())  # URL prefixed with 0x00 (no abbreviation)
    
    record_length = len(payload)
    if record_length < 256:
        length_field = [record_length]
    else:
        length_field = [0xFF, (record_length >> 8) & 0xFF, record_length & 0xFF]
    
    header = [0xD1] + length_field + [len(record_type)] + record_type
    ndef_message = header + payload
    message_length = len(ndef_message)
    return [message_length >> 8, message_length & 0xFF] + ndef_message

def main():
    connection = connect_to_reader()
    if connection:
        try:
            connection.connect()
            
            # Example: Write URL
            write_url(connection, "https://www.example.com")
            
            # Example: Read NDEF data
            url = read_ndef_data(connection)
            if url:
                print(f"Read URL: {url}")
            else:
                print("Failed to read URL")
            
        finally:
            connection.disconnect()

if __name__ == "__main__":
    main()