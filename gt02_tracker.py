import socket
import logging
from crc import CRC_GT02

crc16 = CRC_GT02()

def server_response(incoming_bytes):
    """
    Create response to incoming packet

    Build a response from an incoming GT06 protocol GPS Tracker packet
    """
    log = logging.getLogger(__name__)
    b = bytearray(incoming_bytes)

    start = b[0:2]
    length = b[2]
    protocol = b[3]
    payload = b[4:-6]
    serial = b[-6:-4]
    crc = b[-4:-2]
    end = b[-2:]
    to_crc = b[2:-4]
    calc_length = len(b) -5
    calc_crc = crc16.crcb(to_crc)

    # Check start
    if start != b'\x78\x78':
        log.error("Bad start to received data packet")
    else:
        log.debug("Good start bits")

    # Confirm correct data length
    if length != calc_length:
        log.error("Length mismatch - Calculated: %d, Supplied: %d" % calc_length, length)
    else:
        log.debug("Length match")

    # Confirm checksum
    if calc_crc != crc:
        log.error("Checksum mismatch - Calculated: %02x, Supplied: %02x" % calc_crc, crc)
    else:
        log.debug("Checksum match")

    # Deal with the message content based on the protocol
    if protocol == 0x01:
        # Login request
        log.info("Login from " + ' '.join(format(x, '02x') for x in payload))
    elif protocol == 0x12:
        # Location Data
        log.info("Location packet received")
    elif protocol == 0x13:
        # Status Information
        log.info("Status packet received")
    elif protocol == 0x15:
        # String Information
        log.info("String packet received")
    elif protocol == 0x16:
        # Alarm Information
        log.info("Alarm packet received")
    elif protocol == 0x1A:
        # GPS query by phone
        log.info("GPS query by phone packet received")
    else:
        log.error("Unknown protocol: " + str(protocol))

    # Build a response packet
    response_payload = b'\x05' + bytes([protocol, serial[0], serial[1]])
    response_crc = crc16.crcb(response_payload)
    response = b'\x78\x78' \
          + response_payload \
          + response_crc \
          + b'\x0d\x0a'
    log.debug("Response packet: " + ' '.join(format(x, '02x') for x in response))
    return response


def main():

    logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s',
                        level=logging.DEBUG)
    log = logging.getLogger(__name__)
    log.info("Starting GT02 Server...")

    # Create a socket server
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('', 9000))
    serversocket.listen(1)
    try:
        while True:
            log.debug("Waiting for connection")
            conn, addr = serversocket.accept()
            log.info("Connection from: " + str(addr))
            while True:
                log.debug("Waiting for data")
                data = conn.recv(128)
                if len(data) == 0:
                    break
                log.debug("Data: " + ' '.join(format(x, '02x') for x in data))
                response = server_response(data)
                conn.send(response)
    finally:
        serversocket.close()

if __name__ == "__main__":
    main()

