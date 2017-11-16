import socket
import threading
import socketserver
import select
import logging
from crc import CRC_GT02


THREAD_TIMEOUT = 120  # seconds


class ThreadedRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        """
        Create response to incoming packet

        Build a response from an incoming GT06 protocol GPS Tracker packet
        """
        log = logging.getLogger(__name__)
        log.info("New processing thread started: "
                + threading.current_thread().name)
                
        done = False
        crc16 = CRC_GT02()

        while not done:
            log.debug("Blocking on incoming data")
            ready = select.select([self.request], [], [], THREAD_TIMEOUT)
            if not ready[0]:
                # Timeout has occured and we are done
                log.info("No message received for " + str(THREAD_TIMEOUT) +
                         " seconds, " + threading.current_thread().name +
                         " exiting")
                done = True
            else:
                b = self.request.recv(260)
                if not b:
                    # If we get zero length data from this call then the socket is
                    # closed, so we are done!
                    log.info("Thread "
                             + threading.current_thread().name()
                             + " ending, socket closed")
                    done = True
                else:
                    bad_data = False
                    log.debug("Data: " + ' '.join(format(x, '02x') for x in b))
                    # Process the data we just got
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
                        bad_data = True
                    else:
                        log.debug("Good start bits")

                    # Confirm correct data length
                    if length != calc_length:
                        log.error("Length mismatch -" +
                                  " Calculated: " + str(calc_length) + 
                                  ", Supplied: " +  str(length))
                        bad_data = True
                    else:
                        log.debug("Length match")

                    # Confirm checksum
                    if calc_crc != crc:
                        log.error("Checksum mismatch -" +
                                  " Calculated: %02x, Supplied: %02x" % (calc_crc, crc))
                        bad_data = True
                    else:
                        log.debug("Checksum match")

                    if not bad_data:    
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
                        self.request.send(response)
                    else:
                        log.error("Bad data received, discarding")


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True


def main():

    logging.basicConfig(format='%(asctime)s %(name)s:%(levelname)s:%(message)s',
                        level=logging.DEBUG)
    log = logging.getLogger(__name__)
    log.info("Starting GT02 Server...")

    # Create a socket server
    try:
        server = ThreadedServer(("", 9000), ThreadedRequestHandler)
        server.serve_forever()
    finally:
        server.server_close()

        #server_tread = threading.Tread(target=server.serve_forever)
        #server_thread.daemon = True
        #server_thread.start()


if __name__ == "__main__":
    main()

