#!/usr/bin/python3
# coding=utf-8
#
import threading
import socketserver
import select
import struct
import logging
import datetime
import time
import json
import yaml
import ssl
import paho.mqtt.publish as publish
from crc import CRC_GT02


THREAD_TIMEOUT = 120  # seconds
config = {}  # Global variable for the config


def parse_location(data):
    log = logging.getLogger(__name__)
    log.debug("Parsing location packet")
    # Date time
    year = data[0] + 2000
    month = data[1]
    day = data[2]
    hour = data[3]
    minute = data[4]
    second = data[5]
    dt = datetime.datetime(year, month, day, hour, minute, second)
    tst = int(time.mktime(dt.timetuple()))
    log.debug("Datetime: " + str(dt))
    # GPS Quality
    bit_length = (data[6] & 0xf0) >> 4
    num_sats = data[6] & 0x0f
    log.debug("GPS Quality: Bitlength = " + str(bit_length) +
              "  Number of satellites = " + str(num_sats))
    # Speed
    speed = data[15]
    if speed < 1:
        log.debug("Moving at " + str(speed) + " kph")
    else:
        log.debug("Not moving")
    # Status and direction
    status = (data[16] << 8) & data[17]
    direction_deg = status & 0x3f
    log.debug("Heading: " + str(direction_deg) + "°")
    if status & 0x0400:
        lat_hemi = 'S'
    else:
        lat_hemi = 'N'
    if status & 0x0800:
        lon_hemi = 'E'
    else:
        lon_hemi = 'W'
    if status & 0x1000:
        gps_pos_ok = False
    else:
        gps_pos_ok = True
    if status & 0x2000:
        gps_pos = "Differential"
    else:
        gps_pos = "Live"
    log.debug("GPS Status: Fix " +
              str(gps_pos_ok) +
              " data is " + gps_pos
              )
    # Lat / Lon
    lat_raw = struct.unpack('>I', data[7:11])[0]
    lon_raw = struct.unpack('>I', data[11:15])[0]
    lat_dd = lat_raw / (30000 * 60)
    lon_dd = lon_raw / (30000 * 60)
    lat_deg = int(lat_dd)
    lat_min = (lat_dd - lat_deg) * 60
    lon_deg = int(lon_dd)
    lon_min = (lon_dd - lon_deg) * 60
    loc_txt = str(lat_deg) + "° "
    loc_txt += format(lat_min, '02.4f') + "'" + lat_hemi + " "
    loc_txt += str(lon_deg) + "° "
    loc_txt += format(lon_min, '02.4f') + "'" + lon_hemi
    # Correct the decimal degrees sign if needed
    if lat_hemi == 'S':
        lat_dd = -lat_dd
    if lon_hemi == 'W':
        lon_dd = -lon_dd
    log.debug("DD: " + str(lat_dd) + " " + str(lon_dd))
    # Log position and movement
    if speed < 1:
        log.info("Static Location: " + loc_txt)
    else:
        log.info("Moving at " + str(speed) +
                 " kph, heading " + str(direction_deg) +
                 ". Position " + loc_txt)

    # GSM Info
    mcc = (data[17] << 8) & data[18]
    mnc = data[19]
    lac = (data[20] << 8) & data[21]
    cell_id = (data[22] << 8) & data[23]
    log.debug("GSM Data:" +
              " MCC: 0x" + format(mcc, '04x') +
              " MNC: 0x" + format(mnc, '02x') +
              " LAC: 0x" + format(lac, '04x') +
              " Cell ID: 0x" + format(cell_id, '04x')
              )
    info = {
            'datetime': dt,
            'timestamp': tst,
            'lat': lat_dd,
            'lon': lon_dd,
            'position': loc_txt,
            'speed': speed,
            'heading': direction_deg,
            'satellites': num_sats,
            'locked': gps_pos_ok,
            'pos_status': gps_pos,
            'bitlength': bit_length,
            'cell_id': cell_id,
            'mcc': mcc,
            'mnc': mnc,
            'lac': lac
            }
    return info


def parse_status(data):
    log = logging.getLogger(__name__)
    log.debug("Parsing status packet")
    # Extract
    info = data[0]
    voltage = data[1]
    signal = data[2]
    alarm_lang = data[3]
    # Bit data
    if info & 0x80:
        immobilised = True
    else:
        immobilised = False

    if info & 0x40:
        tracking = True
    else:
        tracking = False

    alarm = (info & 0x38) >> 3

    if info & 0x04:
        charging = True
    else:
        charging = False

    if info & 0x02:
        ignition = True
    else:
        ignition = False

    if info & 0x01:
        active = True
    else:
        active = False

    log.info("Vehicle:" +
             " Immobilised - " + str(immobilised) +
             " Ingition on - " + str(ignition) +
             " Alarm 1 - " + str(alarm) +
             " Alarm 2 - " + str(alarm_lang)
             )
    log.info("System:"
             " Active - " + str(active) +
             " Tracking - " + str(tracking) +
             " Charging - " + str(charging) +
             " Voltage - " + str(voltage) +
             " Signal - " + str(signal)
             )
    info = {
            'active': active,
            'tracking': tracking,
            'charging': charging,
            'voltage': voltage,
            'signal': signal,
            'immobilised': immobilised,
            'ignition': ignition,
            'alarm1': alarm,
            'alarm2': alarm_lang
            }
    return info


class ThreadedRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        """
        Create response to incoming packet

        Build a response from an incoming GT06 protocol GPS Tracker packet
        """
        log = logging.getLogger(__name__)
        log.info("New processing thread started: "
                 + threading.current_thread().name
                 )

        done = False
        imei = None
        crc16 = CRC_GT02()
        broker = config['mqtt']['broker']
        port = config['mqtt']['port']
        auth = {
                'username': config['mqtt']['username'],
                'password': config['mqtt']['password']
                }
        if 'tls' in config:
            tls = {
                   'ca_certs': config['tls']['ca_certs']
                   }
        else:
            tls = None

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
                    # If we get zero length data from this call then the
                    # socket is closed, so we are done!
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
                    calc_length = len(b) - 5
                    calc_crc = crc16.crcb(to_crc)

                    # Check start
                    if start != b'\x78\x78':
                        log.error("Bad start to received data packet")
                        bad_data = True

                    # Confirm correct data length
                    if length != calc_length:
                        log.error("Length mismatch -" +
                                  " Calculated: " + str(calc_length) +
                                  ", Supplied: " + str(length))
                        bad_data = True

                    # Confirm checksum
                    if calc_crc != crc:
                        log.error("Checksum mismatch -" +
                                  " Calculated: %02x, Supplied: %02x"
                                  % (calc_crc, crc))
                        bad_data = True

                    # Check ending bytes
                    if end != b'\r\n':
                        log.error("Ending bytes are incorrect")
                        bad_data = True

                    if not bad_data:
                        # Deal with the message content based on the protocol
                        if protocol == 0x01:
                            # Login request
                            if imei is None:
                                imei = ''.join(
                                        format(x, '02x') for x in payload)
                                log.info("Login from " + imei)
                                if imei in config['imei']:
                                    device = config['imei'][imei]['device']
                                    tid = config['imei'][imei]['tid']
                                else:
                                    device = imei
                                    tid = imei[-2:]
                            else:
                                log.error("Multiple login attempts")
                                done = True
                        elif protocol == 0x12:
                            # Location Data
                            log.debug("Location packet received")
                            info = parse_location(payload)
                            log.debug("Extracted: " + str(info))
                            owntracks = {
                                         '_type': 'location',
                                         'tid': tid,
                                         'imei': imei,
                                         'lat': info['lat'],
                                         'lon': info['lon'],
                                         'cog': info['heading'],
                                         'vel': info['speed'],
                                         'tst': info['timestamp']
                                         }
                            if not info['locked'] or info['satellites'] < 4:
                                owntracks['acc'] = 10000
                            else:
                                # This is a guestimate
                                owntracks['acc'] = int(200
                                        / info['satellites'])

                            # Publish to mqtt
                            log.debug("Sending via mqtt: " + str(owntracks))
                            publish.single(
                                           "owntracks/" + device + "/" + tid,
                                           payload = json.dumps(owntracks),
                                           tls = tls,
                                           auth = auth,
                                           hostname = broker,
                                           port = int(port)
                                           )
                            log.debug("Sent successfully")

                        elif protocol == 0x13:
                            # Status Information
                            log.warning("Status packet received")
                            info = parse_status(payload)
                        elif protocol == 0x15:
                            # String Information
                            log.warning("String packet received - " +
                                        "NOT IMPLEMENTED")
                        elif protocol == 0x16:
                            # Alarm Information
                            log.warning("Alarm packet received - " +
                                        "NOT IMPLEMENTED")
                        elif protocol == 0x1A:
                            # GPS query by phone
                            log.warning("GPS query by phone packet received - "
                                        + "NOT IMPLEMENTED")
                        else:
                            log.error("Unknown protocol: " + str(protocol))

                        # Build a response packet
                        response_payload = b'\x05' + \
                                           bytes([protocol,
                                                 serial[0],
                                                 serial[1]]
                                                 )
                        response_crc = crc16.crcb(response_payload)
                        response = b'\x78\x78' \
                                   + response_payload \
                                   + response_crc \
                                   + b'\x0d\x0a'
                        log.debug("Response packet: " +
                                  ' '.join(format(x, '02x') for x in response))
                        self.request.send(response)
                    else:
                        log.error("Bad data received, discarding")


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True


def main():

    logging.basicConfig(format='%(asctime)s ' +
                               '%(name)s:%(levelname)s:%(message)s',
                               level=logging.DEBUG
                        )
    log = logging.getLogger(__name__)
    log.info("Starting GT02 Server...")

    log.info("Reading config file: config.yaml")
    global config
    with open("config.yaml", 'r') as y:
        config = yaml.load(y)
    log.debug("Config: " + str(config))

    # Create a socket server
    try:
        server = ThreadedServer(("", 9000), ThreadedRequestHandler)
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
