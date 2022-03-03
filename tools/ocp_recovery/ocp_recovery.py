#!/usr/bin/env python3

"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

import os
import sys
from periphery import I2C


# NOTE:  This script is incomplete.  Development halted on it because the periphery module was not
# returning the I2C data for read operations.  The read was succeeding, but the data was not
# populated.
#
# It remains as a starting point should it ever become useful in the future.


def print_usage ():
    print ("Usage: {0} <device> <addr>".format (sys.argv[0]))
    sys.exit (1)

if (len (sys.argv) < 3):
    print_usage ()


def calculate_smbus_pec (data):
    """
    Calculate the SMBus pec for a block of data.

    :param data:  The raw data to use for the calculation.  This must include all address and
    overhead bytes.

    :return The calculated PEC value.
    """
    crc = 0
    for byte in data:
        crc = (crc ^ byte) & 0xff

        for i in range (0, 8):
            if (crc & 0x80):
                crc = ((crc << 1) ^ 0x07) & 0xff
            else:
                crc = (crc << 1) & 0xff


    return crc

def verify_smbus_pec(data, pec):
    """
    Verify the PEC byte for an SMBus block read or write.  An exception is raised if the PEC does
    not match.

    :param data:  The raw data that is protected by the PEC.  This must include any and all address
    bytes as well as all data bytes.
    """

    crc = calculate_smbus_pec (data)
    if (crc != pec):
        raise Exception ("Rx PEC error.  PEC={0}, Rx={1}".format (hex (pec), hex (crc)))


class OcpRecovery:
    """
    Interface to a device that implements the recovery protocol specified by the OCP security
    working group.

    https://www.opencompute.org/wiki/Security
    """

    def __init__ (self, i2c, address):
        """
        Initialize the OCP recovery interface using and I2C device.

        :param i2c:  A device number or path to use for device communications.
        :param address:  The 7-bit I2C address of the target device.
        """

        if (str (i2c).__contains__ ("i2c")):
            self.i2c = I2C (i2c)
        else:
            self.i2c = I2C ("/dev/i2c-{0}".format (i2c))

        self.addr = int (address, 16)

    def block_read (self, command, bytes, pec=True):
        """
        Execute an SMBus block read command.

        :param command:  The command to send to the device.
        :param bytes:  The number of bytes to read back.
        :param pec:  Flag to indicate if the PEC byte should be read.

        :return A bytearray containing the data payload.  No SMBus overhead will be returned.
        """

        smbus_overhead = 1
        if (pec):
            smbus_overhead += 1

        rx_data = bytearray (bytes + smbus_overhead)

        tx = I2C.Message (bytearray ([command]))
        rx = I2C.Message (rx_data, read=True)
        xfer = [tx, rx]

        self.i2c.transfer (self.addr, xfer)
        print (rx_data)

        if (not pec):
            return rx_data[1:]
        else:
            raw_data = [self.addr << 1, command, (self.addr << 1) | 1]
            raw_data += rx_data[:-1]
            verify_smbus_pec (raw_data, rx_data[-1])

            return rx_data[1:-1]

    def block_write (self, command, data, pec=True):
        """
        Execute an SMBus block write command.

        :param command:  The command to send to the device.
        :param data:  The payload data.
        :param pec:  Flag to indicate if the PEC byte should be sent.
        """

        tx_data = [self.addr << 1, command, len (data) & 0xff]
        tx_data += data
        if (pec):
            tx_data.append (calculate_smbus_pec (tx_data))

        tx = I2C.Message (tx_data[1:])
        xfer = [tx]

        self.i2c.transfer (self.addr, xfer)


class ProtCap:
    """
    Handler for the PROT_CAP message in the recovery protocol.  This command is used to retrieve
    device capabilities.
    """

    def __init__ (self, recovery):
        """
        Read and parse the capabilities of a device.

        :param recovery:  An OcpRecovery instance that will be used to communicate with the device.
        """

        data = recovery.block_read (34, 15)
        print (data)


ocp = OcpRecovery (sys.argv[1], sys.argv[2])

ProtCap (ocp)
