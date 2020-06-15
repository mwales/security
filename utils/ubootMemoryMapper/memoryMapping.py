#!/usr/bin/env python3

import serial

def rebootDetected(ser):
    '''
    Some devices need help to get back to U-Boot menu when they reboot
    '''
    print("Get us back into u-boot menu")
    ser.send(bytearray("\n", "utf=8"))


def processData(address, ser):
    '''
    Return true if memory was dumped, or false if rebooted
    '''

    # We expect to either reboot or dump the memory
    rebootIndicator = "Hit a key to stop autoboot:"

    while True:
        rawdata = ser.readline()

        # Trim everything
        linedata = ""
        for singleChar in rawdata:
            if ( (singleChar >= 0x20) and (singleChar <= 0x7E) ):
                linedata += chr(singleChar)

        print("before: " + linedata)
        linedata = linedata.replace("\r", "")
        linedata = linedata.replace("\n", "")

        print("after: " + linedata)

        if rebootIndicator in linedata:
            print("REBOOT: " + linedata)

            rebootDetected()

            return false

        # a dump line looks like: address: xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx aaaaaa
        # we will check for address, and 3 correct lenght words
        parts = linedata.split()

        if (len(parts) < 6):
            print("INV (not enough parts): " + linedata)
            continue

        addressPart = "00000000" + hex(address)[2:] + ":"
        addressPart = addressPart[-9:]
        print("Address I'm looking for: " + addressPart)

        if (parts[0] != addressPart):
            print("INV (no address): " + linedata)
            continue

        # are parts 1-4 8 chars long
        if ( (len(parts[1]) != 8) or (len(parts[2]) != 8) or (len(parts[3]) != 8) or (len(parts[4]) != 8) ):
            print("INV (no hex words): " + linedata)
            continue

        return True



def main():
    ser = serial.Serial("/dev/ttyUSB0", 115200)
    ser.timeout = 1.0

    curAddress = 0
    for curAddress in range(0, 0xffffffff, 0x4000):

        dumpCmd = "md " + hex(curAddress) + " 4"
        dumpBytes = bytearray(dumpCmd + "\n", "utf-8")
        print("CMD: " + dumpCmd)
        ser.write(dumpBytes)

        processData(curAddress, ser)



if __name__ == "__main__":
    main()
