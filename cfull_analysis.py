#!/usr/bin/python3

import sys

if sys.version_info < (3, 0):
    print("needs python 3")
    sys.exit(2)

import getopt
import pyshark
import time
import numpy
import math
import sys
from decimal import *
from collections import Counter


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hc:g:", ["help", "cap=", "group="])
        if not opts:
            print("No options supplied")
            usage()
            sys.exit(2)
    except getopt.GetoptError:
        print("Error in options {}".format(opts))
        usage()
        sys.exit(2)

    global capfile
    global group

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-c", "--cap"):
            capfile = arg
        elif opt in ("-g", "--group"):
            group = arg
        else:
            print("unknown option " + opt)
            usage()
            sys.exit()
    decode_str = "udp.port=" + "50000"

    # filtering capture with marker to find nb packets per field
    global capture_marker
    idx = 0
    oldIdx = 0
    sequencenumber = []

    capture_marker = pyshark.FileCapture(capfile, keep_packets=False, decode_as={decode_str: 'rtp'},
                                         display_filter='ip.dst==' + group + '&& rtp.marker == 1')

    for pkt in capture_marker:
        sequencenumber.append(pkt.rtp.seq)

    print("Frames: ", len(sequencenumber))

    # -- Should protect next fomula: sequence numbers will overflow --
    # ----------------------------------------------------------------
    npackets = int(sequencenumber[-1]) + 0 - int(sequencenumber[-2])
    # ----------------------------------------------------------------
    print("Npackets = {}".format(npackets))

    # analysing all packets
    capture = pyshark.FileCapture(capfile, keep_packets=False, decode_as={decode_str: 'rtp'},
                                  display_filter='ip.dst==' + group)

    # Time different between packets
    timediffs = []

    # SMPTE2110-21: leaky bucket model
    cfull = []

    # Amount of packets cleared out of the buffer
    cleared = []

    # Number of cleared of packets
    clearnbr = 0

    # Start of the experiment
    initialtime = time = oldTime = 0.000000000

    # Frame duration
    tframe = float(1 / 59.94)

    # Drain factor as defined in SMPTE2110-21
    B = 1.1

    # Formula defined in SMPTE2110-21
    tdrain = tframe / npackets / B
    print("Tdrain = {}".format(tdrain))

    try:
        for idx, pkt in enumerate(capture):

            time = Decimal(pkt.sniff_timestamp)

            if initialtime == 0:
                # Record initial timing of the PCAP file
                initialtime = time
                # Initiate the Cfull bucket with 1 packet
                cfull.append(1)
                cfull[-1] = 1
                cleared.append(0)

            if (oldTime != 0):
                timediff = time - oldTime
                timediffs.append(timediff)
                clearnbr = math.floor((Decimal(time) - Decimal(initialtime)) / Decimal(tdrain))
                cleared.append(clearnbr)
                buffer = cfull[-1] + 1 - (cleared[-1] - cleared[-2])

                if (buffer >= 0):
                    cfull.append(buffer)
                if (buffer < 0):
                    cfull.append(0)
            oldTime = time

    except KeyboardInterrupt:
        print("\nInterrupted")

    data = Counter(timediffs)
    print("Intial Time = ", initialtime)
    print("#packets = ", idx + 1)
    print("#cleared = ", numpy.max(cleared))
    print("Cfull Max = ", max(cfull))
    print("Cfull Min = ", numpy.min(cfull))
    print("Cfull Avg = ", numpy.mean(cfull))
    print("average = ", numpy.mean(timediffs))
    print("maximum = ", numpy.max(timediffs))
    print("minimim = ", numpy.min(timediffs))
    print("Reference Time  :", Decimal(time) - Decimal(initialtime))


def usage():
    print("analyzer.py -c|--cap <capture_file>")
    print("<max_packets> : use \"-\" for all capture")

if __name__ == '__main__':
    main(sys.argv[1:])
