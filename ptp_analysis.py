#!/usr/bin/python3

import sys

if sys.version_info < (3, 0):
    print("needs python 3")
    sys.exit(2)

import getopt
import pyshark
import numpy
import math
from decimal import *


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
    decode_str = "udp.port=" + "5000"

    # filtering capture with marker to find nb packets per field
    global capture_marker
    tframe = Decimal(1001 / 60000)  # 1/59.94

    t1 = 0
    t2 = 0
    t3 = 0
    t4 = 0

    capture = pyshark.FileCapture(capfile, keep_packets=False, decode_as={'udp.port==319':'ptp', 'udp.port==320':'ptp'}, display_filter='udp.port == 319 or udp.port == 320')
    try:
        for idx, pkt in enumerate(capture):
            if int(pkt.udp.port) == 319 and int(pkt.ptp.v2_messageid) == 0:
                t1 = Decimal(pkt.sniff_timestamp)
                print("Sync Message     : ", t1)

            if int(pkt.udp.port) == 320 and int(pkt.ptp.v2_messageid) == 8:
                t2 = Decimal(pkt.ptp.v2_fu_preciseorigintimestamp_seconds) + Decimal(pkt.ptp.v2_fu_preciseorigintimestamp_nanoseconds) / 1000000000
                print("Follow_Up Message: ", t2)

            if int(pkt.udp.port) == 319 and int(pkt.ptp.v2_messageid) == 1:
                t3 = Decimal(pkt.sniff_timestamp)
                print("Delay_req Message: ", t3)

            if int(pkt.udp.port) == 320 and int(pkt.ptp.v2_messageid) == 9:
                t4 = Decimal(pkt.ptp.v2_dr_receivetimestamp_seconds) + Decimal(pkt.ptp.v2_dr_receivetimestamp_nanoseconds) / 1000000000
                print("Delay_resp Message: ",t4)

            if t4 != 0:
                TimeOffset = t2 - t1
                PropagationDelay = (t4 - (t3 + TimeOffset)) / 2
                timestampoffset = TimeOffset + PropagationDelay
                PTPtime = t1 + TimeOffset + PropagationDelay
                print("TimeOffset           : ", TimeOffset)
                print("PropagationDelay     : ", PropagationDelay)
                print("pkt.time             : ", pkt.sniff_timestamp)
                print("Offset with pkt.time : ", timestampoffset)
                print("PTP time             : ", PTPtime)

                videoalignmentpointpacketnumber = pkt.number
                print("videoalignmentpointpacketnumber :", videoalignmentpointpacketnumber)
                videoalignmentpoint = Decimal(math.floor(PTPtime / tframe) * tframe)
                print("videoalignmentpoint             :", videoalignmentpoint)
                print("Frame # since Epoch             :", math.floor(PTPtime / tframe))
                print("--------------------------------------------------------------------------------")

                t4 = 0

    except KeyboardInterrupt:
        print("\nInterrupted")


def usage():
    print("analyzer.py -c|--cap <capture_file>")
    print("<max_packets> : use \"-\" for all capture")


if __name__ == '__main__':
    main(sys.argv[1:])
