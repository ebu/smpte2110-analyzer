#!/usr/bin/python3

import sys

if sys.version_info < (3, 0):
    print("needs python 3")
    sys.exit(2)

import getopt
import pyshark
import math
from decimal import *

PTP_PORT_1 = 319 # Server to Client -> Sync_Message and Deley_Req_Message
PTP_PORT_2 = 320 # Client to Server -> follow_up Message and Delay_resp Messae
MSG_ID_SYNC_MSG   = 0
MSG_ID_FOLLOW_UP  = 8
MSG_ID_DELAY_REQ  = 1
MSG_ID_DELAY_RESP = 9
UDP = 17
PTP_V2 = 2

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

    TFRAME = Decimal(1001 / 60000)  # 1/59.94

    t1 = None
    t2 = None
    t3 = None
    t4 = None
    sync_msg_seq_id = 0
    delr_msg_seq_id = 0
    propagation_delay = None
    time_offset = None


    capture = pyshark.FileCapture(capfile, keep_packets=False, decode_as={'udp.port==319':'ptp', 'udp.port==320':'ptp'}, display_filter='udp.port == 319 or udp.port == 320')
    try:
        for idx, pkt in enumerate(capture):
            if int(pkt.ip.proto) == UDP:
                if int(pkt.ptp.v2_versionptp) == PTP_V2:
                    #print("PTP Version 2")

                    # Retreive packet arrival timestamp from Sync Message
                    if int(pkt.udp.port) == PTP_PORT_1 and int(pkt.ptp.v2_messageid) == MSG_ID_SYNC_MSG:
                        t1 = Decimal(pkt.sniff_timestamp)
                        sync_msg_seq_id = pkt.ptp.v2_sequenceid
                        print("Sync Message       : ", t1)

                    # Retreive PTP timestamp from Follow_up Message
                    if int(pkt.udp.port) == PTP_PORT_2 and int(pkt.ptp.v2_messageid) == 8 and (sync_msg_seq_id == pkt.ptp.v2_sequenceid):
                        t2 = Decimal(pkt.ptp.v2_fu_preciseorigintimestamp_seconds) + Decimal(pkt.ptp.v2_fu_preciseorigintimestamp_nanoseconds) / 1000000000
                        print("Follow_Up Message  : ", t2)

                    # Retreive packet send timestamp from Delay Request Message
                    if int(pkt.udp.port) == PTP_PORT_1 and int(pkt.ptp.v2_messageid) == 1:
                        t3 = Decimal(pkt.sniff_timestamp)
                        delr_msg_seq_id = pkt.ptp.v2_sequenceid
                        print("Delay_req Message  : ", t3)

                    # Retreive roundtrip delay timestamp from Delay Respons Message
                    if int(pkt.udp.port) == PTP_PORT_2 and int(pkt.ptp.v2_messageid) == 9 and (delr_msg_seq_id == pkt.ptp.v2_sequenceid):
                        t4 = Decimal(pkt.ptp.v2_dr_receivetimestamp_seconds) + Decimal(pkt.ptp.v2_dr_receivetimestamp_nanoseconds) / 1000000000
                        print("Delay_resp Message : ",t4)

            if t1 != None and t2 != None:
                time_offset = t2 - t1
                t2 = None

            if t3 != None and t4 != None:
                propagation_delay = (t4 - (t3 + time_offset)) / 2
                t4 = None

            if time_offset != None and propagation_delay != None:
                timestampoffset = time_offset + propagation_delay
                ptp_time = t1 + time_offset + propagation_delay

                print("time_offset          : ", time_offset)
                print("propagation_delay    : ", propagation_delay)
                print("pkt.time             : ", pkt.sniff_timestamp)
                print("Offset with pkt.time : ", timestampoffset)
                print("PTP time             : ", ptp_time)

                videoalignmentpointpacketnumber = pkt.number
                videoalignmentpoint = Decimal(math.floor(ptp_time / TFRAME) * TFRAME)
                print("videoalignmentpointpacketnumber :", videoalignmentpointpacketnumber)
                print("videoalignmentpoint             :", videoalignmentpoint)
                print("Frame # since Epoch             :", math.floor(ptp_time / TFRAME))
                print("--------------------------------------------------------------------------------")
                time_offset = None
                propagation_delay = None


    except KeyboardInterrupt:
        print("\nInterrupted")


def usage():
    print("analyzer.py -c|--cap <capture_file>")
    print("<max_packets> : use \"-\" for all capture")


if __name__ == '__main__':
    main(sys.argv[1:])
