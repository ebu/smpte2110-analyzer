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
    sequencenumber = []

    capture_marker = pyshark.FileCapture(capfile, keep_packets=False, decode_as={decode_str:'rtp'}, display_filter='ip.dst==' + group + ' && rtp.marker == 1')
    
    for pkt in capture_marker:
        sequencenumber.append(pkt.rtp.seq)

    print("Frames: ", len(sequencenumber))
    # -- Should protect next fomula: sequence numbers will overflow --
    # ----------------------------------------------------------------
    npackets = int(sequencenumber[-1]) + 0 - int(sequencenumber[-2])
    # ----------------------------------------------------------------
    print("Npackets = {}".format(npackets))

    capture = pyshark.FileCapture(capfile, keep_packets=False, decode_as={'udp.port==320':'ptp'}, display_filter='udp.port == 320')
    tframe = Decimal(1001/60000) #1/59.94
    videoalignmentpoint = 0
    videoalignmentpointpacketnumber = 0
    timestampoffset = 0
    try:
        for idx, pkt in enumerate(capture):
           if int(pkt.udp.port) == 320 and int(pkt.ptp.v2_messageid) == 8:
               #print("",pkt.number)
               PTPtime = Decimal(pkt.ptp.v2_fu_preciseorigintimestamp_seconds) + Decimal(pkt.ptp.v2_fu_preciseorigintimestamp_nanoseconds) / 1000000000
               #print("PTP Seconds : ",pkt.number, pkt.sniff_timestamp, PTPtime)
               print("Message ID: ",pkt.ptp.v2_messageid)
               print("Frame # since Epoch  : ",math.floor(PTPtime/tframe))
               print("Video Alignment Point: ", Decimal (math.floor(PTPtime/tframe) * tframe))
               print("Offset with pkt.time : ", PTPtime - Decimal(pkt.sniff_timestamp))
               if videoalignmentpoint == 0:
                   videoalignmentpoint = Decimal (math.floor(PTPtime/tframe) * tframe)
                   #timestampoffset = PTPtime - Decimal(pkt.sniff_timestamp)
                   videoalignmentpointpacketnumber = pkt.number
               timestampoffset = PTPtime - Decimal(pkt.sniff_timestamp) #use last ptp timestamp.
    except KeyboardInterrupt:
      print("\nInterrupted")

      
    # ---------------------------
    # VRXbuffer -----------------
    # ---------------------------
    # Definition of the variables
    # ---------------------------

    J = 0
    VRXbuff = []
    Ractive = Decimal(1080 / 1125)
    Trs = Decimal(tframe * Ractive / npackets)
    TROdefault = tframe * 43 / 1125
    markers = []
    timestampInit = 0
    timestampCurr = 0
    timestampPrev = 0
    TRoffset = 0
    FrameCounter = 0
    rcv_pkt_counter = 0
    drain_pkt_counter = 0
    drain_time = 0

    print ("Trs: ",Trs)
    
    # Reading the PCAP file 
    capture = pyshark.FileCapture(capfile, keep_packets=False, decode_as={decode_str:'rtp'}, display_filter='ip.dst==' + group)

    flag = False
    try:
        for idx, pkt in enumerate(capture):
            timestampCurr = pkt.sniff_timestamp
            if timestampInit == 0:
                timestampInit = pkt.sniff_timestamp

            # Start after first PTP packet.    
            if int(pkt.number) > int(videoalignmentpointpacketnumber):
                # count the received packets
                rcv_pkt_counter = rcv_pkt_counter + 1
                print("J: ",J, rcv_pkt_counter, drain_pkt_counter, rcv_pkt_counter - drain_pkt_counter, end="\r")
                
                if flag == True:
                    # First packet of Frame TPR0
                    flag = False
                    J = 0
                    FrameCounter = FrameCounter + 1
                    TRoffset = (Decimal(pkt.sniff_timestamp) + Decimal(timestampoffset)) - videoalignmentpoint - (FrameCounter-1)*tframe
                    print("TPR0: ",FrameCounter, pkt.number, VRXbuff[-1],(Decimal(pkt.sniff_timestamp) + Decimal(timestampoffset)), TRoffset, Decimal(timestampCurr)-Decimal(timestampPrev))
                if int(pkt.rtp.marker) == 1: # rt.marker == 1 indicates last packet of frame.
                    #Set flag true to indicate next packet is start of new frame.
                    flag = True
                    markers.append(pkt.number)
 
                # VRXbuff drain 
                # (videoalignmentpoint + (FrameCounter-1)*tframe) + TRoffset + J * Trs -> packet J drains.
                drain_time = (Decimal(videoalignmentpoint) + Decimal((FrameCounter-1)*tframe) + TROdefault + Decimal(J * Trs))
                drain_pkt_counter = math.floor(drain_pkt_counter + drain_time / (Decimal(pkt.sniff_timestamp) + Decimal(timestampoffset)))

                if (rcv_pkt_counter - drain_pkt_counter) > 0:
                    VRXbuff.append((rcv_pkt_counter - drain_pkt_counter))
                else:
                    print ("ALERT")
                    VRXbuff.append(0)

                J = J + 1
 
            timestampPrev = timestampCurr
        print("----")
        print("VRXbuff MAX: ", numpy.max(VRXbuff))
        print("VRXbuff AVG: ", numpy.average(VRXbuff))

    except KeyboardInterrupt:
      print("\nInterrupted")

    tdrain = tframe / npackets / B
    print("Tdrain = {}".format(tdrain))


def usage():
    print("analyzer.py -c|--cap <capture_file>")
    print("<max_packets> : use \"-\" for all capture")

if __name__ == '__main__':
    main(sys.argv[1:])
