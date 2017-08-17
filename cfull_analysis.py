import getopt
import pyshark
import numpy
import math
import sys
from decimal import *

RTP_CLOCK = 90000  # RTP clock Frequency is defined at 90kHz
B = 1.1  # Drain factor as defined in SMPTE2110-21


def frame_len(capture):
    # To calculate Npackets, you need to count the amount of packets between two rtp.marker == 1 flags.
    # This is as easy as looking to 2 rtp.marker == 1 packets and substract the rtp.sequence number.
    # The exception will occur, the packet sequence number rotates: Modulo is your friend!!

    first_frame = None
    for pkt in capture:
        if pkt.rtp.marker == '1':
            if not first_frame:
                first_frame = int(pkt.rtp.seq)
            else:
                return (int(pkt.rtp.seq) - first_frame) % 65536
    return None


def frame_rate(capture):
    # To calculate the framerate of a given capture, you need to look at three consequent rtp time stamps [(t2-t1) +
    # (t3-t2)] / 2 will result in the average timestamp difference. Note:  the frame periods (difference between 90
    # kHz timestamps) might not appear constant For example 60/1.001 Hz frame periods effectively alternate between
    # increments of 1501 and 1502 ticks of the 90 kHz clock.
    rtp_timestamp = []

    for pkt in capture:
        if pkt.rtp.marker == '1':
            if len(rtp_timestamp) < 3:
                rtp_timestamp.append(int(pkt.rtp.timestamp))
            else:
                frame_rate_c = Decimal(RTP_CLOCK /
                                       (((rtp_timestamp[2] - rtp_timestamp[1]) + (
                                           rtp_timestamp[1] - rtp_timestamp[0])) / 2))
                return frame_rate_c
    return None


def cfull_analysis(capture, tframe, npackets, B):
    # Time different between packets
    global idx
    timediffs = []

    # SMPTE2110-21: leaky bucket model
    cfull = []

    # Amount of packets cleared out of the buffer
    cleared = []

    # Start of the experiment
    initialtime = time = oldTime = 0.000000000

    # Formula defined in SMPTE2110-21
    tdrain = tframe / npackets / Decimal(B)
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

            if oldTime != 0:
                timediff = time - oldTime
                timediffs.append(timediff)
                clearnbr = math.floor((Decimal(time) - Decimal(initialtime)) / Decimal(tdrain))
                cleared.append(clearnbr)
                buffer = cfull[-1] + 1 - (cleared[-1] - cleared[-2])

                if buffer >= 0:
                    cfull.append(buffer)
                if buffer < 0:
                    cfull.append(0)
            oldTime = time

    except KeyboardInterrupt:
        print("\nInterrupted")

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

    return cfull


def write_array(filename, array):
    text_file = open(filename, "w")

    idx = 0

    while idx < len(array):
        text_file.write(str(array[idx]) + "\n")
        idx += 1

    text_file.close()
    return 0


def usage():
    print("cfull_analysis.py -c|--cap <capture_file> -g|--group <multicast_group> -p|--port <udp_port>")


def getarguments(argv):
    global opts
    short_opts = 'hc:g:p:'
    long_opts = ["help", "cap=", "group=", "port="]

    try:
        opts, args = getopt.getopt(argv, short_opts, long_opts)
        if not opts:
            print("No options supplied")
            usage()
            sys.exit(2)
    except getopt.GetoptError:
        print("Error in options {}".format(opts))
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-c", "--cap"):
            capfile = arg
        elif opt in ("-g", "--group"):
            group = arg
        elif opt in ("-p", "--port"):
            port = arg
        else:
            print("unknown option " + opt)
            usage()
            sys.exit()
    return (capfile, group, port)


if __name__ == '__main__':
    capfile, group, port = getarguments(sys.argv[1:])

    capture = pyshark.FileCapture(capfile, keep_packets=False, decode_as={"udp.port=" + port: 'rtp'}, display_filter='ip.dst==' + group + ' && rtp.marker == 1')
    frame_ln = frame_len(capture)
    print("Npackets  : ", frame_ln)

    framerate = frame_rate(capture)
    print("Frame Frequency: ", round(framerate, 2), " Hz")
    tframe = 1 / framerate

    capture = pyshark.FileCapture(capfile, keep_packets=False, decode_as={"udp.port=" + port: 'rtp'},
                                  display_filter='ip.dst==' + group)
    cfull_array = cfull_analysis(capture, tframe, frame_ln, B)

    write_array(capfile + "_cfull_" + ".txt", cfull_array)