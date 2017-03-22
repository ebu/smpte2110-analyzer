from decimal import Decimal

import sys
import getopt
import numpy as np
import pyshark
import math

RTP_CLOCK = 90000

def frame_len(capture):
    # To calculate Npackets, you need to count the amount of packets between two rtp.marker == 1 flags.
    # This is as easy as looking to 2 rtp.marker == 1 packets and substract the rtp.sequence number.
    # The exception that might occurs is that the packet sequence number rotates.

    first_frame = None
    for pkt in capture:
        if pkt.rtp.marker == '1':
            if not first_frame:
                first_frame = int(pkt.rtp.seq)
            else:
                return int(pkt.rtp.seq) - first_frame
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
                    (((rtp_timestamp[2] - rtp_timestamp[1]) + (rtp_timestamp[1] - rtp_timestamp[0])) / 2))
                return frame_rate_c
    return None


def vrx(capture, trs, tframe, npackets):
    res = []
    tvd = 0
    prev = None  # previous packet
    frame_idx = 0  # frame index
    initial_tm = None  # first frame timestamp
    drained = 0
    drained_prev = 0
    vrx_prev = 0
    vrx_curr = 0
    for pkt in capture:
        cur_tm = Decimal(pkt.sniff_timestamp)  # current timestamp
        if prev and prev.rtp.marker == '1':  # new frame
            if frame_idx == 0:  # first frame
                # Should use each first packet as a Tvd
                initial_tm = cur_tm
            tvd = initial_tm + frame_idx * tframe
            drained = drained_prev = 0
            frame_idx += 1

        if initial_tm:

            # should not drain any more packet after time: Tvd + Npackets * Trs
            # drained = int((cur_tm - initial_tm) / trs)
            if (cur_tm - tvd) < (tvd + npackets * trs):
                drained = math.ceil((cur_tm - tvd + trs) / trs)

            vrx_curr = vrx_prev + 1 - (drained - drained_prev)
            if vrx_curr < 0:
                vrx_curr = 0
                print("VRX buffer underrun")

            drained_prev = drained

        res.append(vrx_curr)
        vrx_prev = vrx_curr
        prev = pkt

    return res


def write_array(filename, array):
    text_file = open(filename, "w")

    idx = 0
    while idx < len(array):
        text_file.write(str(array[idx]) + "\n")
        idx += 1

    text_file.close()
    return None

def usage():
    print("vrx_analysis.py -c|--cap <capture_file> -g|--group <multicast_group> -p|--port <udp_port>")

def getarguments(argv):
    short_opts = 'hc:g:p:'
    long_opts  = ["help", "cap=", "group=", "port="]

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
    RACTIVE = Decimal(1080 / 1125)
    B = Decimal(1.1)

    capfile, group, port = getarguments(sys.argv[1:])

    capture = pyshark.FileCapture(capfile, keep_packets=False, decode_as={"udp.port=" + port: 'rtp'},
                                  display_filter='ip.dst==' + group + ' && rtp.marker == 1')
    frame_ln = frame_len(capture)
    print("Npackets  : ", frame_ln)

    framerate = frame_rate(capture)
    print("Frame Frequency: ", round(framerate, 2), " Hz")
    tframe = 1 / framerate

    trs = tframe * RACTIVE / frame_ln


    capture = pyshark.FileCapture(capfile, keep_packets=False, decode_as={"udp.port=" + port: 'rtp'},
                                  display_filter='ip.dst==' + group)
    vrx_buf = vrx(capture, trs, tframe, frame_ln)

    print("VRX max: ", np.max(vrx_buf))
    #np.save('vrx_' + capfile, np.asarray(vrx_buf))
    write_array('vrx_' + capfile + '.txt', vrx_buf)

