from decimal import *

class Constants:
    PKT_SEQUENCE_BIT_DEPTH  = pow(2,16) # The RTP packet sequence number is defined as a 16 bit number.
    RTP_TIMESTAMP_BIT_DEPTH = pow(2,32) # The RTP timestamp value is defined as a 32 bit number.
    RTP_CLOCK = 90000                   # RTP clock Frequency is defined at 90kHz.

def frame_len(capture):
    # To calculate Npackets, you need to count the amount of packets between two rtp.marker == 1 flags.
    # This is as easy as looking to 2 rtp.marker == 1 packets and substract the rtp.sequence number.
    # The exception that will occurs is that the packet sequence number rotates. Modulo is your friend!

    first_frame = None
    for pkt in capture:
        if pkt.rtp.marker == '1':
            if not first_frame:
                first_frame = int(pkt.rtp.seq)
            else:
                return (int(pkt.rtp.seq) - first_frame) % Constants.PKT_SEQUENCE_BIT_DEPTH
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
                frame_rate_c = Decimal(Constants.RTP_CLOCK /
                    (( (rtp_timestamp[2] - rtp_timestamp[1]) % Constants.RTP_TIMESTAMP_BIT_DEPTH +
                       (rtp_timestamp[1] - rtp_timestamp[0]) % Constants.RTP_TIMESTAMP_BIT_DEPTH) / 2))
                return frame_rate_c
    return None

