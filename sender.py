"""A Sender for the GBN protocol."""

import argparse
import Queue
import logging
from scapy.layers.inet import IP, ICMP
from scapy.packet import Packet, bind_layers
from scapy.fields import (BitEnumField, BitField, ShortField, ByteField,
                          ConditionalField)
from scapy.automaton import Automaton, ATMT
from scapy.sendrecv import send

FORMAT = "[SENDER:%(lineno)3s - %(funcName)10s()] %(message)s"
logging.basicConfig(format=FORMAT)
log = logging.getLogger('sender')
log.setLevel(logging.DEBUG)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

TIMEOUT = 1  # number of seconds before packets are retransmitted


class GBN(Packet):
    """The GBN Header.

    It includes the following fields:
        type: data or ack
        options: sack support
        len: payload length
        hlen: header length
        num: sequence number
        win: SACK block 3 length
    """
    name = 'GBN'
    fields_desc = [BitEnumField("type", 0, 1, {0: "data", 1: "ack"}),
                   BitField("options", 0, 7),
                   ShortField("len", None),
                   ByteField("hlen", 0),
                   ByteField("num", 0),
                   ByteField("win", 0)]


# GBN header is coming after the IP header
bind_layers(IP, GBN, frag=0, proto=222)


class GBNSender(Automaton):
    """Sender implementation for the GBN protocol using a scapy automaton.

    Attributes:
        win: Maximum window size of the sender
        receiver: IP address of the receiver
        sender: IP address of the sender
        q: Queue for all payload messages
        current: Sequence number of next data packet to send
        unack: First unacked segment
        receiver_win: Current window advertised by receiver, initialized with
                      sender window size
        Q_3_2: Is Selective Repeat used
        SACK: Is SACK used
        Q_3_4: Is Congestion Control used
    """

    def parse_args(self, sender, receiver, n_bits, payloads, win,
                   Q_3_2, Q_3_3, Q_3_4, **kwargs):
        """Initialize Automaton."""
        Automaton.parse_args(self, **kwargs)
        self.win = win
        self.n_bits = n_bits
        assert self.win < 2**self.n_bits
        self.receiver = receiver
        self.sender = sender
        self.q = Queue.Queue()
        for item in payloads:
            self.q.put(item)

        self.buffer = {}
        self.current = 0
        self.unack = 0
        self.receiver_win = win
        self.Q_3_2 = Q_3_2
        self.SACK = Q_3_3
        self.Q_3_4 = Q_3_4

    def master_filter(self, pkt):
        """Filter packts of interest.

        Source has be the receiver and both IP and GBN headers are required.
        """
        return (IP in pkt and pkt[IP].src == self.receiver and GBN in pkt
                and ICMP not in pkt)

    @ATMT.state(initial=1)
    def BEGIN(self):
        """Start state of the automaton."""
        raise self.SEND()

    @ATMT.state(final=1)
    def END(self):
        """End state of the automaton."""
        log.debug("All packets successfully transmitted!")

    @ATMT.state()
    def SEND(self):
        """Main state of sender.

        New packets are transmitted to the receiver as long as there is space
        in the window.
        """
        # check if you still can send new packets to the receiver
        if len(self.buffer) < min(self.win, self.receiver_win):
            try:
                # get next payload (automatically removes it from queue)
                payload = self.q.get(block=False)
                log.debug("Sending packet num: %s" % self.current)

                # add the current segment to the payload and SACK buffer
                self.buffer[self.current] = payload
                log.debug("Current buffer size: %s" % len(self.buffer))

                ###############################################################
                # TODO:                                                       #
                # create a GBN header with the correct header field values    #
                # send a packet to the receiver containing the created header #
                # and the corresponding payload                               #
                ###############################################################

                header_GBN = GBN(type='data',options=0,len=len(payload),hlen=6,num=self.current,win=self.win)
                send(IP(src=self.sender, dst=self.receiver) / header_GBN / payload)


                # sequence number of next packet
                self.current = int((self.current + 1) % 2**self.n_bits)

                # back to the beginning of the state
                # (send next packet if possible)
                raise self.SEND()

            # no more payload pieces in the queue --> if all are acknowledged,
            # we can end the sender
            except Queue.Empty:
                if self.unack == self.current:
                    raise self.END()

    @ATMT.receive_condition(SEND)
    def packet_in(self, pkt):
        """Transition: Packet coming in from the receiver"""
        log.debug("Received packet: %s" % pkt.getlayer(GBN).num)
        raise self.ACK_IN(pkt)

    @ATMT.state()
    def ACK_IN(self, pkt):
        """State for received ACK."""
        # check if type is ack
        if pkt.getlayer(GBN).type == 0:
            log.error("Error: data type received instead of ack %s" % pkt)
            raise self.SEND()
        else:
            log.debug("Received ACK %s" % pkt.getlayer(GBN).num)

            # set the receiver window size to the received value
            self.receiver_win = pkt.getlayer(GBN).win

            # handle sequence number overflow
            if self.current < self.unack:
                temp_end = self.current + 2**self.n_bits
            else:
                temp_end = self.current

            # list with expected ack numbers not yet seen
            # (self.unack+1 ... self.current)
            # "+1" because the receiver always sends an ack with the number of
            # the next expected packet
            good_ack = [int((x+1) % 2**self.n_bits)
                        for x in range(self.unack, temp_end)]
            ack = pkt.getlayer(GBN).num

            # ack packet has "good" sequence number
            if ack in good_ack:

                ############################################################
                # TODO:                                                    #
                # remove all the acknowledged sequence numbers from buffer #
                ############################################################

                #Delete all elements from buffer with sequence numbers <= ack
                for x in range(ack):
                    del self.buffer[ack]

                # set self.unack to the first not acknowledged packet
                self.unack = ack

            else:
                # could be interesting for the selective repeat question or the
                # SACK question...
                pass

        # back to SEND state
        raise self.SEND()

    @ATMT.timeout(SEND, TIMEOUT)
    def timeout_reached(self):
        """Transition: Timeout is reached for first unacknowledged packet."""
        log.debug("Timeout for sequence number %s" % self.unack)
        raise self.RETRANSMIT()

    @ATMT.state()
    def RETRANSMIT(self):

        ##############################################
        # TODO:                                      #
        # retransmit all the unacknowledged packets  #
        # (all the packets currently in self.buffer) #
        ##############################################
        for seqNr in self.buffer:
            header_GBN = GBN(type='data',
                             options=0,
                             len=len(self.buffer[seqNr]),
                             hlen=6,num=seqNr,
                             win=self.win)
            
            send(IP(src=self.sender, dst=self.receiver) / header_GBN / self.buffer[seqNr])




        # back to SEND state
        raise self.SEND()


if __name__ == "__main__":
    # get input arguments
    parser = argparse.ArgumentParser('GBN sender')
    parser.add_argument('sender_IP', type=str,
                        help='The IP address of the sender')
    parser.add_argument('receiver_IP', type=str,
                        help='The IP address of the receiver')
    parser.add_argument('n_bits', type=int,
                        help='The number of bits used to encode the sequence '
                             'number field')
    parser.add_argument('input_file', type=str,
                        help='Path to the input file')
    parser.add_argument('window_size', type=int,
                        help='The window size of the sender')
    parser.add_argument('Q_3_2', type=int,
                        help='Use Selective Repeat (question 3.2)')
    parser.add_argument('Q_3_3', type=int,
                        help='Use Selective Acknowledgments (question 3.3)')
    parser.add_argument('Q_3_4', type=int,
                        help='Use Congestion Control (question 3.4/Bonus)')

    args = parser.parse_args()

    n_bits = args.n_bits
    assert n_bits <= 8

    in_file = args.input_file
    payload_to_send_bin = list()  # list for binary payload
    chunk_size = 2**6             # chunk size of payload

    # fill payload list
    with open(in_file, "rb") as file_in:
        while True:
            chunk = file_in.read(chunk_size)
            if not chunk:
                break
            payload_to_send_bin.append(chunk)

    # initial setup of automaton
    sender = GBNSender(args.sender_IP, args.receiver_IP, n_bits,
                       payload_to_send_bin, args.window_size, args.Q_3_2,
                       args.Q_3_3, args.Q_3_4)

    # start automaton
    sender.run()
