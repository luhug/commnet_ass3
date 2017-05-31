import os
import random
import logging
import argparse
from scapy.sendrecv import send
from scapy.layers.inet import IP, ICMP
from scapy.packet import Packet, bind_layers
from scapy.fields import (BitEnumField, BitField, ShortField, ByteField,
                          ConditionalField)
from scapy.automaton import Automaton, ATMT


FORMAT = "   [RECEIVER:%(lineno)3s - %(funcName)12s()] %(message)s"
logging.basicConfig(format=FORMAT)
log = logging.getLogger('sender')
log.setLevel(logging.DEBUG)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# fixed random seed to reproduce packet loss
random.seed('TEST')


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
                   ByteField("win", 0),
                   ConditionalField(ByteField("sackcnt",0), lambda pkt:(pkt.hlen > 6 and pkt.options == 1)),
                   ConditionalField(ByteField("sackstart1",0), lambda pkt:pkt.sackcnt >= 1),
                   ConditionalField(ByteField("sacklen1",0), lambda pkt:pkt.sackcnt >= 1),
                   ConditionalField(ByteField("pad2",0), lambda pkt:pkt.sackcnt >= 2),
                   ConditionalField(ByteField("sackstart2",0), lambda pkt:pkt.sackcnt >= 2),
                   ConditionalField(ByteField("sacklen2",0), lambda pkt:pkt.sackcnt >= 2),
                   ConditionalField(ByteField("pad3",0), lambda pkt:pkt.sackcnt >= 3),
                   ConditionalField(ByteField("sackstart3",0), lambda pkt:pkt.sackcnt >= 3),
                   ConditionalField(ByteField("sacklen3",0), lambda pkt:pkt.sackcnt >= 3)]


# GBN header is coming after the IP header
bind_layers(IP, GBN, frag=0, proto=222)


class GBNReceiver(Automaton):
    """Receiver implementation for the GBN protocol using a scapy automaton.

    Attributes:
        win: Window size advertised by receiver
        p_data: loss probability for data segments (0 <= p_data < 1)
        p_ack: loss probability for acks (0 <= p_ack < 1)
        sender: IP address of the sender
        receiver: IP address of the receiver
        next: Next expected sequence number
        out_file: Name of output file
        p_file: Expected payload size
        end_receiver: Can we close the receiver?
        end_num: Sequence number of last packet + 1

    """

    def parse_args(self, receiver, sender, nbits, out_file, window, p_data,
                   p_ack, chunk_size, **kargs):
        """Initialize the automaton."""
        Automaton.parse_args(self, **kargs)
        self.win = window
        self.n_bits = nbits
        assert self.win <= 2**self.n_bits
        self.p_data = p_data
        assert 0 <= p_data and p_data < 1
        self.p_ack = p_ack
        assert 0 <= p_ack and p_ack < 1
        self.sender = sender
        self.receiver = receiver
        self.next = 0
        self.out_file = out_file
        self.p_size = chunk_size
        self.end_receiver = False
        self.end_num = -1
        self.buffer = {}
        self.sacksize = 0
        self.lastreceived = 0

    def master_filter(self, pkt):
        """Filter packts of interest.

        Source has be the sender and both IP and GBN headers are required.
        """
        return (IP in pkt and pkt[IP].src == self.sender and GBN in pkt
                and ICMP not in pkt)

    @ATMT.state(initial=1)
    def BEGIN(self):
        """Start state of the automaton."""
        raise self.WAIT_SEGMENT()

    @ATMT.state(final=1)
    def END(self):
        """End state of the automaton."""
        log.debug("Receiver closed")

    @ATMT.state()
    def WAIT_SEGMENT(self):
        """Waiting state for new packets."""
        log.debug("Waiting for segment %s" % self.next)

    @ATMT.receive_condition(WAIT_SEGMENT)
    def packet_in(self, pkt):
        """Transition: Packet is coming in from the sender."""
        raise self.DATA_IN(pkt)

    @ATMT.state()
    def DATA_IN(self, pkt):
        """State for incoming data."""
        # received segment was lost/corrupted in the network
        self.lastreceived = pkt.getlayer(GBN).num
        if random.random() < self.p_data:
            log.debug("Data segment lost: [type = %s num = %s win = %s]",
                      pkt.getlayer(GBN).type,
                      pkt.getlayer(GBN).num,
                      pkt.getlayer(GBN).win)
            raise self.WAIT_SEGMENT()

        # segment was received correctly
        else:
            log.debug("Received: [type = %s num = %s win = %s]",
                      pkt.getlayer(GBN).type,
                      pkt.getlayer(GBN).num,
                      pkt.getlayer(GBN).win)
            self.newestreceived = pkt.getlayer(GBN).num

            # check if segment is a data segment
            ptype = pkt.getlayer(GBN).type
            if ptype == 0:

                # check if last packet --> end receiver
                if len(pkt.getlayer(GBN).payload) < self.p_size:
                    self.end_receiver = True
                    self.end_num = int(
                        (pkt.getlayer(GBN).num + 1) % 2**self.n_bits)

                # this is the segment with the expected sequence number
                if pkt.getlayer(GBN).num == self.next:
                    log.debug("Packet has expected sequence number: %s",
                              pkt.getlayer(GBN).num)
                    
                    # write payload to file
                    result = open(self.out_file, 'ab')
                    result.write(str(pkt.getlayer(GBN).payload))
                    result.close()
                    log.debug("Delivered packet to upper layer: %s",
                              pkt.getlayer(GBN).num)
                    self.next = int((self.next + 1) % 2**self.n_bits)

                    #[3.2.1] Check if there are any packets in the buffer that can now be written
                    while self.next in self.buffer:
                        log.debug("Writing packet from buffer: %s", self.next)
                        result = open(self.out_file, 'ab')
                        result.write(str(self.buffer[self.next]))
                        result.close()
                        log.debug("Delivered packet to upper layer: %s",
                                  self.next)
                        del self.buffer[self.next] #Prevent memory leak
                        self.next = int((self.next + 1) % 2**self.n_bits)
                                        
                # this was not the expected segment but is in recieving window
                elif ((pkt.getlayer(GBN).num > self.next and pkt.getlayer(GBN).num < self.next + self.win) or ((self.next + self.win)>=2**self.n_bits and pkt.getlayer(GBN).num < (self.next+self.win)%2**self.n_bits)):
                    log.debug("Out of sequence segment [num = %s] received. "
                              "Expected %s", pkt.getlayer(GBN).num, self.next)
                    #[3.2.1] Write packet to buffer if not already in buffer
                    if ~(pkt.getlayer(GBN).num in self.buffer):
                        log.debug("Writing %s to buffer" % pkt.getlayer(GBN).num)
                        self.buffer[pkt.getlayer(GBN).num] = pkt.getlayer(GBN).payload
                                        
            else:
                # we received an ack while we are supposed to receive only
                # data segments
                log.error("ERROR: Received ACK segment: %s" % pkt.show())
                raise self.WAIT_SEGMENT()

            # send ack back to sender
            if random.random() < self.p_ack:
                # the ack will be lost, discard it
                log.debug("Lost ACK: %s" % self.next)

            # the ack will be received correctly
            else:

                #If SACK is not supported
                if pkt.getlayer(GBN).options == 0:
                    header_GBN = GBN(type="ack",
                                     options=0,
                                     len=0,
                                     hlen=6,
                                     num=self.next,
                                     win=self.win)

                    log.debug("Sending ACK: %s" % self.next)
                    send(IP(src=self.receiver, dst=self.sender) / header_GBN,
                         verbose=0)
                
                #If SACK is supported
                else:
                    log.debug("Starting SACK procedure")
                    first = True
                    x = self.next
                    #Iterate over all possible SACK blocks.
                    sackstart = list()
                    sacklen = list()
                    for i in range(3):
                        #If nothing more left to ACK
                        if len(self.buffer.keys()) == 0 or x > 2**self.n_bits:
                            break                            
                        #Generate contigious blocks
                        
                        while x % 2**self.n_bits != (self.next - 1) % 2**self.n_bits:
                            if x in self.buffer:
                                if first:
                                    sackstart.append(x)
                                    prev = x
                                    sacklen.append(1)
                                    first = False
                                elif x == prev + 1:
                                    sacklen[i] += 1
                                    prev = x
                                elif ~first:
                                    break
                            x += 1
                        first = True

                    sackcnt = len(sackstart)
                    header_GBN = GBN(type="ack",
                                     options=1,
                                     len=0,
                                     hlen=6 + 3*len(sackstart),
                                     num=self.next,
                                     win=self.win,
                                     )
                    #Add SACK fields as needed
                    self.sacksize = sum(sacklen)
                    if sackcnt >= 1:
                        header_GBN.sackcnt = sackcnt
                        header_GBN.sackstart1 = sackstart[0]
                        header_GBN.sacklen1 = sacklen[0]
                        if sackcnt >= 2:
                            header_GBN.sackstart2 = sackstart[1]
                            header_GBN.sacklen2 = sacklen[1]
                            if sackcnt >= 3:
                                header_GBN.sackstart3 = sackstart[2]
                                header_GBN.sacklen3 = sacklen[2]

                    log.debug("Sending SACK: %s; Buffer: %s" , self.next, str(self.buffer.keys()))
                    send(IP(src=self.receiver, dst=self.sender) / header_GBN,
                         verbose=0)



                # last packet received and all ACKs successfully transmitted
                # --> close receiver
                if self.end_receiver and self.end_num == self.next:
                    raise self.END()

            # transition to WAIT_SEGMENT to receive next segment
            raise self.WAIT_SEGMENT()


if __name__ == "__main__":
    # get input arguments
    parser = argparse.ArgumentParser('GBN receiver')
    parser.add_argument('receiver_IP', type=str,
                        help='The IP address of the receiver')
    parser.add_argument('sender_IP', type=str,
                        help='The IP address of the sender')
    parser.add_argument('n_bits', type=int,
                        help='The number of bits used to encode the sequence '
                        'number field')
    parser.add_argument('output_file', type=str,
                        help='Path to the output file (data from sender is '
                        'stored in this file)')
    parser.add_argument('window_size', type=int,
                        help='The window size of the receiver')
    parser.add_argument('data_l', type=float,
                        help='The loss probability of a data segment '
                        '(between 0 and 1.0)')
    parser.add_argument('ack_l', type=float,
                        help='The loss probability of an ACK '
                        '(between 0 and 1.0)')

    args = parser.parse_args()
    out_file = args.output_file             # filename of output file
    chunk_size = 2**6                       # normal payload size
    n_bits = args.n_bits
    assert n_bits <= 8

    # delete previous output file (if it exists)
    out_file = args.output_file
    if os.path.exists(out_file):
        os.remove(out_file)

    # initial setup of automaton
    receiver = GBNReceiver(args.receiver_IP, args.sender_IP, n_bits, out_file,
                           args.window_size, args.data_l, args.ack_l,
                           chunk_size)
    # start automaton
    receiver.run()
