#!/bin/bash

# To terminate the sender and receiver if e.g. ctrl-c is used
function clean_up {
	echo "clean_up"

	ps ax | grep "python $SENDER_FILE $LOCAL_SENDER_IP $LOCAL_RECEIVER_IP $NBITS $IN_FILE $SENDER_WIN_SIZE $Q_3_2 $Q_3_3 $Q_3_4" | grep -v "grep" | awk '{print $1}' | while read x; do sudo kill -9 $x; done
	
	ps ax | grep "python $RECEIVER_FILE $LOCAL_RECEIVER_IP $LOCAL_SENDER_IP $NBITS $OUT_FILE $RECEIVER_WIN_SIZE $DATA_L $ACK_L" | grep -v "grep" | awk '{print $1}' | while read x; do sudo kill -9 $x; done

	exit
}

trap clean_up INT TERM

# Your local IP addresses. Do not change!
LOCAL_SENDER_IP="1.0.0.1"
LOCAL_RECEIVER_IP="1.0.0.2"



########################################################################################################
# Changeable parameters                                                                                #
########################################################################################################

# Filenames of receiver and sender implementation
RECEIVER_FILE="receiver.py"
SENDER_FILE="sender.py"

# Parameters for sender and receiver
NBITS=8                    # The number of bits used to encode the sequence number

# Parameters for sender
IN_FILE=mandelbrot.bmp    # Data to transmit (e.g. sample_text.txt or ETH_logo.png)
SENDER_WIN_SIZE=128        # Window size of the sender
Q_3_2=0                    # Use Selective Repeat implemented in question 3.2 (0 or 1)
Q_3_3=1                    # Use Selective Acknowledgments implemented in question 3.3 (0 or 1)
Q_3_4=0                    # Use Congestion Control implemented in question 3.4/Bonus (0 or 1)

# Parameters for receiver
OUT_FILE=mandelout.bmp      # Output file for the received data from the sender
RECEIVER_WIN_SIZE=4        # Window size of the receiver
DATA_L=0.2                   # Loss probability of data segments (between 0 and 1.0)
ACK_L=0                    # Loss probability of ACKs (between 0 and 1.0)

########################################################################################################
# END changeable parameters                                                                            #
########################################################################################################



# Check that Selective Repeat and SACK are not used at the same time
if [ $Q_3_2 -eq 1 -a $Q_3_3 -eq 1 ]; then
	echo "You cannot use Selective Repeat and SACK at the same time."
	exit
fi

# Start the receiver
echo "Start receiver"
sudo ip netns exec receiver_ns python $RECEIVER_FILE $LOCAL_RECEIVER_IP $LOCAL_SENDER_IP $NBITS $OUT_FILE $RECEIVER_WIN_SIZE $DATA_L $ACK_L &

sleep 0.5

# Start the sender
echo "Start sender"
sudo ip netns exec sender_ns python $SENDER_FILE $LOCAL_SENDER_IP $LOCAL_RECEIVER_IP $NBITS $IN_FILE $SENDER_WIN_SIZE $Q_3_2 $Q_3_3 $Q_3_4 &

wait
