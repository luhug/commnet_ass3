#!/bin/bash

# To terminate the sender and receiver if e.g. ctrl-c is used
function clean_up {
	echo "clean_up"
	if [ $TEST_SENDER_OR_RECEIVER -eq 1 ]; then
		ps ax | grep "python $SENDER_FILE $MY_IP $NEIGHBOR_IP $NBITS $IN_FILE $SENDER_WIN_SIZE $Q_3_2 $Q_3_3 $Q_3_4" | grep -v "grep" | awk '{print $1}' | while read x; do sudo kill -9 $x; done
	fi

	if [ $TEST_SENDER_OR_RECEIVER -eq 2 ]; then
		ps ax | grep "python $RECEIVER_FILE $MY_IP $NEIGHBOR_IP $NBITS $OUT_FILE $RECEIVER_WIN_SIZE $DATA_L $ACK_L" | grep -v "grep" | awk '{print $1}' | while read x; do sudo kill -9 $x; done
	fi

	exit
}

trap clean_up INT TERM

# Your IP addresses (sender or receiver). Do not change!
MY_IP="192.168.56.25"



########################################################################################################
# Changeable parameters                                                                                #
########################################################################################################

# The IP of the group you want to communicate with.
# Format: 192.168.56.X - X=group number
NEIGHBOR_IP="192.168.56.4"

# Filenames of receiver and sender implementation
RECEIVER_FILE="receiver.py"
SENDER_FILE="sender.py"

# 1 for sender, 2 for receiver
TEST_SENDER_OR_RECEIVER=1

# Parameters for sender and receiver
NBITS=8                    # The number of bits used to encode the sequence number

# Parameters for sender
IN_FILE=laurent.jpg    # Data to transmit (e.g. sample_text.txt or ETH_logo.png)
SENDER_WIN_SIZE=128          # Window size of the sender
Q_3_2=0                    # Use Selective Repeat implemented in question 3.2 (0 or 1)
Q_3_3=1                    # Use Selective Acknowledgments implemented in question 3.3 (0 or 1)
Q_3_4=0                    # Use Congestion Control implemented in question 3.4/Bonus (0 or 1)

# Parameters for receiver
OUT_FILE=laurent.jpg      # Output file for the received data from the sender
RECEIVER_WIN_SIZE=128        # Window size of the receiver
DATA_L=0                   # Loss probability of data segments (between 0 and 1.0)
ACK_L=0                    # Loss probability of ACKs (between 0 and 1.0)

########################################################################################################
# END changeable parameters                                                                            #
########################################################################################################



# Check that Selective Repeat and SACK are not used at the same time
if [ $Q_3_2 -eq 1 -a $Q_3_3 -eq 1 ]; then
	echo "You cannot use Selective Repeat and SACK at the same time."
	exit
fi

# Start sender if TEST_SENDER_OR_RECEIVER==1
if [ $TEST_SENDER_OR_RECEIVER -eq 1 ]; then
	echo "Start sender"
	sudo python $SENDER_FILE $MY_IP $NEIGHBOR_IP $NBITS $IN_FILE $SENDER_WIN_SIZE $Q_3_2 $Q_3_3 $Q_3_4 &
fi

# Start receiver if TEST_SENDER_OR_RECEIVER==2
if [ $TEST_SENDER_OR_RECEIVER -eq 2 ]; then
	echo "Start receiver"
	sudo python $RECEIVER_FILE $MY_IP $NEIGHBOR_IP $NBITS $OUT_FILE $RECEIVER_WIN_SIZE $DATA_L $ACK_L &
fi

wait
