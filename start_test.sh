#!/bin/bash

# To terminate the sender and receiver if e.g. ctrl-c is used
function clean_up {
	echo "clean_up"

	ps ax | grep "python client.py $NEIGHBOR_IP $PORT $TEST_NUM" | grep -v "grep" | awk '{print $1}' | while read x; do sudo kill -9 $x; done

	if [ $TEST_NUM -eq 1 ] || [ $TEST_NUM -eq 3 ] || [ $TEST_NUM -eq 5 ]; then
		ps ax | grep "python $SENDER_FILE $MY_IP $NEIGHBOR_IP $NBITS $IN_FILE $SENDER_WIN_SIZE $Q_3_2 $Q_3_3 $Q_3_4" | grep -v "grep" | awk '{print $1}' | while read x; do sudo kill -9 $x; done
	fi

	if [ $TEST_NUM -eq 2 ] || [ $TEST_NUM -eq 4 ]; then
		ps ax | grep "python $RECEIVER_FILE $MY_IP $NEIGHBOR_IP $NBITS $OUT_FILE $RECEIVER_WIN_SIZE $DATA_L $ACK_L" | grep -v "grep" | awk '{print $1}' | while read x; do sudo kill -9 $x; done
	fi

	exit
}

trap clean_up INT TERM


########################################################################################################
# Changeable parameters                                                                                #
########################################################################################################

# Change X to your group number!
X=25

# The test you want to perform
# 1: sender Q3.1 (header, ACK handling and retransmission after timeout)
# 2: receiver Q3.2 (buffering of out-of-order packets)
# 3: sender Q3.2 (Selective Repeat)
# 4: receiver Q3.3 (SACK header generation)
# 5: sender Q3.3 (retransmission after receiving SACK header)
TEST_NUM=3

# Filenames of receiver and sender implementation
RECEIVER_FILE="receiver.py"
SENDER_FILE="sender.py"

########################################################################################################
# END changeable parameters                                                                            #
########################################################################################################


if [ $X -eq 0 ]; then
	echo "Please change X to your group number!"
	exit
fi

# Your IP address.
MY_IP="192.168.56.$X"

# The port used for the external TCP connection to the test server.
PORT=$((10000 + X))

NEIGHBOR_IP="192.168.56.99"

# Start client
sudo python client.py $NEIGHBOR_IP $PORT $TEST_NUM &

# Parameters for sender and receiver
NBITS=5

# Parameters for sender
IN_FILE=to_send_test.txt   

# Parameters for receiver
OUT_FILE=out_test.txt      
DATA_L=0                   
ACK_L=0                    

if [ $TEST_NUM -eq 1 ]; then
	echo "Start sender for test 1"
	sleep 2
	SENDER_WIN_SIZE=5
	Q_3_2=0                    
	Q_3_3=0                    
	Q_3_4=0  
	sudo python $SENDER_FILE $MY_IP $NEIGHBOR_IP $NBITS $IN_FILE $SENDER_WIN_SIZE $Q_3_2 $Q_3_3 $Q_3_4 &
fi

if [ $TEST_NUM -eq 2 ]; then
	echo "Start receiver for test 2"
	RECEIVER_WIN_SIZE=5
	sudo python $RECEIVER_FILE $MY_IP $NEIGHBOR_IP $NBITS $OUT_FILE $RECEIVER_WIN_SIZE $DATA_L $ACK_L &
fi

if [ $TEST_NUM -eq 3 ]; then
	echo "Start sender for test 3"
	sleep 2
	SENDER_WIN_SIZE=4
	Q_3_2=1                    
	Q_3_3=0                    
	Q_3_4=0  
	sudo python $SENDER_FILE $MY_IP $NEIGHBOR_IP $NBITS $IN_FILE $SENDER_WIN_SIZE $Q_3_2 $Q_3_3 $Q_3_4 &
fi

if [ $TEST_NUM -eq 4 ]; then
	echo "Start receiver for test 4"
	RECEIVER_WIN_SIZE=10
	sudo python $RECEIVER_FILE $MY_IP $NEIGHBOR_IP $NBITS $OUT_FILE $RECEIVER_WIN_SIZE $DATA_L $ACK_L &
fi

if [ $TEST_NUM -eq 5 ]; then
	echo "Start sender for test 5"
	sleep 2
	SENDER_WIN_SIZE=10
	Q_3_2=0         
	Q_3_3=1                    
	Q_3_4=0  
	sudo python $SENDER_FILE $MY_IP $NEIGHBOR_IP $NBITS $IN_FILE $SENDER_WIN_SIZE $Q_3_2 $Q_3_3 $Q_3_4 &
fi

wait
