#!/bin/bash

# This script runs a traffic capture for an hour
# and terminates and restarts it at the end of the hour.
#
# Traffic captured during the first hour is stored in its 
# own file, separate to the traffic captured in the next hour.
#
# To change the number of hours traffic capture is run for, change:
# while [ $count -le XX ]
# where XX is the number of hours

count=1
while [ $count -le 168 ]
	do
		date=$(date "+%Y%m%d-%H%M")
		echo $date
		summary="summary-${date}"
		file_name="${date}.csv"
		sudo ./tls $summary > $file_name &
		pid=$!
		echo Process $pid started
		sleep 1h
		sudo kill -SIGINT $pid
		sudo killall tls
		echo Process $pid killed
		((count++))
	done