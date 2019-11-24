# This script analyses a range of log files and extracts
# the captured traffic for a specified IP address
# USAGE: python getTrafficForIP.py <public IP address>
#
# Modifications can be made to extract specific traffic 
# as well. E.g. HTTP traffic only 

import sys

IPofInterest = sys.argv[1]

start_time = 0
start_date = 29

for d in range(1):
    date = start_date + d
    full_date = '201910' + str(date)

    for t in range(24):
        _time = start_time + t
        if(_time < 10):
            full_time = '0' + str(_time) + '00'
        elif(_time < 24):
            full_time = str(_time) + '00'
        else:
            continue

        filename = full_date + '-' + full_time

        file = filename + ".csv"

        print("Analysing " + filename)

        with io.open(file, 'r', encoding='ISO-8859-1', errors='ignore') as log_file:
            lines = log_file.read().splitlines()

        for line in lines:
        	srcIP = line.split(',')[1]
        	if(IPofInterest == srcIP):
        		print(line)
