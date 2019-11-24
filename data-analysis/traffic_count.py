# This script uses the summary files generated at the end of 
# each traffic capture and counts the total number of entries

import os
import sys
import io

start_time = 0
start_date = 14
total = 0

for d in range(7):
    date = start_date + d
    full_date = str(date) + '1019'

    for t in range(24):
        _time = start_time + t
        if(_time < 10):
            full_time = '0' + str(_time) + '00'
        elif(_time < 24):
            full_time = str(_time) + '00'
        else:
            continue

        filename = full_date + '-' + full_time

        file = "logs/summary-" + filename + ".csv"

        print("Analysing " + filename)

        with io.open(file, 'r') as summary_file:
            user_agents = summary_file.read().splitlines()[3]

        count = int(user_agents.split(',')[1])
        total = total + count
    print(full_date + str(total))

print(total)