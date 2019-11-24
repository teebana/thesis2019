# This script is used to test the response time of local Elasticsearch database
# 
# USAGE: python db_response_time.py <number of entries to resolve>
# Output: Time taken to resolve the number of entries specified in command line
#         For response time (per entry), divide the time elapsed by the number of entries

import requests
import json
import os
import random
import sys
import time
import io

from elasticsearch import Elasticsearch

host = 'telescope-qosmos.sdn.unsw.edu.au'
port = 9200
connection = Elasticsearch([{'host': host, 'port': port}])
count = int(sys.argv[1])
file = "../logs/191019-0900.csv"

def in_database(_value, _index):

    elastic_query = json.dumps({
      "query": {
        "term": {
          "parse.user_agent": {
            "value": _value
          }
        }
      }
     })

    result = connection.search(index=_index, body=elastic_query)

    if(result['hits']['total']['value'] == 0):
    	return None, 0
    else:
    	return result['hits']['hits'][0]['_source'], result['hits']['total']['value']



with io.open(file, 'r', encoding='ISO-8859-1', errors='ignore') as ua_file:
	sample_uas = ua_file.read().splitlines()

start = int(round(time.time() * 1000))
i = 0

for line in sample_uas:
	if i == count:
		end = int(round(time.time() * 1000))
		break
	sample_ua = line.split(",")[0]
	_, hits = in_database(sample_ua, "traffic")
	i = i+1

elapsed = end-start
print("Time taken: " + str(elapsed) + "ms")


