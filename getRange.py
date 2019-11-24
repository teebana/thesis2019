# This script is used to analyse the local Elasticsearch database
# and extract the different device types detected on the UNSW network.
# Each extracted device type was pushed to a another Elasticsearch database
# to be analysed separately
#
# A device type was characterised by a combination of its:
#  1) Hardware Type e.g. Mobile
#  2) Hardware Sub Type e.g. Phone
#  3) Operating System e.g. iOS 13.1
#  4) Operating Platform e.g. iPhone
#  5) Software e.g. Safari

import requests
import json
import os
import random
import time
import sys
import io

from elasticsearch import Elasticsearch

host = 'telescope-qosmos.sdn.unsw.edu.au'
port = 9200
connection = Elasticsearch([{'host': host, 'port': port}])

file = sys.argv[1]

def writeToDB(_index, _body):
    result = connection.index(index=_index, body=_body)
    print(result)


def search_database(_value, _index):

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

def in_database(operating_platform, software_name, operating_system):
	elastic_query = json.dumps({
	  "query": {
	    "bool": {
	      "must": [
	        {
	          "match": {
	            "operating_platform": operating_platform
	          }
	        },
	        {
	          "match": {
	            "software_name": software_name
	          }
	        },
	        {
	          "match": {
	            "operating_system.keyword": operating_system
	          }
	        }        
	      ]
	    }
	  }
	})

	# print(elastic_query)
	result = connection.search(index='unsw', body=elastic_query)

	if(result['hits']['total']['value'] == 0):
		return False
	else:
		return True


with io.open(file, 'r', encoding='ISO-8859-1', errors='ignore') as ua_file:
	sample_uas = ua_file.read().splitlines()

for line in sample_uas:
	sample_ua = line.split(',')[0]
	entry,count = search_database(sample_ua, 'traffic')
	if(count != 0):
		parse = entry.get('parse')
		if(parse):
			operating_platform = parse.get('operating_platform')
			if(operating_platform):
				hardware_type = parse.get('hardware_type')
				hardware_sub_type = parse.get('hardware_sub_type')
				software_name = parse.get('software_name')
				operating_system = parse.get('operating_system')
				data = {}
				data['operating_platform'] = operating_platform
				if(hardware_type):
					if(hardware_type == "server"):
						continue
					data['hardware_type'] = hardware_type
				if(hardware_sub_type):
					data['hardware_sub_type'] = hardware_sub_type
				else:
					hardware_sub_type = 'null'
					data['hardware_sub_type'] = hardware_sub_type
				if(software_name):
					data['software_name'] = software_name
				else:
					software_name = 'null'
					data['software_name'] = software_name
				if(operating_system):
					data['operating_system'] = operating_system
				else:
					operating_system = 'null'
					data['operating_system'] = operating_system

				print("OP: " + operating_platform)
				print("SW: " + software_name)
				print("OS: " + operating_system)

				if(not in_database(operating_platform, software_name, operating_system)):
					json_data = json.dumps(data)
					writeToDB('unsw', json_data)
					time.sleep(1)


