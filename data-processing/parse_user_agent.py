# This script parses the raw user agents stored in 
# a range of .csv log files, using the API to online database
# provided by whatismybrowser.com.
#
# The response from the online API is sent to and cached 
# in local Elasticsearch database.

import requests
import json
import os
import random
import time
import sys
import io

from elasticsearch import Elasticsearch
#date = sys.argv[1]
ext = '.csv'
# file = filename

host = 'localhost'
port = 9200
connection = Elasticsearch([{'host': host, 'port': port}])

def writeToDB(_index,_type, _body):
    result = connection.index(index=_index, body=_body)
    print(result)
    
    


def APIcall(ua_string):

    # Where will the request be sent to
    api_url = "https://api.whatismybrowser.com/api/v2/user_agent_parse"

    # -- Set up HTTP Headers
    headers = {
        'X-API-KEY': "0b202ddc47bd143e356768bbf17ff9f5",
    }

    # -- Set up the request data
    post_data = {}
    post_data["user_agent"] = ua_string


    # -- Make the request
    result = requests.post(api_url, data=json.dumps(post_data), headers=headers)

    # -- Try to decode the api response as json
    result_json = {}
    try:
        result_json = result.json()
        error = 0
    except Exception as e:
        print("Couldn't decode the response as JSON:", e)
        error = 1
        #exit()

    # -- Check that the server responded with a "200/Success" code
    if result.status_code != 200:
        #print("ERROR: not a 200 result. instead got: %s." % result.status_code)
        #print(json.dumps(result_json, indent=2))
        error = 1
        #exit()

    # -- Check the API request was successful
    if result_json.get('result', {}).get('code') != "success":
        #print("The API did not return a 'success' response. It said: result code: %s, message_code: %s, message: %s" % (result_json.get('result', {}).get('code'), result_json.get('result', {}).get('message_code'), result_json.get('result', {}).get('message')))
        #print(json.dumps(result_json, indent=2))
        result_json['parse'] = {'user_agent': ua_string}
        error = 1
        #exit()

    if error != 1 and result_json.get('parse').get('user_agent') is None:
        result_json['parse']['user_agent'] = ua_string

    return result_json, error


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

def parse_user_agent(parse):

    if parse.get('is_abusive') is True:
        print("BE CAREFUL - this user agent seems abusive")
    # This user agent contains one or more fragments which appear to
    # be an attempt to compromise the security of your system

    if parse.get('simple_software_string'):
        print(parse.get('simple_software_string'))
    else:
        print("Couldn't figure out what software they're using")

    if parse.get('simple_sub_description_string'):
        print(parse.get('simple_software_string'))

    if parse.get('simple_operating_platform_string'):
        print(parse.get('simple_operating_platform_string'))

    # if version_check:
    # # Your API account has access to version checking information

    #     if version_check.get('is_checkable') is True:
    #     # This software will have information about whether it's up to date or not
    #         if version_check.get('is_up_to_date') is True:
    #             print("%s is up to date" % parse.get('software_name'))
    #         else:
    #             print("%s is out of date" % parse.get('software_name'))

    #             if version_check.get('latest_version'):
    #                 print("The latest version is %s" % ".".join(version_check.get('latest_version')))

    #             if version_check.get('update_url'):
    #                 print("You can update here: %s" % version_check.get('update_url'))



def writeToCSV(newCSVEntry):

    # Check if csv file exists
    if(os.path.exists("API-calls.csv") == True):
        csv_flag = 1
    else:
        csv_flag = 0

    # If csv file exists...
    if(csv_flag == 1):
        # Write to file
        with open("API-calls.csv", 'a') as file:
            file.write(newCSVEntry + '\n')


    # If csv file doesn't exist...
    if(csv_flag == 0):
        file = open("API-calls.csv", 'w+')
        file.write(newCSVEntry + '\n')
        file.close()


start_time = 0
start_date = 14
counter = 1
API_hits = 0

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

        file = filename + ext

        print("Analysing " + filename)

        with io.open(file, 'r', encoding='ISO-8859-1', errors='ignore') as ua_file:
            sample_uas = ua_file.read().splitlines()


        for line in sample_uas:

            # if(counter <= 5946033):
            #     counter = counter + 1
            #     continue

            print(counter)
            sample_ua = line.split(",")[0]
            print(sample_ua)

            # If user-agent is in the database...
            print("Searhing database...")
            _, count = in_database(sample_ua, "traffic")
            if(count != 0):
                CSVentry = str(counter) + ',' + str(API_hits)
                writeToCSV(CSVentry)

                print("Found in database:")
                # if error == 0:
                #     parse_user_agent(entry.get('parse'))
                # else:
                #     print(entry.get('result').get('message'))

            # User-agent isn't in database so make API call
            else:

                API_hits = API_hits + 1
                CSVentry = str(counter) + ',' + str(API_hits)
                writeToCSV(CSVentry)
                entry,count = in_database(sample_ua, "secondary")
                if(count == 0):
                    print("Not found in database: Calling API...")
                    result_json, error = APIcall(sample_ua)
                    writeToDB("secondary","user-agents", result_json)
                    writeToDB("traffic","user-agents", result_json)
                    # if(error == 0):
                    #     parse_user_agent(result_json.get('parse'))
                    # else:
                    #     print(result_json.get('result').get('message'))

                    delay = random.randint(0,5)
                    print("Waiting " + str(delay)+" seconds...")
                    time.sleep(delay)
                else:
                    writeToDB("traffic","user-agents", entry)


            counter = counter + 1
            print("\n")
    
# Now you can do whatever you need to do with the parse result
# Print it to the console, store it in a database, etc
# For example - printing to the console:



# Refer to:
# https://developers.whatismybrowser.com/api/docs/v2/integration-guide/#user-agent-parse-field-definitions
# for more fields you can use