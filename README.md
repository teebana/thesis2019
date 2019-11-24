# thesis2019

This repository holds the code developed and used for Teebana Balakumar's undergraduate thesis.

The code used for each stage of the project can be found in its corresponding directory.

## Repository Summary:

### data-acquisition
  http_util.go: used for parsing HTTP flows and extracting user agent
  script.sh: used for automatically starting and terminating traffic capture every hour
  tls.go: holds interrupt function that filters packets as they come in and sends them to the relevant parsing algorithm
  tls_util.go: used for parsing TLS flows and extracting array of cipher suites
  
### data-processing
  db_response_time.py: used for timing the performance of local Elasticsearch database
  parse_user_agent.pu: used for parsing raw user agents to interpretable JSON structures, using local database, or online database (via                           whatismybrowser.com API) if user agent was not present in local database
  
### data-analysis
  getRange.py: used for analysing local database to get range of devices found on the UNSW network
  getTrafficForIP.py: analyses a .csv log file(s) and extracts traffic flows from a specified IP address
  mapped_uas.go: maps all the user agents detected under each IP address (used for detecting NAT and static gateways)
  traffic_count.py: used for counting how many entries are in a .csv log file(s) - often in the order of millions
  unique_ua.go: analyses a .csv log file(s) and extracts all the unique user agents found
