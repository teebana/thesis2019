/*
* This function takes in a HTTP payload and extracts the 
# user agent, if it is present
#
* Can easily be modified to extract (and return) more attributes e.g. host name
*
*/

package main
//import "fmt"
import "strings"
func parseTcpPayloadForHttp(payloadPtr *[]byte) (int,string, string, string, string) {
	
	payload := *payloadPtr
	var host, user_agent, content_type, connection string
	var success bool

	// Store payload length in variable
	payloadLength := len(payload)

	// If HTTP packet doesn't have payload, return with error code 0
	if payloadLength <= 6 {
		return 0, user_agent, host, content_type, connection
	}

	// If HTTP packet isn't either a POST or GET request, return with error code 1
	if payload[0] != 'P' && payload[0] != 'G' {		
		return 1, user_agent, host, content_type, connection
	}

	// Prepare payload for string analysis
	payloadString := string(payload)
	//fmt.Printf("%s\n", payloadString)

	success, user_agent = attemptToParse("User-Agent", payloadPtr, payloadString)
	if !success {
		success, user_agent = attemptToParse("user-agent", payloadPtr, payloadString)
	}

	// If HTTP packet doesn't contain user-agent, return with error code 2
	if !success {
		return 2, user_agent, host, content_type, connection
	}

	_, host = attemptToParse("Host", payloadPtr, payloadString)

	_, content_type = attemptToParse("Content-Type", payloadPtr, payloadString)

	_, connection = attemptToParse("Cookie", payloadPtr, payloadString)

	return 3, user_agent, host, content_type, connection
}

func attemptToParse(HTTPheaderField string, payloadPtr *[]byte, payloadString string) (bool,string) {

	payload := *payloadPtr
	var field_value string

	field_index := strings.Index(payloadString, HTTPheaderField)
	if field_index != -1 {
		fieldPtr := payload[field_index:len(payloadString)]
		newline_index := strings.Index(string(fieldPtr), "\r\n")
		if newline_index != -1 {
			field_index = len(HTTPheaderField) + 2
			if(newline_index > field_index) {
				field_value = string(fieldPtr[len(HTTPheaderField) + 2:newline_index])
				return true, field_value
			}
		}	
	}
	return false, field_value
}
