/*
* This function takes in a TLS payload, confirms if it
* is a Client Hello packet, and extracts the array of supported
* cipher suites.
* 
* Can easily be modified to extract (and return) more attributes e.g. server (host) name
*
*/

package main

// import "fmt"

func parseTcpPayloadForTls(payloadPtr *[]byte)(bool, []byte, string) {
	payload := *payloadPtr
	payloadLength := len(payload)
	var cipher_suites []byte
	var server_name string
	//var tls_version int
	//var compression_methods []byte

	// If the packet is a Client Hello
	if payloadLength > 6 && payload[0] == 0x16 && payload[5] == 0x01 {

		// Extract TLS Version
		//tls_version = bytesToInt16(payload[1:3])

		// Extract Session ID Length and convert Hex value to Decimal (1 byte)
		session_id_length := int((payload[43:44])[0])

		// Start after <Session ID Length>
		index := 44

		// Skip over <Session IDs>
		index += session_id_length

		
		// Extract Cipher Suite Length and convert Hex value to Decimal (2 bytes)
		cipher_suite_length := bytesToInt16(payload[index : index+2])

		// Skip over <Cipher Suite Length>
		index += 2

		// Extract Cipher Suites
		cipher_suites = payload[index : index+cipher_suite_length]

		// Skip over <Cipher Suites>
		index += cipher_suite_length



		if index >= payloadLength {
			return false, cipher_suites, server_name
		}		


		// Extract <Compression Methods Length>
		compression_methods_length := int(payload[index])

		// Skip over compression methods length field
		index += 1

		// Extract Compression Methods
		//compression_methods = payload[index: index+compression_methods_length]

		// Skip over <Compression Methods>
		index += compression_methods_length

		// Extract <Extensions Length>
		extensions_length := bytesToInt16(payload[index : index+2])

		// Skip over <Extensions Length>
		index += 2


		if index >= payloadLength {
			return false, cipher_suites, server_name
		}


		for index < payloadLength {
			extension_code := bytesToInt16(payload[index : index+2])
			index += 2
			if index >= payloadLength {
				return false, cipher_suites, server_name
			}
			if extension_code == 0 {
				// fmt.Printf("%x,",payload[index : index + 2])
				server_name_length := bytesToInt16(payload[index : index+2])
				server_name_length -= 2
				index += 4
				if index >= payloadLength {
					return false, cipher_suites, server_name
				}
				if int(payload[index]) == 0 {
					server_name_length -= 3
					index += 3
					// fmt.Printf("%d,%d,",server_name_length,index)
					server_name = string(payload[index : index+server_name_length])
					break
				}
			} else {
				extensions_length = bytesToInt16(payload[index : index+2])
				index += 2
				index += extensions_length
			}
		}
		return true, cipher_suites, server_name
	}
	return false, cipher_suites, server_name
}

func bytesToInt16(byteSlice []byte) int {
	return int(byteSlice[0])<<8 + int(byteSlice[1])
}