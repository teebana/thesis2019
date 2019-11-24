/*
* Initially, the user agent entries in a log file are ordered chronologically.
* This script maps and prints the user agent entries by IP address instead.
*
*/

package main

import (
	"fmt"
	"bufio"
	"time"
	"os"
	"strings"
)



var m = make(map[string]map[string]bool)
var start = time.Now()
func main() {

	f, _ := os.Open("../logs/191019-0900.csv")
    scanner := bufio.NewScanner(f)
	for scanner.Scan() {
    	line := scanner.Text()
    	IP := strings.Split(line, ",")[2]
    	ua := strings.Split(line, ",")[0]
    	IP = strings.TrimSpace(IP)
    	ua = strings.TrimSpace(ua)
    	m[IP] = add(ua, IP)
    	elapsed := time.Since(start)
    	//fmt.Println(elapsed)
		if(elapsed > 60*time.Second){
			fmt.Printf("Printing...\n")
			print()
			start = time.Now()
		}
	}
	print()

	

}

func add(ua string, IP string)(map[string]bool){
    
	if m[IP] == nil { // Map has not been created for this client IP

		m[IP] = make(map[string]bool) // Make map for this client IP	
	}

	if ua == "" {
		return m[IP] // User-Agent is NULL
	}

	if m[IP][ua]{
		return m[IP] // Already in map
	}

	m[IP][ua] = true

	return m[IP]

}

func print() {

	for IP := range m {
		fmt.Printf("%s\n", IP)
		for ua := range m[IP]{
			fmt.Printf(",%s\n", ua)
		}
	}

}