/*
* This scripts finds all the unique user agents in a .csv log file.
*
*/


package main

import (
	"fmt"
	"os"
	"bufio"
	"strings"
)

var m = make(map[string]int)
var a = []string{}

func main() {

	f, _ := os.Open("../logs/23-07-2019 - FULL.csv")
    scanner := bufio.NewScanner(f)
	for scanner.Scan() {
    	ua := strings.SplitN(scanner.Text(), ",", 3)[1]
    	add(ua)
	}
	print()

	

}

func add(s string) {
    if m[s] != 0 {
    	m[s]++;
        return // Already in the map
    }
    a = append(a, s)
    m[s] = 1
}

func print() {

	sum := 0

	for i:= 0; i < len(m); i++ {
		fmt.Printf("%s,%d\n",a[i], m[a[i]])
		sum += m[a[i]]
	}

	//fmt.Printf("Total number of entries: %d\n", sum)
}