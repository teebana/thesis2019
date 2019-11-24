/*
* This is the main program for traffic capture. It is
* responsible for initialisations and runs the interrupt
* routine (packetHandler) when a packet comes in.
*
* The interrupt routine deciphers the application layer 
* protocol (HTTP or TLS) of the packet using its dst port,
* and passes the packet to the relevant parsing algorithm:
* either parseTcpPayloadForTls(payload) or parseTcpPayloadForHttp(payload)
*
*/


package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"tls/config"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
 
  	"strings"
  	"time"
  	"math"
  	"strconv"
  	"syscall"

)
const burstSize = 32

const tcp = 6
const http = 80
const tls = 443
const natsPostInterval = 60
var m = make(map[types.IPv4Address]map[string]bool)
var a = []string{}
var flows = make(map[three_tuple]int64)
var startOfCapture = time.Now().UnixNano()
var timerStart = startOfCapture
var TcpPacketCount = 0
var HttpPacketCount = 0
var NonFirstPacketCount = 0
var NoUserAgentCount = 0
var UserAgentCount = 0
var packetCounter = 0
var TlsPacketCount = 0
var arg = os.Args[1]
var outputFilename = arg + ".csv"
var c = make(chan os.Signal, 1)

	
type three_tuple struct {
    scrIP uint32
    dstIP uint32
    srcPort uint16
    dstPort uint16
}

func main() {
	
	if len(os.Args) != 2 {
		fmt.Println("USAGE: sudo ./tls <output file>")
		return
	}

	flag.String("config", "tls.toml", "Configuration for TLS extractor")
	cores := flag.String("cores", "0-15", "Specify CPU cores to use")
	noscheduler := flag.Bool("no-scheduler", false, "disable scheduler")
	dpdkLogLevel := flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL")
	debugtime := flag.Uint("debugtime", 5000, "Time in miliseconds for scheduler to display statistics.")
	flag.Parse()
	conf := config.GetConfig()
	//fmt.Println("Config File Loaded")

	var err error
	// Set up reaction to SIGINT (Ctrl-C)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Init NFF-GO system
	nffgoconfig := flow.Config{
		CPUList:          *cores,
		DPDKArgs:         []string{*dpdkLogLevel},
		DisableScheduler: *noscheduler,
		DebugTime:        *debugtime,
	}
	flow.CheckFatal(flow.SystemInit(&nffgoconfig))

	// Get packets from the configured DPDK interface
	//inboundTrafficFlow, err := flow.SetReceiver(conf.Ports.InboundInterface)
	//flow.CheckFatal(err)

	// Only interested in outbound traffic for this research
	outboundTrafficFlow, err := flow.SetReceiver(conf.Ports.OutboundInterface)
	flow.CheckFatal(err)

	//flow.CheckFatal(flow.SetVectorHandler(inboundTrafficFlow, packetHandler, nil))
	flow.CheckFatal(flow.SetVectorHandler(outboundTrafficFlow, packetHandler, nil))

	//flow.CheckFatal(flow.SetStopper(inboundTrafficFlow))
	flow.CheckFatal(flow.SetStopper(outboundTrafficFlow))

	// Start flow scheduler
	go func() {
		flow.CheckFatal(flow.SystemStart())
	}()

	// Wait for interrupt
	sig := <-c

	// Used for timing arrival rate of packets. Can be commented out if not needed.
	endOfCapture := time.Now().UnixNano()
	captureDurationMs := (endOfCapture - startOfCapture)/int64(math.Pow10(3))
	HttpAvgArrivalRate := captureDurationMs / int64(HttpPacketCount - NonFirstPacketCount)
	fmt.Println("Avg Arrival Rate: " + strconv.FormatInt(HttpAvgArrivalRate, 10) + " us for ",
									 strconv.Itoa(HttpPacketCount) + " first HTTP packtets" )
	
	// Generating content for summary file outlining how the packets seen in the hour of capture
	summary := "Total TLS," + strconv.Itoa(TlsPacketCount) + "\n"
	summary += "Total HTTP," + strconv.Itoa(HttpPacketCount) + "\n"
	summary += "Non-First Packets," + strconv.Itoa(NonFirstPacketCount) + "\n" 
	summary += "No User Agents," + strconv.Itoa(NoUserAgentCount) + "\n" 
	summary += "User Agent Packets," + strconv.Itoa(UserAgentCount) + "\n"

    f, err := os.Create(outputFilename)
    if err != nil {
        fmt.Println(err)
        return
    }
    _, err = f.WriteString(summary)
    if err != nil {
        fmt.Println(err)
        f.Close()
        return
    }
    f.Close()
    _ = sig
}


func packetHandler(packetSlice []*packet.Packet, mask *[burstSize]bool, ctx flow.UserContext) {
	current := time.Now().UnixNano()
	elapsed := current - startOfCapture
	elapsed = elapsed/int64(math.Pow10(9))
	
	if(elapsed > int64(3600)) { // Terminate the traffic capture after an hour
		syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	}

	for i := uint(0); i < burstSize; i++ {
		if (*mask)[i] == true {
			cur := packetSlice[i]
			cur.ParseL3()
			l3header := cur.GetIPv4NoCheck()
			protocol := l3header.NextProtoID
			cur.ParseL4ForIPv4()

			switch protocol {
			case tcp:
//				_ = cur.GetTCPNoCheck()
				l4header := cur.GetTCPNoCheck()

//				l4header := cur.GetTCPForIPv4()
				srcAddr := packet.SwapBytesUint32(uint32(l3header.SrcAddr))

//				clientIP := packet.SwapBytesIPv4Addr(types.IPv4Address(clientIP));
				dstAddress := packet.SwapBytesUint32(uint32(l3header.DstAddr))
				sPort := packet.SwapBytesUint16(l4header.SrcPort)
				dPort := packet.SwapBytesUint16(l4header.DstPort)
//				packetLen := packet.SwapBytesUint16(l3header.TotalLength)
				l4Payload, _ := cur.GetPacketPayload()


				// This map can be used for organising flows by IP in real-time.
				// IP := l3header.SrcAddr
				// m[IP] = add(ua, IP)

				current := time.Now().UnixNano()
				elapsed := current - timerStart
				elapsed = elapsed/int64(math.Pow10(9))
				// Every minute, remove expired flows stored in map
				if(elapsed > int64(60)) {
					//fmt.Printf("Checking outdated flows...\n")
					removeExpiredFlows()
					//print()
					timerStart = time.Now().UnixNano()
				}

				key := three_tuple{srcAddr,dstAddress,sPort, dPort}
				now := time.Now()
				timestamp := now.UnixNano()


				switch dPort {

				 // case tls:

				 // 	if len(l4Payload) > 6 {

				 // 		keyInMap := isKeyInMap(key)
				 // 		if !keyInMap {
				 // 			TlsPacketCount++
				 // 			success, cs, _ := parseTcpPayloadForTls(&l4Payload)
				 // 			if success {
				 // 				fmt.Printf("TLS,%s,%s,", now.Format("15:04:05.999999"), l3header.SrcAddr)
				 // 				for i:= 0; i < len(cs); i += 2 {
				 // 					if i == 0 {
				 // 						fmt.Printf("%x", cs[i:i+2])
				 // 					} else {
				 // 						fmt.Printf(" %x", cs[i:i+2])
				 // 					}
				 // 				}
				 // 				fmt.Println()
				 // 				mapPacketToFlow(key, timestamp)
				 // 			}
				 // 		}
				 // 	}

				case http:
					success, ua, _,_,_ := parseTcpPayloadForHttp(&l4Payload)

					keyInMap := isKeyInMap(key)

					switch success {
					case 0:
						if keyInMap {
							TcpPacketCount++
							mapPacketToFlow(key, timestamp)
						}
						break
					case 1:
						if keyInMap{
							TcpPacketCount++
							HttpPacketCount++
							NonFirstPacketCount++
							mapPacketToFlow(key, timestamp)
						}
						break
					case 2:
						TcpPacketCount++
						HttpPacketCount++
						if keyInMap {
							NonFirstPacketCount++
						} else {
							NoUserAgentCount++
						}
						mapPacketToFlow(key, timestamp)
						break
					case 3:
						TcpPacketCount++
						HttpPacketCount++
						if keyInMap {
							NonFirstPacketCount++
						} else {
							UserAgentCount++
							ua = strings.ReplaceAll(ua, ",", ";")
							fmt.Printf("HTTP,%s,%s,%s\n", now.Format("15:04:05.999999"), l3header.SrcAddr, ua)
						}
						mapPacketToFlow(key, timestamp)

					}
				}
			}
		}
	}
}

func add(ua string, IP types.IPv4Address)(map[string]bool){
    
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
		fmt.Println(IP)
		for ua := range m[IP]{
			fmt.Printf("\t%s\n", ua)
		}
	}

}

func mapPacketToFlow(key three_tuple, timestamp int64) bool {

	if isKeyInMap(key) { // If key is present in map
    	flows[key] = timestamp // Update the timestamp
		return false // Return false to say 'No' to logging the packet
	} else {
		flows[key] = timestamp // Add to map with timestamp
		return true // Return true to say 'Yes' to logging the packet
	}

}

func isKeyInMap(key three_tuple) bool {
	if _,ok := flows[key]; ok {
		return true
	} else {
		return false
	}
}

func removeExpiredFlows(){
	flowsDeleted := 0
	current := time.Now().UnixNano()
	for flow,timestamp := range flows {
		elapsed := current - timestamp
		elapsed = elapsed/int64(math.Pow10(9))
		if(elapsed > int64(120)) {
			delete(flows, flow)
			flowsDeleted = flowsDeleted + 1
		}
	}
	//fmt.Printf("Flow Deleted: %d\n", flowsDeleted)
}

