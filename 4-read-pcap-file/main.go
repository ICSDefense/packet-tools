package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	handle *pcap.Handle
	err    error
)

func main() {
	pcapFile := flag.String("p", "../modbus.pcap", "Pcap file path")
	flag.Parse()
	//flag.PrintDefaults()

	// Open file instead of device
	handle, err = pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		// fmt.Println(packet.Data())
		fmt.Println(hex.EncodeToString(packet.Data()))
		// start := d.hexConvert(data[0:2])

	}
}
