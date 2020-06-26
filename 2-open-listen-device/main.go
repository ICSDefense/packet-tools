package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	promiscuous bool = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)

func main() {

	device := flag.String("d", "en0", "Device: en0")
	snapshotLen := flag.Int("s", 1024, "Snapshot Length: 1024")

	flag.Parse()
	//flag.PrintDefaults()

	// Open device
	handle, err = pcap.OpenLive(*device, int32(*snapshotLen), promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		fmt.Println(packet.Data())
	}
}
