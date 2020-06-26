package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

const (
	MIN_HEADER_LENGTH = 10
	START_FIELD       = 0x0564
)

var FCodes = map[byte]string{
	0:   "Confirm",
	1:   "Read",
	2:   "Write",
	3:   "Select",
	4:   "Operate",
	5:   "Direct Operate",
	6:   "Direct Operate No ACK",
	7:   "Immediate Freeze",
	8:   "Immediate Freeze No ACK",
	9:   "Freeze and Clear",
	10:  "Freeze and Clear No ACK",
	11:  "Freeze With Time",
	12:  "Freeze With Time No ACK",
	13:  "Cold Restart",
	14:  "Warm Restart",
	15:  "Initialize Data",
	16:  "Initialize Application",
	17:  "Start Application",
	18:  "Stop Application",
	19:  "Save Configuration",
	20:  "Enable Spontaneous Msg",
	21:  "Disable Spontaneous Msg",
	22:  "Assign Classes",
	23:  "Delay Measurement",
	24:  "Record Current Time",
	25:  "Open File",
	26:  "Close File",
	27:  "Delete File",
	28:  "Get File Info",
	29:  "Authenticate File",
	30:  "Abort File",
	31:  "Activate Config",
	32:  "Authentication Request",
	33:  "Authentication Error",
	129: "Response",
	130: "Unsolicited Response",
	131: "Authentication Response",
}

// "-" Reserved or Obsolete
var PfCodes = map[byte]string{
	0:  "Reset of Remote Link", // 0x10
	1:  "Reset of User Process",
	2:  "Test Function For Link", // 0x12
	3:  "User Data",              // 0x13
	4:  "Unconfirmed User Data",  // 0x14
	5:  "-",
	6:  "-",
	7:  "-",
	8:  "-",
	9:  "Request Link Status", // 0x19
	10: "-",
	11: "-",
	12: "-",
	13: "-",
	14: "-",
	15: "-",
}

var SfCodes = map[byte]string{
	0:  "ACK", // 0x00
	1:  "NAK", // 0x01
	2:  "-",
	3:  "-",
	4:  "-",
	5:  "-",
	6:  "-",
	7:  "-",
	8:  "-",
	9:  "-",
	10: "-",
	11: "Status of Link", // 0x0B
	12: "-",
	13: "-",
	14: "Link Service Not Functioning",
	15: "Link Service Not Used or Implemented", // 0x0F
}

/***************************************************************************/
/* Application Layer Internal Indication (IIN) bits */
/* 2 Bytes, message formatting: [First Octet] | [Second Octet] */
/***************************************************************************/
var IINCodes = map[string]string{
	/* Octet 1 */
	"0x0100": "Broadcast message rx'd",
	"0x0200": "Class 1 Data Available",
	"0x0400": "Class 2 Data Available",
	"0x0800": "Class 3 Data Available",
	"0x1000": "Time Sync Req'd from Master",
	"0x2000": "Outputs in Local Mode",
	"0x4000": "Device Trouble",
	"0x8000": "Device Restart",

	/* Octet 2 */
	"0x0001": "Function code not implemented",
	"0x0002": "Requested Objects Unknown",
	"0x0004": "Parameters Invalid or Out of Range",
	"0x0008": "Event Buffer Overflow",
	"0x0010": "Operation Already Executing",
	"0x0020": "Device Configuration Corrupt",
	"0x0040": "Reserved",
	"0x0080": "Reserved",
}

/***************************************************************************/
/* Application Layer Object Prefix codes bits */
/***************************************************************************/
var ObjPrefixCodes = map[byte]string{
	0: "Objects packed without a prefix",
	1: "Objects prefixed with 1-octet index",
	2: "Objects prefixed with 2-octet index",
	3: "Objects prefixed with 4-octet index",
	4: "Objects prefixed with 1-octet object size",
	5: "Objects prefixed with 2-octet object size",
	6: "Objects prefixed with 4-octet object size",
	7: "Reserved",
}

/***************************************************************************/
/* Application Layer Object Prefix codes bits */
/***************************************************************************/
var ObjRangeSpecifierCodes = map[byte]string{
	0:  "8-bit Start and Stop Indices in Range Field",
	1:  "16-bit Start and Stop Indices in Range Field",
	2:  "32-bit Start and Stop Indices in Range Field",
	3:  "8-bit Absolute Address in Range Field",
	4:  "16-bit Absolute Address in Range Field",
	5:  "32-bit Absolute Address in Range Field",
	6:  "Length of Range field is 0 (no range field)",
	7:  "8-bit Single Field Quantity",
	8:  "16-bit Single Field Quantity",
	9:  "32-bit Single Field Quantity",
	10: "Reserved",
	11: "Free-format Qualifier, range field has 1 octet count of objects",
	12: "Reserved",
	13: "Reserved",
	14: "Reserved",
	15: "Reserved",
}

type DNP3 struct {
	DataLinkLayer    DataLinkLayer
	TransportLayer   TransportLayer
	ApplicationLayer ApplicationLayer
}

type DataLinkLayer struct {
	Start   string
	Length  int
	Control struct {
		ControlByte string
		IsMaster    int    `json:"Is Master"`
		PRM         int    `json:"Primary"`
		FCB         int    `json:"Frame Count Bit"`
		FCV         int    `json:"Frame Count Valid"`
		FUNC        string `json:"Function Code"`
	}
	Destination int
	Source      int
	CRC         string
}

type TransportLayer struct {
	TransportByte string
	Final         int
	First         int
	Sequence      int
}

type ApplicationLayer struct {
	Control struct {
		ControlByte string
		First       int
		Final       int
		Confirm     int
		Unsolicited int
		Sequence    int
	}
	Function string `json:"Function Code"`
}

func main() {
	pcapFile := flag.String("p", "../dnp3.pcap", "Pcap file path")
	flag.Parse()

	// Open pcap file
	handle, err = pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// For loop for packets in pcap file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		DNP3Decode(packet)
	}
}

// DNP3Decode ...
func DNP3Decode(packet gopacket.Packet) {

	// Display all layers in packet
	// fmt.Println("All packet layers:")
	// for _, layer := range packet.Layers() {
	// 	fmt.Println("- ", layer.LayerType())
	// }

	// var dataStr string
	var dataByte []byte
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {

		fmt.Println("Application layer/Payload found.")

		dataByte = applicationLayer.Payload()
		// dataStr = hex.EncodeToString(applicationLayer.Payload())
		d := &DNP3{}

		d.checkLength(dataByte)
		d.ifDNP3(dataByte[0:2])
		d.setDataLinkLayer(dataByte)
		d.setTransportLayer(dataByte)
		d.setApplicationLayer(dataByte)

		sonuc, _ := json.MarshalIndent(d, "", "  ")
		fmt.Println(string(sonuc))

	}

	// Output: 	000c29243a0a005056c0000808004500003701a840008006ff44c0a83c01c0a83c82c1804e20101a13d667552a13501801002f450000
	// DNP3: 	056408c40a000100fc42c0c00e7edc
	// DNP3:	05640a4401000a006e25c1c0810001c4fd

	// start := hex.EncodeToString(data[0:2])

}

func (d *DNP3) checkLength(data []byte) {
	if len(data) < MIN_HEADER_LENGTH {
		log.Fatal("Invalid packet length")
	}
}

func (d *DNP3) ifDNP3(data []byte) {
	if binary.BigEndian.Uint16(data[0:2]) != START_FIELD {
		log.Fatal("This is not DNP3")
	}
}

func (d *DNP3) setDataLinkLayer(data []byte) {
	start := hex.EncodeToString(data[0:2])
	d.DataLinkLayer.Start = start

	length := int(data[2])
	d.DataLinkLayer.Length = length

	ctlControl := hex.EncodeToString([]byte{data[3]})
	d.DataLinkLayer.Control.ControlByte = ctlControl

	IsMaster := int((data[3] & 0x80) >> 7)
	d.DataLinkLayer.Control.IsMaster = IsMaster

	PRM := int((data[3] & 0x40) >> 6)
	d.DataLinkLayer.Control.PRM = PRM

	FCB := int((data[3] & 0x20) >> 5)
	d.DataLinkLayer.Control.FCB = FCB

	FCV := int((data[3] & 0x10) >> 4)
	d.DataLinkLayer.Control.FCV = FCV

	FUNCCODE := data[3] & 0x0F
	ctlFUNCCODE := fmt.Sprintf("%d", FUNCCODE)

	var ctlFUNC string
	if PRM == 0x00 {
		ctlFUNC = SfCodes[FUNCCODE]
	}

	if PRM == 0x01 {
		ctlFUNC = PfCodes[FUNCCODE]
	}

	ctlFUNC = ctlFUNC + " (" + ctlFUNCCODE + ")"
	d.DataLinkLayer.Control.FUNC = ctlFUNC

	d.DataLinkLayer.Destination = int(binary.LittleEndian.Uint16(data[4:6]))
	d.DataLinkLayer.Source = int(binary.LittleEndian.Uint16(data[6:8]))

	// TODO: Is correct? Hesapla
	crcStr := fmt.Sprintf("0x%04x", binary.LittleEndian.Uint16(data[8:10]))
	d.DataLinkLayer.CRC = crcStr
	// crc16 := crc.CalculateCRC(crc.CRC16, data[0:9])
	// fmt.Printf("CRC is 0x%04x\n", crc16)
}

func (d *DNP3) setTransportLayer(data []byte) {

	transport := fmt.Sprintf("0x%02x", data[10])
	d.TransportLayer.TransportByte = transport

	final := data[10] & 0x80 >> 7
	d.TransportLayer.Final = int(final)

	first := data[10] & 0x40 >> 6
	d.TransportLayer.First = int(first)

	sequence := data[10] & 0x3f // 6bit
	d.TransportLayer.Sequence = int(sequence)

}

func (d *DNP3) setApplicationLayer(data []byte) {
	controlByte := fmt.Sprintf("0x%x", data[11])
	d.ApplicationLayer.Control.ControlByte = controlByte

	first := data[11] & 0x80 >> 7
	d.ApplicationLayer.Control.First = int(first)

	final := data[11] & 0x40 >> 6
	d.ApplicationLayer.Control.Final = int(final)

	confirm := data[11] & 0x20 >> 5
	d.ApplicationLayer.Control.Confirm = int(confirm)

	unsolicited := data[11] & 0x10 >> 4
	d.ApplicationLayer.Control.Unsolicited = int(unsolicited)

	sequence := data[11] & 0x0f
	d.ApplicationLayer.Control.Sequence = int(sequence)

	funcByte := fmt.Sprintf("0x%x", data[12])
	d.ApplicationLayer.Function = FCodes[data[12]] + " (" + funcByte + ")"
}
