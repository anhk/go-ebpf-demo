package main

import (
	"encoding/binary"
	"fmt"
	"go_ebpf_demo/utils"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdp ebpf/xdp.c -- -I ../inc

type SlbKey struct {
	Vip  uint32 // __u32 vip
	Port uint16 // __u16 port
	Pad1 uint16 // __u16 _pad1
	Slot uint32 // __u32 slot
	Pad2 uint32 // __u32 _pad2
}

type SlbValue struct {
	Count uint32 // __u32 count
	RIP   uint32 // __u32 rip
	Port  uint16 // __u16 port
	Pad1  uint16 // __u16 _pad1
	Pad2  uint32 // __u32 _pad2
}

var (
	vip     = "192.168.64.37:9999"
	ifName  = "enp0s1"
	backend = []string{
		"10.244.47.101:80",
		"10.244.47.102:80",
	}
)

func htons(p uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, p)
	return binary.BigEndian.Uint16(b)
}

// func htonl(p uint32) uint32 {
// 	b := make([]byte, 4)
// 	binary.LittleEndian.PutUint32(b, p)
// 	return binary.BigEndian.Uint32(b)
// }

func main() {
	utils.Must(rlimit.RemoveMemlock())
	utils.Must(utils.MountBPF())

	objs := &xdpObjects{}
	utils.Must(loadXdpObjects(objs, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf"}}))
	defer objs.Close()

	iface, err := net.InterfaceByName(ifName)
	utils.Must(err)

	xdp, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpSlb,
		Interface: iface.Index,
	})
	utils.Must(err)
	defer xdp.Close()

	tcpAddr, err := net.ResolveTCPAddr("tcp", vip)
	utils.Must(err)

	key := &SlbKey{
		Vip:  binary.LittleEndian.Uint32(tcpAddr.IP.To4()),
		Port: htons(uint16(tcpAddr.Port)),
	}

	value := &SlbValue{}

	for i := 0; i < len(backend); i++ {
		key.Slot = uint32(i + 1)

		tcpAddr, err := net.ResolveTCPAddr("tcp", backend[i])
		utils.Must(err)

		value.RIP = binary.LittleEndian.Uint32(tcpAddr.IP.To4())
		value.Port = htons(uint16(tcpAddr.Port))

		fmt.Printf("%x\n", value.RIP)

		utils.Must(objs.xdpMaps.SlbMap.Update(unsafe.Pointer(key), unsafe.Pointer(value), ebpf.UpdateAny))
	}

	// update vip
	key.Slot = 0
	value.Count = uint32(len(backend))
	value.RIP, value.Port = 0, 0
	utils.Must(objs.xdpMaps.SlbMap.Update(unsafe.Pointer(key), unsafe.Pointer(value), ebpf.UpdateAny))

	fmt.Println("----")
	iter := objs.xdpMaps.SlbMap.Iterate()
	for iter.Next(key, value) {
		fmt.Printf("%v %x:%x -> %x:%x %v\n", key.Slot, key.Vip, key.Port, value.RIP, value.Port, value.Count)
	}

	fmt.Println("===")
	utils.TraceEBPF()
}
