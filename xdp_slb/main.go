package main

import (
	"go_ebpf_demo/utils"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdp ebpf/xdp.c -- -I ../inc

func main() {
	utils.Must(rlimit.RemoveMemlock())

	objs := &xdpObjects{}
	utils.Must(loadXdpObjects(objs, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf"}}))
	defer objs.Close()

	iface, err := net.InterfaceByName("enp0s1")
	utils.Must(err)

	xdp, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpSlb,
		Interface: iface.Index,
	})
	utils.Must(err)
	defer xdp.Close()

	utils.TraceEBPF()
}
