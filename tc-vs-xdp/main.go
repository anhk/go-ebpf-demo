package main

import (
	"go_ebpf_demo/log"
	"go_ebpf_demo/utils"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	helper "github.com/florianl/go-tc/core"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ebpf/tc-vs-xdp.c -- -I ../inc

const (
	ifName = "enp0s1"
)

func main() {
	utils.Must(rlimit.RemoveMemlock())
	utils.Must(utils.MountBPF())

	objs := &ebpfObjects{}
	utils.Must(loadEbpfObjects(objs, &ebpf.CollectionOptions{}))

	iface, err := net.InterfaceByName(ifName)
	utils.Must(err)

	log.Infof("interface: %v", ifName)
	log.Infof("device Id: %v", iface.Index)

	// attach xdp to nic
	xdp, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProcess,
		Interface: iface.Index,
	})
	utils.Must(err)
	defer utils.Must(xdp.Close())

	// tc
	tcnl, err := tc.Open(&tc.Config{})
	utils.Must(err)
	defer func() { utils.Must(tcnl.Close()) }()

	// For enhanced error messages from the kernel
	utils.Must(tcnl.SetOption(netlink.ExtendedAcknowledge, true))

	qdiscs, err := tcnl.Qdisc().Get()
	utils.Must(err)

	for _, qdisc := range qdiscs {
		iface, err := net.InterfaceByIndex(int(qdisc.Ifindex))
		utils.Must(err)
		log.Infof("QDISC for %v", iface.Name)
	}

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  helper.BuildHandle(0xFFFF, 0x0000),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{Kind: "clsact"},
	}
	utils.Must(tcnl.Qdisc().Add(&qdisc))
	defer func() {
		log.Infof("utils.Must(tcnl.Qdisc().Delete(&qdisc))")
		utils.Must(tcnl.Qdisc().Delete(&qdisc))
	}() // tc qdisc del dev enp0s1 clsact

	info, _ := objs.TcProcess.Info()
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  0,
			Parent:  0xfffffff2,
			Info:    0x10300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    utils.Pointer(uint32(objs.TcProcess.FD())),
				Name:  utils.Pointer(info.Name),
				Flags: utils.Pointer(uint32(0x1)),
			},
		},
	}

	utils.Must(tcnl.Filter().Add(&filter))
	defer func() {
		log.Infof("utils.Must(tcnl.Filter().Delete(&filter))")
		utils.Must(tcnl.Filter().Delete(&filter))
	}()

	go utils.TraceEBPF()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
}
