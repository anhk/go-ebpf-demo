package main

import (
	"go_ebpf_demo/log"
	"go_ebpf_demo/utils"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	helper "github.com/florianl/go-tc/core"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ebpf/tc-slb.c -- -I ../inc

const (
	ifName = "enp0s1"
)

type Object struct {
	objs  ebpfObjects
	iface *net.Interface

	tcnl *tc.Tc

	qdisc   *tc.Object
	ingress *tc.Object
	egress  *tc.Object
}

func (o *Object) Load() *Object {
	os.Mkdir("/sys/fs/bpf/tc-slb", 0755)
	utils.Must(loadEbpfObjects(&o.objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/tc-slb"},
	}))
	return o
}

func (o *Object) Close() {
	utils.Must(o.tcnl.Filter().Delete(o.ingress))
	// tc qdisc del dev enp0s1 clsact
	utils.Must(o.tcnl.Qdisc().Delete(o.qdisc))
	utils.Must(o.tcnl.Close())
}

func (o *Object) openTc() { // tc
	tcnl, err := tc.Open(&tc.Config{})
	utils.Must(err)
	// For enhanced error messages from the kernel
	utils.Must(tcnl.SetOption(netlink.ExtendedAcknowledge, true))
	o.tcnl = tcnl

	objs, err := tcnl.Qdisc().Get()
	utils.Must(err)
	for _, obj := range objs {
		// log.Infof("kind: %v", obj.Attribute.Kind)
		if obj.Attribute.Kind == "clsact" {
			o.qdisc = &obj
			return
		}
	}

	// qdisc for ingress
	o.qdisc = &tc.Object{Msg: tc.Msg{
		Family:  unix.AF_UNSPEC,
		Ifindex: uint32(o.iface.Index),
		Handle:  helper.BuildHandle(0xFFFF, 0x0000),
		Parent:  tc.HandleIngress,
	}, Attribute: tc.Attribute{Kind: "clsact"}}
	utils.Must(o.tcnl.Qdisc().Add(o.qdisc))
}

func (o *Object) attachTcIngress() {
	// open TC
	if o.tcnl == nil {
		o.openTc()
	}

	// filter for ingress
	info, _ := o.objs.TcProcess.Info()
	o.ingress = &tc.Object{Msg: tc.Msg{
		Family:  unix.AF_UNSPEC,
		Ifindex: uint32(o.iface.Index),
		Handle:  0,
		Parent:  helper.BuildHandle(0xffff, tc.HandleMinIngress),

		// Priority = Info&0xFFFF0000 ==> Perf
		// Protocol = Info&0x0000FFFF ==> #define ETH_P_ALL 0x0003
		Info: 0x10300,
	}, Attribute: tc.Attribute{Kind: "bpf", BPF: &tc.Bpf{
		FD:    utils.Pointer(uint32(o.objs.TcProcess.FD())),
		Name:  utils.Pointer(info.Name),
		Flags: utils.Pointer(uint32(0x1)),
	}}}
	utils.Must(o.tcnl.Filter().Add(o.ingress))
}

func (o *Object) attachTcEgress() {
	// open TC
	if o.tcnl == nil {
		o.openTc()
	}

	// filter for egress
	info, _ := o.objs.TcEgress.Info()
	o.egress = &tc.Object{Msg: tc.Msg{
		Family:  unix.AF_UNSPEC,
		Ifindex: uint32(o.iface.Index),
		Handle:  0,
		Parent:  helper.BuildHandle(0xffff, tc.HandleMinEgress),
		Info:    0x10300,
	}, Attribute: tc.Attribute{Kind: "bpf", BPF: &tc.Bpf{
		FD:    utils.Pointer(uint32(o.objs.TcEgress.FD())),
		Name:  utils.Pointer(info.Name),
		Flags: utils.Pointer(uint32(0x1)),
	}}}
	utils.Must(o.tcnl.Filter().Add(o.egress))
}

func main() {

	utils.Must(rlimit.RemoveMemlock())
	utils.Must(utils.MountBPF())

	iface, err := net.InterfaceByName(ifName)
	utils.Must(err)

	log.Infof("interface: %v", ifName)
	log.Infof("device Id: %v", iface.Index)

	o := (&Object{iface: iface}).Load()
	o.attachTcIngress()
	o.attachTcEgress()

	defer func() { o.Close() }()

	go utils.TraceEBPF()

	utils.WaitInterrupt()
}
