package main

import (
	"go_ebpf_demo/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 ebpf ebpf/trace-pkts.c -- -I ../inc

type KProbeMap struct {
	symbol string
	prog   *ebpf.Program
}

type TracepointMap struct {
	group string
	name  string
	prog  *ebpf.Program
}

type Object struct {
	objs ebpfObjects
}

func (o *Object) Load() *Object {
	utils.Must(loadEbpfObjects(&o.objs, &ebpf.CollectionOptions{}))
	return o
}

func (o *Object) AttachKprobe(m *KProbeMap) {
	_, err := link.Kprobe(m.symbol, m.prog, nil)
	utils.Must(err)
}

func (o *Object) AttachTracepoint(t *TracepointMap) {
	_, err := link.Tracepoint(t.group, t.name, t.prog, nil)
	utils.Must(err)
}

func main() {
	utils.Must(rlimit.RemoveMemlock())
	utils.Must(utils.MountBPF())

	o := (&Object{}).Load()

	kprobeMap := []KProbeMap{
		{"__netif_receive_skb", o.objs.K__netifReceiveSkb},
		{"netif_receive_skb_core", o.objs.K_netifReceiveSkbCore},
		{"__netif_receive_skb_one_core", o.objs.K__netifReceiveSkbOneCore},
		{"ip_rcv_core", o.objs.K_ipRcvCore},
		{"ip_rcv_finish", o.objs.K_ipRcvFinish},
		{"ip_forward", o.objs.K_ipForward},
		{"ip_forward_finish", o.objs.K_ipForwardFinish},
		{"tcp_v4_do_rcv", o.objs.K_tcpV4DoRcv},
		{"tcp_filter", o.objs.K_tcpFilter},
	}

	tracepointMap := []TracepointMap{
		{"net", "netif_receive_skb", o.objs.T_netifReceiveSkb},
	}

	for _, m := range kprobeMap {
		o.AttachKprobe(&m)
	}

	for _, t := range tracepointMap {
		o.AttachTracepoint(&t)
	}

	go utils.TraceEBPF()

	utils.WaitInterrupt()
}
