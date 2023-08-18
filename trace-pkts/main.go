package main

import (
	"go_ebpf_demo/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 ebpf ebpf/trace-pkts.c -- -I ../inc

type AttachMap struct {
	symbol string
	prog   *ebpf.Program
}

type Object struct {
	objs ebpfObjects
}

func (o *Object) Load() *Object {
	utils.Must(loadEbpfObjects(&o.objs, &ebpf.CollectionOptions{}))
	return o
}

func (o *Object) AttachKprobe(m *AttachMap) {
	_, err := link.Kprobe(m.symbol, m.prog, nil)
	utils.Must(err)
}

func main() {
	utils.Must(rlimit.RemoveMemlock())
	utils.Must(utils.MountBPF())

	objs := (&Object{}).Load()

	attachMap := []AttachMap{
		{"__netif_receive_skb", objs.objs.K__netifReceiveSkb},
	}

	for _, m := range attachMap {
		objs.AttachKprobe(&m)
	}

	go utils.TraceEBPF()

	utils.WaitInterrupt()
}
