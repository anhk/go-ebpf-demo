package main

import (
	"fmt"
	"go_ebpf_demo/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ebpf/perf.c -- -I ../inc

func main() {
	utils.Must(rlimit.RemoveMemlock())

	var objs = ebpfObjects{}
	utils.Must(loadEbpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/"},
	}))
	defer objs.Close()

	k, err := link.Kprobe("sys_execve", objs.ebpfPrograms.BpfProg, nil)
	utils.Must(err)
	defer k.Close()

	go func() {
		r, err := perf.NewReader(objs.Events, 4096)
		utils.Must(err)

		for {
			record, err := r.Read()
			utils.Must(err)
			fmt.Println(record.RawSample)
		}
	}()

	utils.TraceEBPF()
}
