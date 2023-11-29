package main

import (
	"go_ebpf_demo/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --target bpfel ebpf ebpf/ebpf.c -- -I ../inc

func main() {
	utils.Must(rlimit.RemoveMemlock())
	var objs = ebpfObjects{}
	utils.Must(loadEbpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf"},
	}))
	defer objs.Close()

	utils.Must(link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.SockMap.FD(),
		Program: objs.SockMessage,
		Attach:  ebpf.AttachSkMsgVerdict,
	}))

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.SockSetops,
	})
	utils.Must(err)
	defer l.Close()

	go utils.TraceEBPF()
	utils.WaitInterrupt()
}
