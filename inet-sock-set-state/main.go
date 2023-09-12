package main

import (
	"go_ebpf_demo/utils"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ebpf/setstate.c -- -I ../inc

func main() {
	utils.Must(rlimit.RemoveMemlock())

}
