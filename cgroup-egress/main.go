package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ebpf/cgroup-egress.c -- -I ../inc

func main() {

}
