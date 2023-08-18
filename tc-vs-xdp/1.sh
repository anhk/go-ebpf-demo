#!/bin/bash
set -e -x

IFNAME=enp0s1

install() {
    tc qdisc add dev $IFNAME clsact
    tc filter add dev $IFNAME ingress bpf da obj ebpf_bpfel.o sec classifier/ingress
    tc filter add dev $IFNAME egress bpf da obj ebpf_bpfel.o sec classifier/egress
}

uninstall() {
    tc qdisc del dev $IFNAME clsact
}

show() {
    echo "----- qdisc -----"
    tc qdisc show dev $IFNAME

    echo "----- filter -----"
    tc filter show dev $IFNAME ingress
    tc filter show dev $IFNAME egress
}

# install && show
# uninstall && show
show