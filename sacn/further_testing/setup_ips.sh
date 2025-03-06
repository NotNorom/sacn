#!/bin/zsh

export INTERFACE=$1;

ip addr add dev $INTERFACE 192.168.0.6/32
ip addr add dev $INTERFACE 192.168.0.7/32
ip addr add dev $INTERFACE 192.168.0.8/32

ip addr add dev $INTERFACE 2a02:c7f:d20a:c600:a502:2dae:7716:601b
ip addr add dev $INTERFACE 2a02:c7f:d20a:c600:a502:2dae:7716:601c
ip addr add dev $INTERFACE 2a02:c7f:d20a:c600:a502:2dae:7716:601d
