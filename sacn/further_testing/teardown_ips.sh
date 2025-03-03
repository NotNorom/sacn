#!/bin/zsh

export INTERFACE=$1;

ip addr del dev $INTERFACE 192.168.0.6/24
ip addr del dev $INTERFACE 192.168.0.7/24
ip addr del dev $INTERFACE 192.168.0.8/24

ip addr del dev $INTERFACE 2a02:c7f:d20a:c600:a502:2dae:7716:601b
ip addr del dev $INTERFACE 2a02:c7f:d20a:c600:a502:2dae:7716:601c
ip addr del dev $INTERFACE 2a02:c7f:d20a:c600:a502:2dae:7716:601d
