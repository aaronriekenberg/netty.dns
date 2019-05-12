#!/bin/sh

pgrep -U $(id -u) java > /dev/null 2>&1
if [ $? -eq 1 ]; then
  cd ~/netty.dns
  ./restart.sh > /dev/null 2>&1
fi
