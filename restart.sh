#!/bin/sh -x

CONFIG_FILE=./$(hostname -s)-config.json
JAVA_OPTS=

pkill -U $(id -u) java

sleep 2

if [ $(hostname) = 'raspberrypi' ]; then
  export PATH="/home/pi/jdk-11.0.3+7/bin/:$PATH"
  JAVA_OPTS="-Xmx64m"
fi

nohup java -Dconfig.file.name=$CONFIG_FILE $JAVA_OPTS -jar build/libs/*.jar 2>&1 | svlogd logs &
