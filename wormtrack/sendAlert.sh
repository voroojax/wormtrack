#!/bin/sh
cat /root/incidents/$1.incident|mail -s 'Incident Alert Incident ID #:'$1 somee-mail@test.tst
