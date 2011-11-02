#!/bin/sh
EMAIL_TO=email@somehost.tst
INCIDENTS_PATH=/root/incidents

cat $INCIDENTS_PATH/$1.incident|mail -s 'Incident Alert Incident ID #:'$1 $EMAIL_TO
