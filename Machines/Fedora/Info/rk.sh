#!/bin/bash

#This script sets up rkhunter after uninstall

#scan entire system, run as root
rkhunter --check

#LOGS FOUND IN: 
#/var/log/rkhunter.log
