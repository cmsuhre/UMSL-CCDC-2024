#!/bin/bash

#This script will ist current users on linux systems


echo " Current users"
echo ""
awk -F: '{ print $1}' /etc/passwd
echo ""
