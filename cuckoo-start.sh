#!/bin/bash
# ------------------------------------------------------------------------------------
# Title: SentinelOne - SOAR - Sandbox Integration (cuckoo-start.sh)
# Version: V1.0
# Dev Date: 08-03-2021
# Developed by SentinelOne (www.sentinelone.com)
# Developer: Martin de Jongh
# Developer email: martind@sentinelone.com

#   Copyright 2021, SentinelOne
#   Licensed under the Apache License, Version 2.0 (the "License"); 
#   You may not use this Script except in compliance with the License.
#   You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and limitations under the License.
#
# ------------------------------------------------------------------------------------
# Important:
# Before executing below bash script to startup Cuckoo Sandbox and enable API connector.
# Make certain you have installed and configured both Cuckoo Sandbox and a Virtual client (Win7x86 preffered). 
# 
# Run following bash command as ROOT user to cleanly startup all required Cuckoo Sandbox services './cuckoo-start.sh'
# ------------------------------------------------------------------------------------

killall cuckoo
pkill -f 'cuckoo web runserver'

echo 1 > /proc/sys/net/ipv4/ip_forward

systemctl start mongod

runuser -l sysadmin -c 'cuckoo' &
runuser -l sysadmin -c 'cuckoo web runserver 0.0.0.0:8000' &
runuser -l sysadmin -c 'cuckoo api --host 0.0.0.0 --port 8090' &
