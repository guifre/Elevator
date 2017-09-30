# Escalator [![Build Status](https://travis-ci.org/guifre/escalator.svg?branch=master)](https://travis-ci.org/guifre/escalator.svg?branch=master) [![Coverage Status](https://coveralls.io/repos/github/guifre/escalator/badge.svg?branch=master)](https://coveralls.io/github/guifre/escalator?branch=master)

Escalator automates elevation of privileges in Linux systems. It fingerprints the operating system version, downloads, compiles, and executes the relevant exploits from `exploit-db`.

## Getting Started


```
wget escalator; ./escalator
```

## WARNING
Executing this script will potentially download and run hundreds of exploits, which can cause permanent damage to the operating system.

This script is intended to facilitate EoP in OSCP like labs, do not run this anywhere else other than VMs that can be easily reset.