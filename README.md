# Elevator
[![Build Status](https://travis-ci.org/guifre/Elevator.svg?branch=master)](https://travis-ci.org/guifre/Elevator.svg?branch=master) [![Coverage Status](https://coveralls.io/repos/github/guifre/Elevator/badge.svg?branch=master)](https://coveralls.io/github/guifre/Elevator?branch=master)

Elevator automates elevation of privileges in Linux systems. It fingerprints the operating system version, downloads, compiles, and executes the relevant exploits from `exploit-db.com`

## Usage

```
wget --no-check-certificate https://raw.githubusercontent.com/guifre/Elevator/master/elevator.py; chmod +x elevator.py; ./elevator.py
```

## Demo

[![Elevator demo](https://github.com/guifre/guifre.github.io/blob/master/elevator.gif)](https://www.youtube.com/watch?v=VCQ7dNVktjs)


## WARNING
Running Escalator will potentially run hundreds of exploits, which can permanently damage your operating system.

Escalator is intended to facilitate EoP in OSCP like labs, where VMs can be easily reset. Use it at your own risk.

## Bugs & Contact
Feel free to mail me with any problem, suggestion or bug report at: me@guif.re

## License
Code licensed under the GPL v3.0.