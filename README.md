# Netwink

> I wrote this for computer network course.

## Intro

|files|description|
| ---- | ---- |
|input.h/c| handel user input|
|netwink.h/c|  main sniffer loop and filter configure|
|dbg.h| macro define for debug|

## Build

```shell
make
sudo make install
```

## Usage

```shell
netwink [-f] [interface name] //restrict interface
        [-p] [port]//restrict port
        [-i] [IP address]// restrict IP
        [-t] [protocol name]//TCP/UDP/ICMP
        [-s] [out.txt] //save to file
        [-v] //check version
        [-h] //help
```

## License

```
        DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
                    Version 2, December 2004 

 Copyright (c) 2017 LeeReindeer <reindeerlee.work@gmail.com> 

 Everyone is permitted to copy and distribute verbatim or modified 
 copies of this license document, and changing it is allowed as long 
 as the name is changed. 

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION 

  0. You just DO WHAT THE FUCK YOU WANT TO.
```
