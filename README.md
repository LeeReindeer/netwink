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
MIT License

Copyright (c) 2017 LeeReindeer

**Don't use the code unless you understand the license.**

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```