# report_ip_stat
## Installation
```
sudo apt install libpcap-dev
```
## Usage
```
cmake .
make
./report_ip_stat <pcap file path>
```
* The program was tested on Ubuntu 20.10.
## Output
```
175.213.35.39 (total 1255 bytes)
 received 6 ip packets (546 bytes)
 sent 4 ip packets (709 bytes)

10.2.2.3 (total 1571 bytes)
 received 6 ip packets (875 bytes)
 sent 8 ip packets (696 bytes)

10.2.2.1 (total 316 bytes)
 received 2 ip packets (150 bytes)
 sent 2 ip packets (166 bytes)

88:c3:97:c7:1b:5 (total 1571 bytes)
 received 8 ethernet packets (696 bytes)
 sent 6 ethernet packets (875 bytes)

b4:2e:99:ea:97:de (total 1571 bytes)
 received 6 ethernet packets (875 bytes)
 sent 8 ethernet packets (696 bytes)
```