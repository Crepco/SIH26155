# aug/24/2026 18:41:03 by RouterOS 7.14.3
# software id = ABCD-1234
#
# model = RB4011iGS+
# serial number = HG7081ABCDE
/system identity set name=branch-rtr-01
/interface bridge add name=bridge-users protocol-mode=rstp
/interface ethernet set [ find default-name=ether1 ] comment="wan-uplink"
/interface ethernet set [ find default-name=ether2 ] comment="lan"
/ip address add address=198.51.100.2/24 interface=ether1 network=198.51.100.0
/ip address add address=192.168.20.1/24 interface=bridge-users network=192.168.20.0
/ip service set telnet disabled=no port=23
/ip service set ftp disabled=yes
/ip service set www disabled=no port=80
/ip service set ssh disabled=no port=22
/ip service set www-ssl disabled=yes
/ip service set api disabled=yes
/ip service set winbox disabled=no port=8291
/ip firewall filter add action=accept chain=input comment="allow established" connection-state=established,related
/ip firewall filter add action=accept chain=input dst-port=22 protocol=tcp src-address=192.168.20.0/24
/ip firewall filter add action=drop chain=input comment="drop everything else"
/snmp community add name=public read-access=yes
/snmp set enabled=yes trap-version=2
/system clock set time-zone-name=Asia/Kolkata
/system ntp client set enabled=yes
/system ntp client servers add address=10.0.0.1
/system logging action set 0 remote=10.0.0.5
/user set admin password=hunter2
/user add name=monitor group=read password=readonly123
