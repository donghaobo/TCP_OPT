# TCP_OPT
iptables target insert tcp option

# depends
iptables-devel
kernel-devel

# build
make

# install
make install

# usage
iptables -t mangle -I POSTROUTING -d 1.2.3.4/32 -p tcp -m tcp --tcp-flags FIN,SYN,RST NONE -j TCPOPTADD --hex "|aa02bb0300cc040000|"
