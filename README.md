# ms17-010-m4ss-sc4nn3r
MS17-010 multithreading scanner written in python.  
Inspired by [smb_ms17_010](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/smb/smb_ms17_010.rb ) metasploit-framework auxiliary module  
<pre>

                  MS17-010-m4ss-sc4nn3r v1.0

                         Written by:
                       Claudio Viviani

                    http://www.homelab.it

                       info@homelab.it
                   homelabit@protonmail.ch

                 https://twitter.com/homelabit


[+]Usage: ms17-010-m4ss-sc4nn3r.py ip or ip/CIDR or ip/subnet

   Example: ms17-010-m4ss-sc4nn3r.py 192.168.0.1
            ms17-010-m4ss-sc4nn3r.py 192.168.0.0/24
            ms17-010-m4ss-sc4nn3r.py 192.168.0.0/255.255.255.0

</pre>

## Requirements:
- Python 2.7
- ipaddress module

## Features:
<pre>
1) Multithreading
2) Subnet scan
3) CIDR newtrok scan
</pre>

## Windows precompiled version
<pre>
1) No python required
2) No modules requred
3) Tested on x84 and x64 Windows system
</pre>
