# RustyDolphin

time spent making this nonsense in the best language ever made:

[![wakatime](https://wakatime.com/badge/user/8b4f0bdc-5133-4fba-98d4-d75498fa71f2/project/73bc670d-dbbf-467b-af69-086d56b73c16.svg)](https://wakatime.com/badge/user/8b4f0bdc-5133-4fba-98d4-d75498fa71f2/project/73bc670d-dbbf-467b-af69-086d56b73c16)
 
 [IP Location Finder by KeyCDN](https://tools.keycdn.com/geo)

 https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

- [ ] use c strings instead of std strings
- [ ] figure out stuff for MAC Addresses (manufacturers and stuff)
- [ ] remove the define warnings and deal with the consequences
- [ ] maybe make a base class for all type of parsers to make stuff simple
- [ ] ifdef debug tostrings and jsonifys and make them const?
- [ ] pass refrences to strings?
- [ ] improve parsing like the general parser
- [ ] add broadcast instead of all "f"s (maybe also loopback and stuff)
- [ ] switch to unique pointers for packets?
- [ ] expand IPV4 Options
- [ ] expand TCPOptions
- [ ] wrap experimental stuff with try catch to prevent crashing later
- [ ] make parseipv4 and parseipv6 use parse
- [ ] better format ipv6 addresses
- [ ] more tcp options
- [ ] add a function to detect eth padding for packets?
- [ ] add dns, mdns, quic, ssdp, BROWSER?, nbns, tls
- [ ] add more icmpv6 message types and codes (https://en.wikipedia.org/wiki/ICMPv6#Message_processing)
- [ ] take care of loopback packets?

file dialog: https://github.com/aiekick/ImGuiFileDialog

hardware types in arp: https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml

Filtering:
Each packet has a flag 1 passed filter 2 failed filter 0 unchecked. Second flag is somewhere else indicating a need to refilter. Upon refiltering, the string filter is converted to a a dict, which defaults of all options.
- For each packet:
- If there is no filter (""), render it.
- If there is a filter and the packrt flag is 0, check and mark it accordingly and render accordingly
- If the flag isn't 0 and filter flag isn't on, render according to flag,
- If filter flag is on, assume flag is 0 and filter it and mark it
- Mark filter flag as unchanged (off)

General flow:

- Init everything and caches
- Run sanity checks
- Fetch all adapters (maybe run some sort of check)
- Create render thread (maybe main?)
- Create a thread for each adapter to count packets and create rate
- Start rendering and present the rate
- Upon adapter selection, join threads and create another thread specifically for the chosen adapter
- Render the recieved packets which are picked up and analyzed by the thread
- Each packet is rendered according to the filrering
- On click, the packet will present in a small window
- On second one it will open in another window
- In both of these cases, buttons will be presented to do further actions (such as geo track)


possible protocol Values:
- ICMP (Internet Control Message Protocol): 1
- TCP (Transmission Control Protocol): 6
- UDP (User Datagram Protocol): 17
- IGMP (Internet Group Management Protocol): 2
- OSPF (Open Shortest Path First): 89
- GRE (Generic Routing Encapsulation): 47
- ESP (Encapsulating Security Payload): 50
- AH (Authentication Header): 51

Some common EtherType values include:

- IPv4: 0x0800
- ARP: 0x0806
- Wake-on-LAN: 0x0842
- VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq: 0x8100
- IPv6: 0x86DD
- MPLS unicast: 0x8847
- MPLS multicast: 0x8848
