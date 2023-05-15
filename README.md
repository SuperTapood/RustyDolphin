# RustyDolphin

time spent making this nonsense in the best language ever made:

[![wakatime](https://wakatime.com/badge/user/8b4f0bdc-5133-4fba-98d4-d75498fa71f2/project/73bc670d-dbbf-467b-af69-086d56b73c16.svg)](https://wakatime.com/badge/user/8b4f0bdc-5133-4fba-98d4-d75498fa71f2/project/73bc670d-dbbf-467b-af69-086d56b73c16)
 
 [IP Location Finder by KeyCDN](https://tools.keycdn.com/geo)

 to do:
 - include curl in the project!
 - expand TCPOptions
 - make parseipv4 and parseipv6 use parse
 - more tcp options
 - arp poisnoning
 - TCP, UDP, ICMP, ICMPV6 expanded rendering
 - add more icmpv6 message types and codes (https://en.wikipedia.org/wiki/ICMPv6#Message_processing)
 - add filtering
 - can load files
 - can save files
 - add sanity checks?
 - add geo trace route
 - more arp hard types and opcodes (https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml)


file dialog: https://github.com/aiekick/ImGuiFileDialog

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
- In both of these cases, buttons will be presented to do further actions (such as geo track)