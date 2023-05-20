# RustyDolphin

time spent making this nonsense in the best language ever made:

[![wakatime](https://wakatime.com/badge/user/8b4f0bdc-5133-4fba-98d4-d75498fa71f2/project/73bc670d-dbbf-467b-af69-086d56b73c16.svg)](https://wakatime.com/badge/user/8b4f0bdc-5133-4fba-98d4-d75498fa71f2/project/73bc670d-dbbf-467b-af69-086d56b73c16)
 
 [IP Location Finder by KeyCDN](https://tools.keycdn.com/geo)

 to do:
 - add geo trace route
 - more arp hard types and opcodes (https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml)
 - arp poisnoning

General flow:

- Init everything and caches
- Fetch all adapters (maybe run some sort of check)
- Create render thread (main)
- Create a thread for each adapter to count packets and create rate
- Start rendering and present the rate
- Upon adapter selection, join threads and create another thread specifically for the chosen adapter
- Render the recieved packets which are picked up and analyzed by the thread
- Each packet is rendered according to the filtering
- On click, the packet will present in a small window
- In both of these cases, buttons will be presented to do further actions (such as geo track)