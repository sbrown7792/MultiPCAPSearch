# MultiPCAPSearch
Searches multiple PCAPs

1) Load one or more PCAPs. Give each a "friendly name". 
2) Click add filter, also give it a friendly name. Provide filter text.
3) Click "Search Now" and wait. 

Each PCAP will have each filter applied to it, and the resulting number of packets are displayed in the cell. If you have more than one PCAP/filter (which of course you do, why else would you use this tool?) the searches are parallelized, one for each core you have on your PC.
Also, the PCAP/filter combo is hashed and the filter results are stored in the hash table, so "Search Now" will only actually filter if you change the PCAP or filter text. Otherwise it just returns the cached answer.

It's not pretty, but it works. At least on my machine :)

Built with Qt Creator 4.14.2. 


## Why?
Imagine you're a network engineer and trying to follow the flow of traffic across many devices. You have multiple PCAPs from SPAN/RSPAN/ERSPAN sessions at each hop, and you want to see where drops are occurring. Let's say some hops encrypt the traffic within GRE or ESP, so you'll need a different filter to identify the target traffic in those captures vs the plaintext captures. 

Load up all your PCAPs here, make two filters: one for the plaintext source/dest IPs and the second for the tunnel source/dest IPs, and then it's easy to see how many packets in each PCAP match those filters. No need to open 10 copies of Wireshark and worrying about synching your display filters across all instances, then recording each resulting "Displayed" packet count.  
