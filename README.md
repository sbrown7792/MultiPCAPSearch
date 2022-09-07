# MultiPCAPSearch
Searches multiple PCAPs

1) Load one or more PCAPs. Give each a "friendly name". 
2) Click add filter, also give it a friendly name. Provide filter text.
3) Click "Search Now" and wait. 

Each PCAP will have each filter applied to it, and the resulting number of packets are displayed in the cell. If you have more than one PCAP/filter (which of course you do, why else would you use this tool?) the searches are parallelized, one for each core you have on your PC.

It's not pretty, but it works. At least on my machine :)

Built with Qt Creator 4.14.2. 
