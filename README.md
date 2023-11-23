# Simple-Packet-Analyzer
 
 ## Usage
 ```
 # Analyze packets from a saved file.
 ./SPA.exe -r file_path -n n_packets -f filter

 # Perform online packet analysis.
 # When using the 'c' flag, all available devices will be listed, allowing you 
 # to select the network interface from this list.
 ./SPA.exe -c -n n_packets -f filter -s save_path
 ```