# PCAPS
PCAP (Packet Capture) is a protocol for wireless Internet communication that allows a computer or device to receive incoming radio signals from another device and convert those signals into usable information.

The Python script reads the pcap files and unpacks them to read network data. It filters data based on the channels and spawns threads to unpack pcap files and writes the data to files. 

### ISSUES FIXED
There are instances where data of same channel are stored across different pcap files; This introduces an issue where the data with a bigger time stamp gets written to the file before the one with relatively smaller time stamp. The script uses thread to open multiple pcap files and store data from channels, sorts them and writes the data with smallest time stamp to the file.

##### The script was written to create an alternate solution for the production issue while I was working at the Geneva Trading USA.
