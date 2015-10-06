WormTrack's ability to detect network scanning partially depends on having insight into which machines legitimately communicate with which other machines on the same network. In theory, it is not too complicated to define that, however in practice especially in Windows environment it becomes significantly more complex. On network with Windows machines, even if the hosts don't explicitly communicate between each other, due to number of auto-discovery functions enabled by default, ARP requests will be send between those machines. There a number of work arounds, one can employ to reduce the false positives.
  1. Add all windows machine's to each other peer list. The down side of this solution is it reduces the ability to detect worms, that is increases false negatives.
  1. Disable  windows auto discovery, in most cases the auto discovery is completely useless on the network, and in some cases dangerous since it opens ports for communication, and there were a number of vulnerabilities associated with those services
    1. Disabling windows NetBios discovery: go to properties of a particular Network Interface (Device), then to properties of “Internet Protocol Version 4 (TCP/IPv4)”, then click on “Advanced” button and then go to “WINS” Tab. In NetBIOS settings one can either disable it, or set it to be enabled or disabled based on flag in DHCP reply.
    1. Another service you might want to disable is “Function Discovery ...” find those services in “Services” and disable all which start with those two words.
    1. If one has Groove installed,you can disable that too, or its auto-discovery functionality.

If you using standard ISC DHCP adding the following to the top of the configuration file would disable NetBIOS TCP on windows
```

set vendor-id = option vendor-class-identifier;
option space MSFT;
option MSFT.nbt code 1 = unsigned integer 32;
option MSFT.release-on-shutdown code 2 = unsigned integer 32;

if substring ( option vendor-class-identifier, 0, 8 ) = "MSFT 5.0" {
vendor-option-space MSFT;
#option MSFT.release-on-shutdown 1;
option MSFT.nbt 2;
}

```