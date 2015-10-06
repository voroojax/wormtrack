# Introduction #
WormTrack is a Network based intrusion detection system (NIDS) designed to identify scanning activity on the network, in particular of scanning worms (horizontal scanning of the network).
It attempts to do that WITHOUT having any type of privileged access to the network equipment, for example a MONITOR port on a switch.
It also doesn't require a constant updating of its signature engine, as new threats are released, since it is based on detection of anomalous  activity - which all Worms, that propagate through the network, would exhibit in order to survive and spread efficiently.

## Background ##
### The operation of  WormTrack software relies on 2 basic principles: ###
  1. To communicate with a machine on a LAN the source host has to discover the destination physical MAC address by broadcasting a (ARP Request) query to all nodes on the LAN.
  1. Most hosts on the LAN have a fairly predictable communication patterns such as destination peers, etc..

# Description of operation: #
> A client trying to establish IP connection with a server on the local LAN, first has to determine the MAC address for the destination IP (assuming it can't be found in the ARP cache). The source host has to broadcast an ARP Request to all hosts on the network. This arp request would contain full information of the source endpoint: IP and MAC address, and an "incomplete" information of the  destination end point - just the IP address. This behaviour allows any host on the network to monitor those ARP solicitations, because they are broadcast (Destination Ethernet MAC address is set to all 0xFF). If there exist a host with that destination IP address, it would reply directly (not broadcast) to the source host with it MAC address (ARP Reply). Thus simply by watching the ARP requests we can know 2 things: which host wants to communicate with which other host, and the source host MAC address. To underline, we are able accomplish all this completely  passively, and without any special access  to the network switch.
> The second piece of the puzzle, is the observation that, in a typical business LAN hosts have a set pattern of communication between each other. For example, in an office network, a desktop machines might talk to a file server, and to a printer, a secretary's machine would talk to a network FAX machine, and developers' machines would talk to a source-code versioning system. All desktops will talk to a default gateway (to get out on to the wider Internet). However, a secretary desktop will not talk to developers' desktop machines, file-server will not communicate with printers, etc.. Thus we are able to model the “normal” communications patterns on the network fairly well, and a significant deviation from that normal would be a cause for alert.
> > The worm on the network would scan all IP addresses on the subnet as fast as possible, in an effort to discover vulnerable machines. Similarly an insider with malicious intent will try to probe machines to which he should not be talking to. In fact, since he doesn't know the full topology of the network he will attempt to contact IP addresses which have no machines attached to, what-so-ever (dark-space).

## Implementation Overview ##

The current prototype is implemented completely in Perl and comes in 2 major, loosely coupled programs (modules):
  1. arp\_capture.pl is a front end, which is responsible for monitoring the physical network Interface for ARP traffic, decoding the packets, and inserting them into the database.
  1. The wormtrack.pl is the analyze program, which retrieves the packet info from Database and analyzes it, assuming a threat is detected it would call the correct alert program – to send out an E-Mail to admin (for example).

The capture module is the simplest - it  basically does a linear copy of arp packets from the wire into the  databases, in addition it perform auto detection of MAC addresses.

Most hosts on the network, even if they don't attempt to connect to some other host on the same network, send out periodic arp gratuitous broadcasts, which allow other hosts to know the machine's IP and MAC address. One of the requirements of analyze module is to know which IP addresses are dead and which are online, this is the task of auto discover functional. This is the only active part of the system, that is: for destination IP addresses which never broadcast an ARP request (thus we don't know if they are alive) we send out an arp request ourselves. Thus, if they are alive, we would record their reply with a MAC address, as a gratuitous announcement, into the database.

The analyze part of the software performs a number of functions:

  1. Load any configuration files which where updated.
  1. Load incidents from the database, and if any are closed, remove relevant items from the requests table (which were inserted before or at the closing time of the incident).
  1. Pull any latest arp requests from the database.
  1. Process the requests by adding each request to the chain, corresponding to its source IP. Thus, for any source IP, we can pull out which destinations it ever attempted to communicate with. It also performs basic packet level analysis:  for example, is a MAC address know? or if the given request was made by NMAP scanner? it keeps the results of this pre-analysis in the chain items.
  1. Analyze all chains, for all sources, to generate the score based on:
    1. How many machines did the particular source attempted to communicate with, which are NOT in the peer list of that source host.
    1. How many requests did the source attempted, which where destined to a non existing machines.
    1. Calculate how fast the requests where made by the client.
    1. How many requests came from the client with an unknown MAC address, that is address not defined in the known hosts config file, assuming we are monitoring that condition.
    1. How many requests where made by suspected port scanner such as nmap.
  1. The result of above is a numeric score, which if surpasses a defined threshold, would result in creation of an incident record:
    1. Create database record of the incident, such as current score, IP address of the source.
    1. Create a human readable (for now, eventually it will be XML) file with incident's detailed information.
  1. The last step is to attempt to send out an alert, this is accomplishing by inspecting the alert configuration table, which has two columns: incident score and program to execute. Thus, we execute the alert script which is either on our level of the score or bellow. That is, if out table looks like so: score: 500 => email, 700 =>sms . Given an incident with score of 600 would result only in email going out, incident score of 800 would cause email, as well as SMS text message being send out.

## Use Strategy ##
The general work flow and usage of the software is as follows:
  1. Set up of configuration files, the more information provided about the network the better
    1. Run the arp capture for some time to collect enough data, a few hours or a day on the network.
    1. set up a known hosts file: hostname =>IP,MAC address . IP could be a subnet. So if alex=>192.168.1.0/24,adff is defined. This would match for example 192.168.1.200 with mac adff11 . This permits more flexibility for networks with DHCP, where IP addresses might change but MAC is constant. However, it is better (for tighter security) to specify a full IP addresses for hosts, especially since in practice, DHCP servers try to always issue IP address to a host which already had that address before.
    1. Specify the peer relationship, for example alex<=>printer, router;  assuming that “printer” and “router” are defined in known hosts file, this rule says that alex can talk to the printer,and to arouter, and also the router can talk to alex and printer can talk to alex. One can use a short hand like bob,alex<=>printer,router this is equivalent to:  alex<=>printer, router AND bob<=>printer, router
    1. Run the analyzer in test mode with -t parameter, inspect the logs, if incidents are not being created. In case incidents are being generated, we have to update the configuration files again, either peers or hosts. This is done until in testing mode analyzer will run relatively silent (assuming no malicious incidents on the network).
    1. Start the WormTrack without -t and wait for alerts, or run an nmap scan test to see that it is working.
  1. Receive incidents, respond to them.
    1. If it is false positive update the config files accordingly.
    1. If its a malicious attack – remove the threat from the machine.
  1. Close the incident in the database (for now no UI is provided).



Some points to consider: this software is a proof of concept prototype, designed at this point to rapidly DETECT,  not stop the worm propagation. How rapidly? In a minute or two,  however that usually is not enough time to STOP the epidemic outbreak, and other methods must be used to PREVENT infections, such as packet limits on a switch, anti-virus ,etc.. However, there are  longer term plans for WormTrack to be able to issue a command (by means of SNMP) to a network switch, to disable the offending port, or put that port into quarantine VLAN.

Potential counter measures that an attacker can employ:

> If an attacker will limit himself only to host's peers, by either inspecting the host's ARP Cache, or monitoring the network for traffic, he would be able to fly “under the radar” since he would passively discover the network topology. In an effort to perform an this attack, he must slowly target only the machines which are peers of his host, and he would remain undetected by WormTrack.
> However, in  practice this attack doesn’t represent any realistic threat, for the following reasons: the attacker, especially a worm, has no prior knowledge that the network is monitored by WormTrack, thus if he assumes it is, he then would have to assume that for all other networks. However,  majority of networks are not protected in any way! Thus, by keeping a very low profile in an effort to evade WormTrack the worm would be an extremely slow and weak propagator, in general (on all Networks). It is obvious that no rational malware author would cripple his worm in such a way. In addition, assuming a secretary machine was infected: with legitimate peer map as follows secretary<=>printer,DG,fax  , the worm would be limited to only attempt attacks against: printer,DG router,and fax - most of them are embedded devices, which would not be vulnerable to a typical Windows based worm. In other word by being careful, the worm limits the potential target pool significantly, and in such a way that it's ability to propagate becomes crippled. Again, no worm author would implement something like that.

## Configuration ##
Lets say we have a bussiness network with an IP of 10.10.10.1-50

Configuration of known hosts and peers:
In a main config file we set NETS\_TO\_MONITOR=10.10.10/24!
What this says is, to monitor packets from or to this network, and ENFORCE IP - MAC binding.

For a guest network, where we don't have a list of IP and Macs, we will omit “!” disabling the enforcement for that particular network. Machines sometimes, especially Windows, attempt to communicate with some strange IP address or an old one, from another network, thus its useful to ignore those spurious requests- they are by definition harmless, since no machine on the current network would listen to that strange IP address.

The example network contains the following devices:

Router Default gateway : 10.10.10.1 mac: abcdef123
Printer: 10.10.10.5 mac: bcef789
File server: 10.10.10.4 mac:eeffcc90123
CVS and Build server: 10.10.10.3 mac:cefa65612

Developer1 10.10.10.11 mac:aecf0912
Developer2 10.10.10.12 mac:aecf0913
Developer3 10.10.10.13 mac:aecf0916

Secretary 10.10.10.20 mac:eeff00

Thus the known hosts file will look something like this:
```
network=>10.10.10.0/24
gateway=>10.10.10.1,abcdef123
Printer=>10.10.10.5,bcef789
File-server=>10.10.10.4,eeffcc90123
cvs=>10.10.10.3,cefa65612

Developer1=>10.10.10.11,aecf0912
Developer2=>10.10.10.12,aecf0913
Developer3 => 10.10.10.13

Secretary =>10.10.10.0/24,eeff00
```
We have just defined all known machines: and also the network itself: so assuming we are enforcing MAC addresses as specified in main config for this network.
The following are a few examples to better undertand how WormTrack will handle packets with different combinations of IP's and MAC's addresses:

If we receive a packet with src IP 10.10.10.5 and MAC address 12ff00,  this packet matches printer by IP address but not by MAC address, thus it will be flagged as invalid MAC. What happens if we receive a packet with IP 10.10.10.30 and MAC address bcef789AA00? That packet will  match by IP address Secretary and Network, however none of them have a prefix to match the MAC – so, this packet would also be marked as Invalid MAC.
Finally a packet with IP 10.10.10.5 and MAC  bcef789AA00 would match Printer IP and MAC prefix.

Another example: We receive a packet 10.10.10.30 and MAC address: eeff00, this would match Secretary exactly: IP matches the /24 netmask, and MAC prefix also matches, thus it will marked as Valid.

Last example: Packet arrives from 10.10.10.13 and MAC address AAFF0033 will match Developer3 since in a known hosts file MAC address is not specified we ignore it for comparison and only use IP address. However, we demand a full IP match not netmask, this why “network” doesn't match.

The peer configuration file defines which hosts (declared in the known hosts file) we expect to routinely talk to each other.

Let us now try to come up with rules:
  1. Any machine on the network should be able to talk to the default gateway.
  1. Any machine should be able to talk to the printer.
  1. Developers should be able to talk to cvs server.
  1. Secretary should be able to talk to the file server.
In this version of the software we assume two-way communication: so if we allow secretary to talk to the printer we assume that its also ok for printer to talk to the secretary machine, that is send an ARP request to it.

From above we able to come up with possible config file:
```
network<=>gateway,printer #anybody can talk to printer and DG
Developer1,Developer2,Developer3<=>cvs
Secretary<=>file-server
```


Some notes on the general config file syntax:
All items are case insensitive.
Comments are specified with “#” pound sign on the line, everything after that is ignored.
Spaces are ignored between items:
```
Secretary<=>file-server
```
is same as
```
Secretary       <=>        file-server #hh
```
but NOT:
```
Secretary< = >file-server
```

All config files have a basic structure of
Right side possibly delimited by commas (<=> OR => OR = depending on context) Left side possibly delimited by commas.

If your network contains a number of MS Windows machines please read [WindowsFalsePositives](WindowsFalsePositives.md)