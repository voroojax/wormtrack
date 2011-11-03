#!/usr/bin/perl -w

#WormTrack NIDS: detects scanning worms on a networka,and machine scans
#    Copyright (C) 2011  Aleksandr Brodskiy
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#     any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#Email: abrods01 <AT  > GMAIL <Please NO SPAM> COM

use Net::PcapUtils;
use NetPacket::Ethernet qw(:types);
use NetPacket::ARP;
@ISA = qw(Net::IPAddress);
use Socket;
use strict;
use DBI;
use Cwd qw(abs_path);
use Net::ARP;
use Getopt::Std;
use Proc::Daemon;
use Privileges::Drop;
use Log::Log4perl qw(get_logger :levels);

my $IGNORE_FROM='MAC-IP';
my $DB_CONNECT='DBI:mysql:arpcap';
my $DB_USER='arpmon';
my $DB_PASS='arpmon';
my $INTERFACE='eth0';

my $from_ad_ip='0.0.0.0';
my $MINS_BETWEEN_AD_RUN=5;
my $UNPRIV_USER='nobody';
my %opts=();
getopts('hd:p:d:i:r:c:p:A:I:P:u:l:',\%opts);
my $LOG4PERL_CONF='./capture_log.conf';
if($opts{'l'})
{
         $LOG4PERL_CONF=$opts{'l'};
}

if($opts{'h'})
{
print "Usage:\n"
."-c DBI connect string\n"
."-i inteface to monitor\n"
."-r or filename to read from\n"
#."-p file name to write pid to\n"
."-d <PID file >make a daemon\n"
."-h this help\n"
."-A <minutes> Minutes between AudoDiscovery Iterations,0 to disable\n"
."-I Auto Discover from IP"
."-P password file with username:password for DB access\n"
."-u <localuser> to drop privileges to from root\n"
."-l <log config>\n"
;

exit(0);
}
if($opts{'u'})
{
$UNPRIV_USER=$opts{'u'};
}
if($opts{'c'})
{
$DB_CONNECT=$opts{'c'};
}
if($opts{'p'})
{
	open PASS_FILE, $opts{'p'};
	my $line=<PASS_FILE>;
	chomp $line;
	my($u,$p)=split /\:/,$line;
	$DB_USER=$u;
	$DB_PASS=$p;
	close PASS_FILE;
}

if($opts{'i'})
{
$INTERFACE=$opts{'i'};
}

my $PCAP_FILE='';

if($opts{'r'})
{
$PCAP_FILE=$opts{'r'};
$MINS_BETWEEN_AD_RUN=0;
}

if($opts{'A'})
{
 $MINS_BETWEEN_AD_RUN=$opts{'A'};
	if($opts{'I'})
	{
		$from_ad_ip=$opts{'I'};
	}
print("Will be Doing AutoDiscovery from $from_ad_ip \n");
}

if($opts{'d'})
{
print( "Staring Daemon\n");

my $pid_path='./arp_cap.pid';
$pid_path=$opts{'d'};

my $daemon = Proc::Daemon->new(
        work_dir     => '.',
     child_STDOUT => '+>>./arp_cap_out.txt',
      child_STDERR => '+>>./arp_cap_out.txt',
       pid_file     => $pid_path
    );
$daemon->Init();

}

Log::Log4perl->init_and_watch(abs_path($LOG4PERL_CONF),60);
my $logger=get_logger("ALL");
my $INTERFACE_MAC;
my $INTERFACE_MAC_FIXED;
if(!$PCAP_FILE)
{
	$INTERFACE_MAC = Net::ARP::get_mac($INTERFACE);
	$INTERFACE_MAC_FIXED = fixMAC($INTERFACE_MAC);
	$logger->info( "Using Physical IF,My MAC: $INTERFACE_MAC");
}
############################

my %IP_MAC_TABLE=();
my %AD_TABLE=();
my $last_autodiscovery_run=time();
my $dbh = DBI->connect($DB_CONNECT,$DB_USER, $DB_PASS
                   ) || die "Could not connect to database: $DBI::errstr";

my $insert_command="INSERT INTO Requests (src_mac,src_ip,dst_ip,time_sec,time_milis,grat,nmap) VALUES (?,?,?,?,?,?,?)";

my $sth = $dbh->prepare($insert_command)
                or die "Couldn't prepare statement: " . $dbh->errstr;
my $filter_compiled="";
my $err;
my $pcap_object;

if($PCAP_FILE) 
{
$pcap_object= Net::Pcap::open_offline($PCAP_FILE,  \$err);
}else
{
$pcap_object= Net::Pcap::open_live($INTERFACE, 100, 1, -1, \$err);
}
$logger->info("Dropping priv to $UNPRIV_USER");
drop_privileges($UNPRIV_USER);
Net::Pcap::compile($pcap_object, \$filter_compiled, 'arp',1,0);
Net::Pcap::setfilter($pcap_object, $filter_compiled);
Net::Pcap::loop($pcap_object,-1,\&handle_pcap,'');
#################################
sub hex2ip
{
my($ip)=@_;
return inet_ntoa(  pack( "N", hex( $ip ) ) );

}

sub  handle_pcap
{
my ($arg, $hdr, $pkt) = @_;


my $time_milis=$hdr->{'tv_usec'};
my $time_sec=$hdr->{'tv_sec'};

process_pkt($pkt,$time_sec,$time_milis);
}

#Handler
sub process_pkt {
    my ( $pkt,$time_sec,$time_milis) = @_;

    my $eth_obj = NetPacket::Ethernet->decode($pkt);

    if ($eth_obj->{type} == ETH_TYPE_ARP) {
	
        my $arp_obj = NetPacket::ARP->decode($eth_obj->{data}, $eth_obj);
        my $src_ip=hex2ip($arp_obj->{spa});
        my $dst_ip=hex2ip($arp_obj->{tpa});
        my $dst_mac=$eth_obj->{dest_mac};
        my $src_mac=$arp_obj->{sha};
	my $tha=$arp_obj->{tha};
	
	my $replyToMe=0;

	#When we get reply to _US_ from some machine
	#mark it as such, will later grat	
	if($INTERFACE_MAC_FIXED && ($dst_mac eq $INTERFACE_MAC_FIXED))
	{
	 $dst_ip=$src_ip; #make it grat
	 $replyToMe=1;
	} 	
        if(  ( ($dst_mac eq 'ffffffffffff') or $replyToMe)
		 and !shouldIgnore($src_mac,$src_ip)
)
        {
		 my $grat=$dst_ip eq $src_ip;
		#Nmap is when its not grat, and ARP target Hardware
		#Address is all FF,only nmap does it
		#which allows us to fingerprint it
		my $nmap=!$grat &&  ($tha eq 'ffffffffffff');
		my $time_str=localtime($time_sec);
		my $size_mac_table=scalar(keys %IP_MAC_TABLE);
                $logger->info("[ $time_str $src_mac,$src_ip ] --> $dst_ip]");
		$logger->debug("Number of MACs $size_mac_table, isNmap: $nmap");
		my @values=( $src_mac,$src_ip,$dst_ip,$time_sec,$time_milis,$grat,$nmap);
		#add src info to mac table
		$IP_MAC_TABLE{$src_ip}=$src_mac;
		#delete source info for AD auto discovery table,since it became known
		delete $AD_TABLE{$src_ip};

		#is destination,known? 
		my $dst_is_known=$IP_MAC_TABLE{$dst_ip};
		#if not add it to AD table
		if(!$dst_is_known)
		{
			$AD_TABLE{$dst_ip}=1;
		}

		$sth->execute(@values);
        }
	my $ad_time_elapsed=time()-$last_autodiscovery_run;
	#Randomize when we start AD
	my $rand_mins=irand($MINS_BETWEEN_AD_RUN);
	if($MINS_BETWEEN_AD_RUN>0 and $ad_time_elapsed>=(($MINS_BETWEEN_AD_RUN+$rand_mins)*60))
	{
	doAD();
	$last_autodiscovery_run=time();
	}
    }
}
sub irand
{
return int(rand($_[0]));
}
sub shouldIgnore
{
my ($src_mac,$src_ip,$dst_ip)=@_;

my $key=$src_mac.'-'.$src_ip;

if($key eq $IGNORE_FROM)
{

return 1;
}
#Ignore our own AD requests
elsif(($src_mac eq $INTERFACE_MAC_FIXED) and ($src_ip eq $from_ad_ip))
{
return 1;
}

return 0;

}

#send ARP requests to an unknown IP in a random order
#if no reply for 20 times or so we drop the unknown IP
sub doAD
{

my $iter_no=0;
$logger->info( "Starting AutoDiscovery...");
foreach my $ip (keys  %AD_TABLE)
{
	
	my $ip_req_count=$AD_TABLE{$ip};
	#the less number of tryed the more likely we will try again
	#another words,old IP's should be tryed less
	if(irand($ip_req_count)==0)
	{
		$logger->info( "Doing AD for $ip $ip_req_count");
		sendDiscoveryARP($ip);
		$ip_req_count++;
		$AD_TABLE{$ip}=$ip_req_count;
		if($ip_req_count>=20)
		{
			delete $AD_TABLE{$ip};
			$logger->debug("Exceeded Number of AD requests $ip");
		}
	}else
	{
		$logger->debug( "Skipping for  $ip $ip_req_count");
	}
	
}

}

sub sendDiscoveryARP
{
my($to_ip)=@_;
if($< == 0)
{
#Needs root
  Net::ARP::send_packet($INTERFACE,                 # Device
                        $from_ad_ip,          # Source IP
                        $to_ip,          # Destination IP
                         $INTERFACE_MAC,  # Source MAC
                        'ff:ff:ff:ff:ff:ff',  # Destinaton MAC
                        'request');             # ARP operation
}else
{
$logger->warn( "Please set Unpriv user to root to run AD\n");
}

}


sub fixMAC
{
my($mac)=@_;

$mac =~ s/[:|-]//g;
return lc($mac);

}

