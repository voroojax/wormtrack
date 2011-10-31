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

use strict;
use DBI;
use Net::IP;
use Switch;
use Carp qw(longmess); #stack trace do: print longmess()
#install Time::Format_XS otherwise wont work in daemon mode
use Time::Format qw(time_format time_strftime time_manip %time %strftime %manip);
use Cwd qw(abs_path);
use Getopt::Std;
use Proc::Daemon;
use Log::Log4perl qw(get_logger :levels);
my $DB_CONNECT='DBI:mysql:arpcap';
my $DB_USER='arpmon';
my $DB_PASS='';
my $MAX_DIFF=5;
my %REQS_BY_SRC=();
my $LOOP_MAX_SECONDS=10;
my $MAIN_CONFIG_FILE='';
my $MINIMUM_INCIDENT_SCORE=400;
my $KNOWN_HOSTS_FILE="/known_hosts.txt";
my $HOST_PEERS_FILE="./host_peers.txt";
my $INCIDENT_PATH="./incidents/" ;
my @NETS_TO_MONITOR=();
my %WEIGHTS=();

my $DATE_TIME_FORMAT='mm/dd/yyyy hh:mm';
my $REFRESH_LOG_CONF=60;
my $SQL_INSERT_ID="mysql_insertid";
# Keyed by seconds mapped to a score, used for fast scan detection
my %SCAN_TIME_BUCKETS=
(
#1 => 200,
#5 => 150,
#30 => 100,
#60 => 50,
#10*60 => 20,
#60*60 => 10,
#10 *60*60 =>5
);

#Table which stores for each score,the program to excute,loaded from main conf
my %INCIDENT_ALERT=();
############################

#table of known hosts from file hostname,ip,mac
my %KNOWN_HOSTS_TABLE=();

#table of IP MAC build during runtime
#used to establish if a given IP actually exist on network
my %IP_MAC_TABLE=();

#Allowed peers from file, peer1,peer2 ...
my @HOST_PEERS_TABLE=();
my %INCIDENTS_TABLE=();
my %opts=();

getopts('d:htc:p:l:', \%opts);
my $LOG4PERL_CONF='./track_log.conf';
if($opts{'l'})
{
	 $LOG4PERL_CONF=$opts{'l'};
}

my $P_LOG="Process";
my $A_LOG="Analyze";
my $I_LOG="Incident";
my $C_LOG="Conf";
my $S_LOG="System";

if($opts{'h'})
{
print "Usage: \n -c main_config.conf\n"
."-h show this help\n"
."-d <PID Filename> run as Daemon\n"
."-t Testing/Training store alert on incidents\n"
."-l <log4perl file> log4perl config file"
#."-p PID file"
."\n";
exit(0);
}
my $isTesting=$opts{'t'};
if($isTesting)
{
print("WARN: Running in Testing mode, writing to DB and Incidents alerts will be disabled.")
}

if(!$opts{'c'})
{
print "Please specify the main configuration file with a -c option\n";
exit(1)
}

my $expected_pid=$$;

if($opts{'d'})
{
print "Starting  Daemon\n";

my $pid_path='./arp_track.pid';
$pid_path=$opts{'d'};

my $daemon = Proc::Daemon->new(
        work_dir     => '.',
     child_STDOUT => './track_output.txt',
      child_STDERR => '+>>track_debug.txt',
       pid_file     => $pid_path

    );
$daemon->Init;

}

Log::Log4perl->init_and_watch(abs_path($LOG4PERL_CONF),$REFRESH_LOG_CONF);

$MAIN_CONFIG_FILE=$opts{'c'};

#have to load main config ASAP
loadMainConfig();

#connect to DB and set up Prepared stmts
my $dbh = DBI->connect($DB_CONNECT,$DB_USER, $DB_PASS
                   ) || die "Could not connect to database: $DBI::errstr";

my $select_req_command="SELECT src_mac,src_ip,dst_ip,time_sec,time_milis,nmap,id  FROM Requests WHERE id >? ORDER BY  id ASC";

my $sth_req = $dbh->prepare($select_req_command)
                or die "Couldn't prepare statement: " . $dbh->errstr;


my $select_inc_command="SELECT incidentid,src_ip,first_packet,last_packet,score,closed  FROM Incident ORDER BY  incidentid ASC";

my $sth_select_inc = $dbh->prepare($select_inc_command)
                or die "Couldn't prepare statement: " . $dbh->errstr;

my $insert_inc_command="INSERT INTO Incident (src_ip,first_packet,last_packet,score) VALUES (?,?,?,?)";

my $sth_inc_insert = $dbh->prepare($insert_inc_command)
                or die "Couldn't prepare statement: " . $dbh->errstr;

my $update_inc_command="UPDATE Incident SET first_packet=?,last_packet=?,score=?  WHERE incidentid=?";

my $sth_inc_update = $dbh->prepare($update_inc_command)
                or die "Couldn't prepare statement: " . $dbh->errstr;

my $secs2sleep=undef;

my $iter_no=0;

my $last_id=0;
$SIG{'USR1'}='printReqTable';

#starting main loop
debug($S_LOG,"Staring Main Loop, PID; $$");
while(1)
{
my $t_start=time();
my $num_processed=0;
loadConfigFiles();
loadIncidents();

($last_id,$num_processed)=processData($last_id);
info($P_LOG,"==***==   Processed $num_processed Packets, Last ID: $last_id ====***==");

analyze();

$iter_no++;
my $t_end=time();

my $time_elapsed=$t_end-$t_start;
debug($P_LOG,"Time Taken: $time_elapsed seconds");

#the following tries to figure out how long should we wait before the next iter;
#for example: say iteration should be 20 seconds, to process packets
#it takes 5 seconds -so, we should repeat loop in 15 seconds
my $repeat_in_seconds=$LOOP_MAX_SECONDS-$time_elapsed;

#Only sleep when we ran a couple of iterations - to get all old
#packets from DB
if($repeat_in_seconds <=0 ||$iter_no<3)
{
	$repeat_in_seconds=1;
}
debug($P_LOG,"Will sleep for $repeat_in_seconds seconds");
sleep($repeat_in_seconds);
}
######### = End Main Loop, Doing subs =###############



#================ Process ============================
#processes new Packets from DB
#from_id, is packet ID after which to process
sub processData
{

my ($from_id)=@_;
my $last_id=$from_id;
my @params=($from_id);
$sth_req->execute(@params)  or die "Couldn't execute statement: " . $sth_req->errstr;

my $count=0;
while (my @row = $sth_req->fetchrow_array()) {
       my ($src_mac,$src_ip,$dst_ip,$time_sec,$time_milis,$nmap,$id)=@row;
	$last_id=$id;
	addRequest(@row);
	$count++;
    }
debug($P_LOG,"Processed $count packets");
return ($last_id,$count);
}


#add an actual request to the Requests hashTable
sub addRequest
{
my   ($src_mac,$src_ip,$dst_ip,$time_sec,$time_milis,$nmap,$id)=@_;
my $time_delta=undef;

#are we coming from a valid IP
if($src_ip ne '0.0.0.0')
{
	#check if that IP should be monitored
	#does netmask check
	my @should_monitor_ip=shouldMonitorIP($src_ip);
	if(!@should_monitor_ip)
	{
		#if not,return
		return;
	}

	#add to MAC table
	add2MACTable($src_ip,$src_mac);

	my $dist_chain_ref=$REQS_BY_SRC{$src_ip};

	#if no chain for that IP - create it
	if(!defined($dist_chain_ref))
	{
	#first guy is place holder, MAYBE someday we will have chain global info in there
	  my @empty=('empty');
		
	  $dist_chain_ref=\@empty;
	  $REQS_BY_SRC{$src_ip}=$dist_chain_ref;		
	}
	
	#if grat we stop at this point
	if($dst_ip eq $src_ip)
	{
		return;
	}
	#otherwise
	#drop the first item of the chain	
	my @chain_orig= @$dist_chain_ref;
	my @chain=@chain_orig;
	my $chain_info=shift (@chain);
	
	my $chain_len=scalar(@chain);
	
	#if more than one items in a chain we calculate the time delta of current one
	if($chain_len>0)
	{
		
		#current minus prev,do abs value, cause sometimes packets might 
		#be out of order time wise
		my $item_ref=$chain[$chain_len-1];
		
		my $prev_time=$item_ref->{'TIME'};
		$time_delta=abs($time_sec-$prev_time);
	}

	my $host_declared_result='F';
	#in reply of shouldMonitorIP above, it includes if we have to
	#do a MAC check
	if($should_monitor_ip[1])
	{
		$host_declared_result=hostDeclaredByIP_MAC($src_ip,$src_mac);
	}
	#if F means Full match
	
	#see if destination doesnt exist
	my $item_exists=getItemFromChain(\@chain,$dst_ip);
	
	
	#and the current packet is NOT in reply to a pervious one
	#and we SHOULD monitor the distination (before we checked the source)
	if(!defined($item_exists) 
	 &&!isReplyTo($dst_ip,$src_ip,$time_sec)
	&& shouldMonitorIP($dst_ip)
	)
	{
		my %dist_obj=
	 	('DIST_IP'=>$dst_ip,
		 'TIME'=>$time_sec,
		'TIME_DELTA'=>$time_delta
		
		);
		$item_exists=\%dist_obj;
		push @$dist_chain_ref,$item_exists;
	}
	
	#At this point we have item either created or pulled from chain
	
	if(defined($item_exists))
	{
		#so we set some things which we determined
		$item_exists->{'LAST_ACCESS'}=$time_sec;

		#if host no match is not set, then  we can possibly set it
		if(!$item_exists->{'HOST_NO_MATCH'})
		{
			my $host_no_match=($host_declared_result ne 'F');
			$item_exists->{'HOST_NO_MATCH'}=$host_no_match;

			#if its INDEED no match, then add invalid MAC to the list of MACs
			if($host_no_match)
			{
				my $invalid_macs=$item_exists->{'INVALID_MACS'};
				if(!defined($invalid_macs))
				{
					my %h=();
					$invalid_macs=\%h;
					$item_exists->{'INVALID_MACS'}=$invalid_macs;
				}	
				$invalid_macs->{$src_mac}=1;
			}
			
		}

              if(!$item_exists->{'IS_NMAP'})
                {
                        $item_exists->{'IS_NMAP'}=$nmap;
                }


	}
}
		
	

}

#Add IP and MAC to a MAC table
#so given an IP we can get a list of MACs it used
sub add2MACTable
{
my($ip,$mac)=@_;
my $mac_ref=$IP_MAC_TABLE{$ip};
my @macs=undef;
if(defined($mac_ref))
{
	 @macs=@{$mac_ref};
	 #if that MAC is already in list,dont add it again
	 #possibly should be using HashMap
	foreach my $list_mac (@macs)
	{
		if($list_mac eq $mac)
		{
			return;
		}
	}
	push @macs,$mac;
}else
{
	@macs=($mac);
	
}
 $IP_MAC_TABLE{$ip}=\@macs;
}

#tells if given IP should be monitored based on user conf,and if
#MAC should be enforced
sub shouldMonitorIP
{
my($ip)=@_;
my @out=();

#for every Value in the list ,we check, until find match
foreach my $network (@NETS_TO_MONITOR)
{
my $len=length($network);
if($len>0)
{
	#if ends with ! then have to enforce MAC
	my $mac_monitor=((index $network,'!')==($len-1));
	my $network_real=$network;
	if($mac_monitor)
	{
		$network_real=substr $network,0,$len-1;
	}
	#extracted the actual IP or netmask
	my $net_obj=getIPObject($network_real);
	my $ip_obj=getIPObject($ip);
	#see if the IP is inside the specified netmask
	if(isIPInNetwork($net_obj,$ip_obj))
	{
	@out=(1,$mac_monitor);
	return @out;
	}
}

}

#return empty nothing found
return @out;

}

#Given src and distination IP, returns the actual Item from correct chain
#Used in isReplyTo
sub getItemFromHash
{

my ($src_ip,$dist_ip)=@_;
my $chain_ref=$REQS_BY_SRC{$src_ip};
#find the right chain by Source IP
 if(defined($chain_ref))
 {
	my @c=@$chain_ref;
	my @chain=@c;
	shift @chain;
	#find the item by Distination IP
	return getItemFromChain(\@chain,$dist_ip);
 }
 else
 {
	return undef;
 }

}

#given a source IP (my_ip) and destination ip (To_ip)
#determines if there was a request short time before from
#to_ip to my_ip
sub isReplyTo
{

my($to_ip,$my_ip,$my_time)=@_;

#find the item comming from destination to me (current packet)
my $item_ref=getItemFromHash($to_ip,$my_ip);

#if found, check that time interval is short enough
#so this packet is in reply
if(defined($item_ref))
{

my $last_time=$item_ref->{'LAST_ACCESS'};
my $delta=abs($my_time-$last_time);

my $isReply=($delta<=$MAX_DIFF);

if($isReply)
{
	debug($P_LOG,"Reply by $my_ip to $to_ip, within $delta seconds");
}

return $isReply;
}

return undef;
}


#given chain ref, find the item by distination IP
#Otherwise returns undef
sub  getItemFromChain
{
my($chain_ref,$target_ip)=@_;

my @chain=@$chain_ref;

foreach my $item_ref(@chain)
{
        if($item_ref->{'DIST_IP'} eq $target_ip)
        {
         return $item_ref;
        }

}
return undef;
}


#checks if the given IP MAC matches the one in known hosts file
#Used for MAC enforcement in process
sub hostDeclaredByIP_MAC
{
my($ip,$mac)=@_;
my $mac_match='';

#pull hosts from the Known hosts table
foreach my $host_name (keys %KNOWN_HOSTS_TABLE)
{
	my $hi_ref=$KNOWN_HOSTS_TABLE{$host_name};
        my @host_info=@{$hi_ref};

	my $file_mac=$host_info[1];
	my $file_ip=$host_info[0];
	#if the MAC address is provided
	#then we check it
	
	my $net_ip_file=getIPObject($file_ip);
	#if MAC is set in the file
	if(defined($file_mac))
	{
        	#then do prefix match on MAC
	        if(macPartialMatch($file_mac,$mac))
        	{
			#if it matched
			#then do we can do SUBNET match on IP
                	$mac_match='M';
	                #do subnet match
			my $ip_obj=getIPObject($ip);
        	        if(isIPInNetwork( $net_ip_file,$ip_obj))
                	{
                        	return 'F';
                	}

        	}

	}else #mac not set in file
	{
        	#do FULL (unlike the above when we did subnet match) ip match
		#we cant do just string comparison because it can
		#be entered IP as 1.1.1.1/32 which is same as 1.1.1.1
	        if(defined($net_ip_file) &&  $net_ip_file->prefixlen()==32
        	and $net_ip_file->ip() eq $ip)
        	{
                	return 'F';
        	}

	}
}
return $mac_match;
}

#================ Analyze =============================
sub analyze
{
	#iterate through all src hosts in Requests table
	#and analyze their chain
	foreach my $src_ip (sort keys %REQS_BY_SRC)
	{

		my $t1=time();
		analyzeChain($src_ip,$REQS_BY_SRC{$src_ip});

		debug($A_LOG,"Analyze for $src_ip took: ".(time()-$t1));
	}


}

#analyze chain, takes src host IP, and a chain reference
sub analyzeChain
{
	my ($src_ip,$dist_chain_ref)=@_;
	my @dist_chain=@$dist_chain_ref;
	my @dist_chain_copy=@dist_chain;
	my @chain_string=();
	#drop first item of the chain
	shift @dist_chain_copy;
	
	my $dark_space_count=0;
	my $white_space_count=0;
	my $time_delta_score=0;	
	my @unknown_list=();
	my $invalid_peers_count=0;
	my @INVALID_PEERS=();
	my $first_packet_sec='';
	my $last_packet_sec='';
	my $failed_mac_match=0;	
	my %invalid_macs=();
	my $have_valid_mac=0;
	my $nmap_count=0;


	foreach my $item (@dist_chain_copy)
	{
		my $to_ip=$item->{'DIST_IP'};
		my $time=$item->{'TIME'};


		#see if we are trying to talk to none-existing host
		$item->{'DARKSPACE'}=undef;
		
		#was the host ever one of the sources
		my $to_host_exists=$REQS_BY_SRC{$to_ip};
		#or check if that host is in Known hosts table, defined by user
		if(!defined($to_host_exists)
		&& !defined(getKnownHostByIP($to_ip))
		)
		{
			#Talking to NON-Existing host
			push @unknown_list,$to_ip;
			$item->{'DARKSPACE'}=1;
			$dark_space_count++;
		}else
		{
			#talking to Existing host
			$white_space_count++;
			#check if its a Valid Peer of the Source
			$item->{'WRONG_PEER'}=undef;
	                #do talk-to analysis
        	        if(!isValidPeer($src_ip,$to_ip))
                	{
				#not valid peer, mark as such
                        	$invalid_peers_count++;
	                        push @INVALID_PEERS,$to_ip;
        	                $item->{'WRONG_PEER'}=1;
                	}

		}
		#take not of time of last,and first packet in the chain
		 $first_packet_sec=$time if (!$first_packet_sec);
         $last_packet_sec=$time;

		#do timing analysis
		my $delta=$item->{'TIME_DELTA'};
		#find out the score for a given time delta, and add it to total
		if(defined($delta))
		{
			$time_delta_score=
			$time_delta_score+findScoreForDelta($delta);
		}
		
		#see if the any requests came with invalid MAC
		if($item->{'HOST_NO_MATCH'})
		{
			$failed_mac_match=1;
		#get list of macs and add them to a table for display later
			my %macs=%{$item->{'INVALID_MACS'}};
			foreach my $mac (keys %macs)
			{
				$invalid_macs{$mac}=1;
			}
		}else
		{
			$have_valid_mac=1;
		}
		#count how many potential Nmap nping,scans we get
		if($item->{'IS_NMAP'})
		{
			$nmap_count++;
		}
		
	}#loop for the chain is over
	#presenting the info

	my @invalid_macs_list=keys %invalid_macs;
	if($failed_mac_match )
	{
	
		Warn ($A_LOG,"Failed MAC match: $src_ip @invalid_macs_list");
	}
	if(scalar(@INVALID_PEERS)>0 )
	{
		Warn($A_LOG,'Invalid peers are: '.findHostInFile($src_ip).' -> '.ipList2String(\@INVALID_PEERS));
	}

	#getting total score; basicly get most counts and multiply them
	#by the respective,user defined,weights
	#we use log for nmap because,otherise, it would contribute disproportiontly 
	#to the total
	my $total_score=$time_delta_score+($WEIGHTS{'WRONG_PEER'}*$invalid_peers_count)+
	($WEIGHTS{'DARK_SPACE'}*$dark_space_count)+($WEIGHTS{'FAILED_MAC'}*$failed_mac_match)
		+ int($WEIGHTS{'NMAP'}*(2*log($nmap_count+1)));
	
	#incident recording, and alerting; only if we get Minimum score	
	if($total_score>=$MINIMUM_INCIDENT_SCORE)
	{
		info($A_LOG,"Incident Stats $src_ip:  Fast Scan Score: $time_delta_score, \n".
"Invalid Peer Count: $invalid_peers_count, Dark Space Count: $dark_space_count\n".
"Invalid MACs: $failed_mac_match,NMap count: $nmap_count");
		#prev incident
		my $incident_ref=$INCIDENTS_TABLE{$src_ip};

		my %incident=();
		my $incident_id=undef;
		if(!defined($incident_ref))
		{	
			%incident=('SCORE'=>$total_score);
		        
			        
		}else #get past Incident info
		{
			%incident=%{$incident_ref};
			$incident_id=$incident{'INCIDENT_ID'};
		}

		#if Testing don't act on it,in any way
		#also if score didn't change between iterations
		#- do Nothing
		if(!$isTesting and (
		!defined($incident_ref)||$incident{'SCORE'}!=$total_score)
		)
		{
			info($A_LOG,"Writing Incident Score $total_score by $src_ip");

			#Update incident in DB
			$incident_id=updateIncident($incident_id,$src_ip,$first_packet_sec,$last_packet_sec,$total_score);

			makeIncidentFile($src_ip,$incident_id,$dist_chain_ref,$dark_space_count,
			$total_score,$invalid_peers_count,$time_delta_score,$failed_mac_match,\@invalid_macs_list,$have_valid_mac,
			$first_packet_sec,$last_packet_sec,$nmap_count);

			#send out alerts if have to
			doAlert($incident_id,$total_score);
		}
	}

}



#given the time delta in seconds it tryes to put it in the right bucket,
#and depending on bucket get the score
sub findScoreForDelta
{
my ($time_delta)=@_;

#Go though all buckets,order them shortest to longest time intervals
foreach my $bucket_secs (sort keys %SCAN_TIME_BUCKETS)
{
	#find the closest 'Fit'
	if($time_delta<=$bucket_secs)
	{
		#return the score
		return $SCAN_TIME_BUCKETS{$bucket_secs};
	}

}

#delta too greate ,score is zero
return 0;

}



#check if peer A and B can talk betwen each other
sub isValidPeer
{
my($a_ip,$b_ip)=@_;
foreach my $peer_pair_item (@HOST_PEERS_TABLE)
{
	
	#get A B Hosts from table
	my ($a_host,$b_host)=split /,/,$peer_pair_item;
	#see if a given A host matches the A IP
	if(isKnownHostMatch($a_host,$a_ip))
	{
		#if so see if B host matches the B request Ip
		if(isKnownHostMatch($b_host,$b_ip))
		{
			debug($A_LOG,"$a_ip ($a_host) Can talk to $b_ip ($b_host)");
			return 1;
		}
	}
}
return undef;
}

#Determines if that host is known for thatr IP
#used for Peer validation
sub isKnownHostMatch
{
my($host,$ip)=@_;

my $array_ref=$KNOWN_HOSTS_TABLE{$host};
if(defined($array_ref))
{
my @host_info=@{$array_ref};

my $network =getIPObject ($host_info[0]);
my $req_ip= getIPObject ($ip) ;

my $mac_from_file=$host_info[1];
my $macValid=!defined($mac_from_file); #if not set then we skip the check


#Mac was not checked yet, AND it exists
if(!$macValid)
{
	#using the request IP, we check if any seen MAC
	#match the one in a know hosts file
	my $macs_ref=$IP_MAC_TABLE{$ip};

	if(defined($macs_ref))
	{
		my @macs=@{$macs_ref};
		foreach my $mac_seen (@macs)
		{
			
			#do prefix match
			
			if(macPartialMatch($mac_from_file,$mac_seen))
			{
				$macValid=1;
				last;
			}
		}
	}else #if no macs seen we just mark it as validated,in this case
	{
		$macValid=1;
	}
}
#do IP subnet check
return  isIPInNetwork($network,$req_ip)  && $macValid;
}

return undef;
}

#Get From Known Hosts table the host either by MAC or IP
sub getKnownHostByIP
{
my($ip)=@_;
return getKnownHost($ip);
}

#Not used for now

sub getKnownHostByMAC
{
my($mac)=@_;

return getKnownHost($mac,1);
}
sub getKnownHost
{
my($ip_or_mac,$by_mac)=@_;

if(!defined($ip_or_mac))
{
error($S_LOG, "NOT DEFINED!");
}

#go through table,and find either MAC or IP
foreach my $host_name ( keys %KNOWN_HOSTS_TABLE)
{
	my $hi_ref=$KNOWN_HOSTS_TABLE{$host_name};
	my @host_info=@{$hi_ref};
	if(defined($by_mac) and $by_mac>0)
	{
		 if($ip_or_mac eq $host_info[1])
		{
			return $host_name;
		}

	}elsif($ip_or_mac eq $host_info[0])
        { 
         	return $host_name;
                	
	}


}
#Nothing found
return undef;
}

#================ Incidents ===========================
#take incident parameters and write it to file
sub makeIncidentFile
{
my $spacer="============================================================\n";
my($src_ip,$incident_id,$chain_ref,$dark_space,$total_score,$invalid_talk,$time_delta_score,$mac_no_match,$invalid_macs_list_ref,$have_valid_mac,
 $first_packet_sec,$last_packet_sec,$nmap_count)=@_;

open INCIDENT_FILE, ">", $INCIDENT_PATH.'/'."$incident_id.incident" or die $!;
my $hostname=findHostInFile($src_ip);

my $time_delta_str=time2string($last_packet_sec-$first_packet_sec);

my $first_line= "Incident # $incident_id, and SRC_IP: $src_ip ";
if($hostname ne $src_ip)
{
	$first_line=$first_line." ($hostname) ";
}

$first_line=$first_line.timeStr($first_packet_sec).'-'.timeStr($last_packet_sec)." Delta $time_delta_str";
$first_line=$first_line."\n";
print INCIDENT_FILE $first_line;
print INCIDENT_FILE $spacer;
my $basic_info= "Total Score: $total_score";

$basic_info=$basic_info.", [D]arkSpace # $dark_space" if($dark_space>0); 

$basic_info=$basic_info.",Non [P]eer Addresses: $invalid_talk " if($invalid_talk>0);

$basic_info=$basic_info.",[N]Map Count: $nmap_count " if($nmap_count>0);

if($mac_no_match)
{
	my $some='ALL';

	$some='SOME' if($have_valid_mac);

	my $invalid_macs_str= join ',',@{$invalid_macs_list_ref};
	$basic_info=$basic_info." $some [M]AC match failure: $invalid_macs_str ";
}

$basic_info=$basic_info.",Fast Scan Score: $time_delta_score \n";

my $chain_string=distChain2String($chain_ref,3,1);

print INCIDENT_FILE $basic_info;
print INCIDENT_FILE $spacer;
print INCIDENT_FILE $chain_string."\n";
close INCIDENT_FILE;
}



#Insert/Update incident in a DB
#takes basic info,like src IP,score
sub updateIncident
{
my ($incident_id,$src_ip,$first_packet,$last_packet,$score)=@_;
my @vals=();

#if ID is not defined its a new incident
if(!defined($incident_id))
{
#src_ip,first_packet,last_packet,score
 @vals=($src_ip,$first_packet,$last_packet,$score);
$sth_inc_insert->execute(@vals);

#get the ID from DB since its auto Incriment
$incident_id=$dbh->{$SQL_INSERT_ID};
}
else
{
#if have incident,we just update
@vals=($first_packet,$last_packet,$score,$incident_id);
$sth_inc_update->execute(@vals);
}

#return incident ID
return $incident_id;
}

#takes incident id,and score,and sends using right alert method
sub doAlert
{
my($incident_id,$incident_score)=@_;
my $arg=quotemeta '$INCIDENT_ID';
#go though alert table and find, alert command
#which handle a greater or equal score for our incident
foreach my $score_key (keys %INCIDENT_ALERT)
{
	#its a hack to support keys with the same score
	my ($score,$x)=split /\./,$score_key;
	print "Score: $score\n";
	if($score<=$incident_score)
	{
		#get command, and place out incident id into its parameter
		my $exec_cmd=$INCIDENT_ALERT{$score_key};
		
		$exec_cmd =~ s/$arg/$incident_id/g;
		info($I_LOG, "Executing: $exec_cmd");
		#start process in background so we wont be slown down
		system($exec_cmd.' &');
	}
}

}

#loads incidents from DB into the hashTable
sub loadIncidents
{

debug($I_LOG,"Loading Incidents from DB");
$sth_select_inc->execute()  or die "Couldn't execute statement: " . $sth_select_inc->errstr;

my $count=0;
%INCIDENTS_TABLE=();

#From DB,populate the Incidents HashMap
while (my ($incidentid,$src_ip,$first_packet,$last_packet,$score,$closed) = $sth_select_inc->fetchrow_array()) {
	
	my %incident=
	(
	'INCIDENT_ID'=>$incidentid,
	'FIRST_TIME'=>$first_packet,
	'LAST_TIME'=>$last_packet,
	'IS_CLOSED'=>$closed,
	'SCORE'=>$score
	);

	debug($I_LOG,"Loaded Incident with $incidentid $src_ip");
	$INCIDENTS_TABLE{$src_ip}=\%incident;
}
debug($I_LOG,"Total Incidents loaded: ".scalar(keys(%INCIDENTS_TABLE)));
}

#removes packets from chains which happened before the incident was closed
sub clearClosedPackets
{

debug($I_LOG,"Removing packets for closed Incidents");
foreach my $src_ip (keys  %INCIDENTS_TABLE)
{
	my %incident=%{$INCIDENTS_TABLE{$src_ip}};
		
	#if closed, find the chain in requests table and remove packets
	if($incident{'IS_CLOSED'})
	{	 
		debug($I_LOG,"Incident with IP: $src_ip is closed");
		$REQS_BY_SRC{$src_ip}=clearChain($incident{'LAST_TIME'}, $REQS_BY_SRC{$src_ip});
		delete $INCIDENTS_TABLE{$src_ip};
	}
}

}
#actually remove the packets from a given chain
sub clearChain
{
my ($close_time,$chain_ref)=@_;

my @chain=@{$chain_ref};
my $i=0;
my $found_index=undef;
#find the old item in the chain, before or equals the close time
foreach my $req (@chain)
{
	#skip the first,because its an object
	if($i>0)
	{

		my $req_time=$req->{'TIME'};
		if($req_time<=$close_time)
		{
			$found_index=$i;
		}
		else
		{
		last;
		}
	}
	
	$i++;
}

if(defined($found_index))
{
	debug($I_LOG,"Found, will remove from 1 -$found_index");
	splice @chain,1,$found_index;
}
return \@chain;
}

#================ Config File =============================
#just load all config files
sub loadConfigFiles
{
	loadMainConfig();
	loadKnownHosts();
	loadHostPeers();
}

sub loadMainConfig
{
debug($C_LOG,"Loading main config");
my @lines=readFile($MAIN_CONFIG_FILE,'MAIN_CONFIG');
if(!isValid(@lines))
{
debug($C_LOG,"Was not changed so, nothing to do");
return;
}

#some defaults
@NETS_TO_MONITOR=('0.0.0.0');
%SCAN_TIME_BUCKETS=();
$KNOWN_HOSTS_FILE='';
$HOST_PEERS_FILE='';
$INCIDENT_PATH='./incidents/';
%INCIDENT_ALERT=();

my $line_index=0;
foreach my $line (@lines)
{
		$line_index++;
        my $conf_ref=parseFileLine($line,'=');
        if(defined($conf_ref))
	{
		my @var=@{$conf_ref->{L}};
        my @data=@{$conf_ref->{R}};
		my $first_var=$var[0];
		my $first_data=$data[0];
		debug($C_LOG,"Index. $line_index Line: $first_var = $first_data");

		switch($first_var)
		{
			case  'DBI_STRING'
			{
				$DB_CONNECT=$first_data;
			}
			case 'DB_USER'
			{
				$DB_USER=$first_data;
			}case 'DB_PASS'
					{
				$DB_PASS=$first_data;
                	}
			case 'ITER_PERIOD'
			{
				$LOOP_MAX_SECONDS=$first_data
			}
			case 'MINIMUM_INCIDENT_SCORE'
        	        {
				$MINIMUM_INCIDENT_SCORE=$first_data;
                	}case 'KNOWN_HOSTS_FILE'
                	{
				$KNOWN_HOSTS_FILE=$first_data;
	                }case 'HOST_PEERS_FILE'
        	        {
				$HOST_PEERS_FILE=$first_data;
                	}case 'INCIDENTS_DIR'
	                {
				$INCIDENT_PATH=$first_data
        	        }case 'NETS_TO_MONITOR'
                	{
				@NETS_TO_MONITOR=@data;
	                }case 'SCAN_BUCKET'
        	        {
				if(scalar(@var)>1 and $var[1])
				{
					
					my $time=eval($var[1]);
					$SCAN_TIME_BUCKETS{$time}=$first_data;
				}
                	}
			case 'INCIDENT_ALERT'
			{
				 if(scalar(@var)>1 and $var[1])
                                {
					$INCIDENT_ALERT{$var[1].'.'.$line_index}=$first_data;
				}
			}
			case 'WEIGHT'
			{
				 if(scalar(@var)>1 and $var[1])
                                {
					$WEIGHTS{$var[1]}=$first_data;
				}
			}
			case 'SQL_INSERT_ID'
			{
				$SQL_INSERT_ID=$first_data;
			}
			else
			{
				Warn($C_LOG, "Main config Unknown variable $first_var $line_index\n");
			}
		}
		
	}
}}

#load valid peers for a host, from conf file
sub loadHostPeers
{

my @lines=readFile($HOST_PEERS_FILE,'HOST_PEERS');

debug($C_LOG,"Loading valid peers for hosts from config file");

if(!isValid(@lines))
{
	return;
}
@HOST_PEERS_TABLE=();

foreach my $line (@lines)
{
	my $talk_to_info=parseFileLine($line,'<=>');
        if(defined($talk_to_info))
        {
                my @from_array=@{$talk_to_info->{L}};
		my @to_array=@{$talk_to_info->{R}};
		#go for each item on left side and make it a peer to the
		#whole right side
		foreach my $from_host(@from_array)
		{
			debug($C_LOG,"Left side Peer: $from_host");
			loadToPeersFromHost($from_host,\@to_array);
		}
	}
}

}
#go through the whole right side
#and peer it with the item on left side
sub loadToPeersFromHost
{
	my($from_host,$to_hosts_ref)=@_;
	foreach my $to_host(@{$to_hosts_ref})
	{

		addToHostPeersTable(lc($from_host),lc($to_host));
	}
	debug($C_LOG,"Total Peers Loaded: ".scalar(@HOST_PEERS_TABLE));
}


sub addToHostPeersTable
{
	my($from,$to)=@_;
	#reverse if talking is ok from->to,then its ok to->from
	my $from_key=$from.','.$to;
	my $to_key=$to.','.$from;
	warnNoHostKnown($from,$to);
	push @HOST_PEERS_TABLE,$from_key;
	push @HOST_PEERS_TABLE,$to_key;

}

sub warnNoHostKnown
{
	foreach  my $host_name( @_)
	{
		if(!defined($KNOWN_HOSTS_TABLE{$host_name}))
		{
			Warn($C_LOG, "WARN: $host_name is not defined in Known Hosts file");
		}

	}
}

#loads know hosts from the file
sub loadKnownHosts
{

	my @lines=readFile($KNOWN_HOSTS_FILE,'KNOWN_HOSTS');

	if(!isValid(@lines))
	{
		debug($C_LOG,"Known Hosts file, was not changed");
		return;
	}

	%KNOWN_HOSTS_TABLE=();

	foreach my $line (@lines)
	{
		my $host_info=parseFileLine($line,'=>');
		if(defined($host_info))
		{
			my $host_name=${@{$host_info->{L}}}[0];
			my $host_ip=${@{$host_info->{R}}}[0];
			my $host_mac=${@{$host_info->{R}}}[1];
			debug($C_LOG, "H: $host_name,I:$host_ip,M:".null($host_mac));
			$KNOWN_HOSTS_TABLE{lc($host_name)}=[$host_ip,fixMAC($host_mac)];
		}
	}

}

#reads a file if it was not changed from last read, otherwise returns undef
my %FILE_CACHE=();
sub readFile
{
my ($path,$name)=@_;
debug($C_LOG,"Attempting to read $path for $name");

$path=abs_path($path);

debug ($C_LOG,"Abs path: $path");
if(!$path)
{
die "Unable to parse PATH $path for $name\n";
}

#get modification time of the file
  my  ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
    $atime,$mtime,$ctime,$blksize,$blocks)
    = stat($path);

if(!defined($mtime))
{
	 die "File $path doesn't exist $name\n";
}
#see if we already read the file
my $old_mtime=$FILE_CACHE{$path};
#if so,see if file was changed since last read
if(defined($old_mtime) && $old_mtime>=$mtime)
{
	#if it was NOT return undef
	return undef;
}

debug($C_LOG,"File was changed on $mtime, rereading");

#if new file or changed then we read it
open FILE, "<$path" or die $!;
my @out=<FILE>;
close FILE;

debug($C_LOG,"Lines read: ".scalar(@out));
#and Update cache accordingly
$FILE_CACHE{$path}=$mtime;

#do we expect to return just plain text? -- glue the lines
if(!wantarray)
{
	return join '',@out;

}else #if we want array broken by lines then do so
{
	return @out;
}

}

#Given the line, it splits it up in two halfs based on delim, and on each 
#half it breaks it up by commas
sub parseFileLine
{
my ($line,$delim)=@_;

chomp $line;

$line=stripComments($line);
chomp $line;
if(!isValid($line))
{
return undef;
}

#if delim is specified, we split it on right and left half
if(defined($delim))
{
	my @right_left=split  $delim,$line;

	#then split each side on commas
	my @l=split (/,/,$right_left[0]);
	my @r=undef;
	if(defined($right_left[1]))
	{
		@r=split (/,/,$right_left[1]);
	}
	my %out=(
	'L'=>[trimArray(@l)],
	'R'=>[trimArray(@r)]
	);

	return \%out;
}else # if no delim specified,just break line on commas
{
	return split /,/,$line;
}

}

#given a line ,removes comments marked by pound sign
sub stripComments
{
my($line)=@_;
#when comment starts
my $com_indx=index $line,'#';

if($com_indx>=0)
{
	#remove everything after comment start
	my $ret= substr $line, 0,$com_indx;
	return $ret;
}
return $line;

}

#goes through all items in array, and trims each one
#used for file parsing
sub trimArray
{
my @out=();

if(!isValid(@_))
{
	return undef;
}

foreach my $item (@_)
{
	if(!defined($item))
	{
		return undef;
	}
	
	chomp $item;
	push @out,trim($item);
}

return @out;
}

#============================ Useful Util ===============

#format unix time
sub timeStr
{
	my($time_sec)=@_;
	return time_format($DATE_TIME_FORMAT, $time_sec);
}

sub trim($)
{
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

#normalizes MAC address removing spaces,dashes,colons,etc..
sub fixMAC
{
my($mac)=@_;
if(!defined($mac) or trim($mac) eq '')
{
return undef;
}

$mac =~ s/[:|-]//g;
return lc($mac);
}

#tryes to figure out if the input, either scalar or array, is valid
#defined,has values,not empty,etc..
sub isValid
{
my $have_val= @_ && scalar(@_)>0 && defined($_[0]);
#return $have_val;
if(!$have_val or scalar(@_)>1)
{
return $have_val;
}else
{
my $x=$_[0];
return not($x=~ /^\s*$/);
}

}

#Given an IP or Net mask,creates IP Object
my %IP_OBJECTS_CACHE=();

#puts it in cache useful optimization
sub getIPObject
{
my($ip)=@_;
my $obj=$IP_OBJECTS_CACHE{$ip};
if(!defined($obj))
{
 $obj=new Net::IP($ip);
 $IP_OBJECTS_CACHE{$ip}=$obj;
}
return $obj;
}


#Takes Net::IP Objects checks if IP is in Network
sub isIPInNetwork
{
my($network,$ip)=@_;

#mask out the ip, and see if it equals to IP part of the network
return ($ip->binip() & $network->binmask()) eq $network->binip();
}

sub macPartialMatch
{
my($file_mac,$request_mac)=@_;
 my $i=index $request_mac,$file_mac,0;
return $i==0;
}
#======== Pretty Printing ===================

#Given IP address,returns its host name from file,if its know
#otherwise returns an IP, used for pretty-printing
sub findHostInFile
{
my($ip)=@_;
my $out=getKnownHostByIP($ip);
return $out if($out);
return $ip;
}


#pretty printing of an item
#if shouldprinTime is set, then will print TIMe of item
#instead of Time_delta
#extended will print out attributes like nmap,dark space,etc..
sub distItem2String
{
my($item,$shouldPrintTime,$extended)=@_;
my $dist_ip=$item->{'DIST_IP'};
my $out= $dist_ip.' ';
my $delta=$item->{'TIME_DELTA'};
if(defined($shouldPrintTime) && $shouldPrintTime>0)
{
 $out=$out.$item->{'TIME'};
}elsif(defined($delta))
{
$out=$out.time2string($item->{'TIME_DELTA'});
}

my $extended_str='';
if($extended)
{
	if($item->{'DARKSPACE'})
	{
		
		$extended_str=$extended_str.'D';
	}
        if($item->{'WRONG_PEER'})
        {
                $extended_str=$extended_str.'P';
        }
        if($item->{'IS_NMAP'})
        {
                $extended_str=$extended_str.'N';
        }
	if($item->{'HOST_NO_MATCH'})
	{
		$extended_str=$extended_str.'M';
	}
	
}
if($extended)
{
	my $hostname=findHostInFile($dist_ip);
	if($hostname ne $dist_ip)
	{
	$out=$out.' ('.$hostname.')';
	}	
}
if($extended_str)
{
	$out=$out." [$extended_str]";
}
return $out;
}



#print the WHOLE resuest table
sub printReqTable
{
foreach my $src_ip (sort keys %REQS_BY_SRC) 
{ 
my $dist_chain_str= distChain2String($REQS_BY_SRC{$src_ip});
if($dist_chain_str ne '')
{
	print "$src_ip =>[ $dist_chain_str ]\n"; 
}

}

}

#given Chain ref, break_no is number of items to print before new-line
#extended - print extended attributes like Wrong Peer,NMap,etc..
sub distChain2String
{
my ($dist_chain_ref,$break_no,$extended)=@_;
my @dist_chain=@$dist_chain_ref;
my @dist_chain_copy=@dist_chain;
my @chain_string=();
shift @dist_chain_copy;
my $out='';
my $count=0;
my $break='';
foreach my $item_ref (@dist_chain_copy)
{
	
	my $comma='';
	if($count>0 && $count<scalar(@dist_chain_copy))
        {
                $comma=', ';
        }
	$out=$out.$comma.$break.distItem2String($item_ref,undef,$extended);
	$count++;
	$break='';
	if(defined($break_no) && ($count%$break_no==0))
        {
                $break="\n";
        }
}
return $out;
}


#pritty print time,given time
#return seconds,minutes,hors etc..
sub time2string
{
my ($time)=@_;
my $days=$time/(3600*24);
my $hours=$time/3600;
my $minutes=$time*(0.16); #very weird div by anything gives compiler
#errors
if(int ($days)>0)
{
 return round($days).'d';
}
elsif(int($hours)>0)
{
return round($hours).'h';

}elsif (int($minutes)>0)
{

return round($minutes).'m';
}

return $time.'s';

}

sub round
{
my ($f)=@_;
return  sprintf("%.2f", $f);
}

#Used for pretty printing
sub null
{
my($x)= @_;
if(!$x)
{
return "<null>";
}
return $x;
}

sub ipList2String
{

my($ref)=@_;
my $out='';
my @IPS=@{$ref};
foreach my $ip ( @IPS)
    {
      $out=$out.findHostInFile($ip).',';
     }
return $out;
}


#======== LOGGING ==============================
my %LOGGERS=();

#caching for Categories, not sure if we need them
#Subsys is the name of category
sub getMyLogger
{
	my($subsys)=@_;
	my $logger=$LOGGERS{$subsys};
	if(!$logger)
	{
		$logger=get_logger($subsys);
		$LOGGERS{$subsys}=$logger;
	}
return $logger;

	
}

#all the same just have to ajust our depth other wise
#logs will come from the function like info,debug
#instead of their callers
sub info
{
	my($subsys,$msg)=@_;
	my $mylogger=getMyLogger($subsys);
	$Log::Log4perl::caller_depth++;
	$mylogger->info($msg);
	$Log::Log4perl::caller_depth=0;
}

sub Warn
{
        my($subsys,$msg)=@_;
        my $mylogger=getMyLogger($subsys);
        $Log::Log4perl::caller_depth++;
        $mylogger->warn($msg);
        $Log::Log4perl::caller_depth=0;
}

sub debug
{
        my($subsys,$msg)=@_;
        my $mylogger=getMyLogger($subsys);
        $Log::Log4perl::caller_depth++;
        $mylogger->debug($msg);
        $Log::Log4perl::caller_depth=0;
}

sub error
{
        my($subsys,$msg)=@_;
        my $mylogger=getMyLogger($subsys);
        $Log::Log4perl::caller_depth++;
        $mylogger->error($msg);
        $Log::Log4perl::caller_depth=0;
}
