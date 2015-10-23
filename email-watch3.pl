#!/usr/bin/perl
use Term::ANSIColor qw (:constants);
use Time::Local;
use strict;
use warnings;
use File::Tail;

my $version="v3.0.0";
# This Version:
#   Running via Tail - in progress
#   Increasing modularity - done
#   refactoring with objects
# TO DO:
#   option for only showing the last hour/day/week of result
#   option to only show the last 'n' results
#   Continuous running mode which uses tail.  probably needs a complete rewrite
#   option to hide the QID
#   tracking the initial contact which uses a 5 digit QID
#   option to have a numerical summary of all emails received
#       local, non-local, total, ham, spam per hour, day, week
#   emphasise mail from certain email addresses (e.g. family)
#
#
my @options=@ARGV;
my $verbose=0;
my $reports=0;
my $all=0;
my $last=0;
print "Options:\n";
foreach my $option (@options) {
    chomp $option;
    print "\t$option\n";
    if ( $option eq "verbose" ) {$verbose=1;}
    if ( $option eq "reports" ) {$reports=1;}
    if ( $option eq "all" ) {$all=1;}
    if ( $option eq "last" ) {$last=1;}
}

my @logs=("/var/log/maillog.1.gz", "/var/log/maillog.1", "/var/log/maillog");
if ( $all==1) { @logs=`ls /var/log/maillog*`;}
if ( $last==1) { @logs=("/var/log/maillog.4.gz", "/var/log/maillog.3.gz", "/var/log/maillog.2.gz", "/var/log/maillog.1.gz", "/var/log/maillog");}
#my @logs=`ls /var/log/maillog`;
my %times;
my %timestamp;
my %from;
my %to;
my %months=( "Jan"=>0, "Feb"=>1, "Mar"=>2, "Apr"=>3, "May"=>4, "Jun"=>5,
    "Jul"=>6, "Aug"=>7, "Sep"=>8, "Oct"=>9, "Nov"=>10, "Dec"=>11 );
my %size;
my %relay;
my %to_relay;
my %from_relay;
my %ip_addr;
my %host;
my %reject;
my %dsn;
my %delay;
my %ntries;
my %transaction_completed;
my %spam_score;
my %required_score;
my %spam_tests;
my %spam_report;
my %stat;
my %invalid_userids;
my $year = `date +%Y`;
my $runtime=`date +%s`;
my %ctladdr;
my %connecting_hosts;
my %authfailures;
my %lastauthfailure;;
my %lastconnection;;

my %connecting_hosts;
my %connections;
# Parse the log files first
foreach my $log (@logs) {
    chomp $log;
    my @lines;
    if ( $log =~ /\.gz$/) {
        @lines=`gunzip -c $log`;
    } else {
        @lines=`cat $log`;
    }
    foreach my $line (@lines) {
        chomp $line;
        print GREEN, "$line\n" if $verbose;
        &parse_5_digit_pid($log, $line);
        &parse_14_digit_pid($log, $line);
    }
}
print "\n";

# report on the invalid usernames
foreach my $userid (sort keys %invalid_userids) {
    if (exists($invalid_userids{$userid})) {
        if ($invalid_userids{$userid} > 1) {
            print "\t$invalid_userids{$userid} attempts to deliver to $userid\n";
        }
    }
}

# report on the connecting Hosts
my $limit = 100;
print "Hosts with more than $limit connections:\n";
foreach my $host (sort keys %connecting_hosts){
    if (exists($connecting_hosts{$host})) {
        if ($connecting_hosts{$host} > $limit ) {
            print "\t$connecting_hosts{$host} connections from $host. Last at $lastconnection{$host}\n";
        }
    }
}

# report on the auth failures
# print "Authentication failures:\n";
foreach my $host (sort {$lastauthfailure{$a} cmp $lastauthfailure{$b} } keys %authfailures) {
    if (exists($authfailures{$host})) {
        #if ($invalid_userids{$userid} > 1) {
            print "\t$authfailures{$host} authentication failures from $host. Last at $lastauthfailure{$host}.";
        add_host_to_iptable($iptable_name, $host);
        #print "\techo \"ALL:\t$host\" >>/etc/hosts.deny\n";
        print "\n";
        #}
    }
}



#print "now tailling...";
# Then tail -f the maillog
#my $log = "/var/log/maillog";
#my $tail = File::Tail->new($log);
#while (defined(my $line=$tail->read)) {
#   chomp $line;
#   print GREEN, "$line\n" if $verbose;
#   &parse_5_digit_pid($log, $line);
#   &parse_14_digit_pid($log, $line);
#}

#exit if $verbose;
#sleep 20 if $verbose;
print "\n";

#foreach my $qid (sort {$timestamp{$a} <=> $timestamp{$b} } keys %timestamp) {
#foreach my $qid (sort by_timestamp_and_qid keys %timestamp) {
#   print WHITE, "\n";
#   print WHITE, "$qid ";
#   #print WHITE, "$qid " if $verbose;
#   print WHITE, "$times{$qid} " if exists($times{$qid});
#   print GREEN, "$ip_addr{$qid} " if exists($ip_addr{$qid});
#   print GREEN, "[$from_relay{$qid}] " if exists $from_relay{$qid};
#   print GREEN, "-> " if exists($to_relay{$qid}) && exists($from_relay{$qid});;
#   print GREEN, "[$to_relay{$qid}] " if exists $to_relay{$qid};
#   print CYAN, "$from{$qid} -> " if exists $from{$qid};
#   print CYAN, "$to{$qid} " if exists $to{$qid};
#   print CYAN, "($size{$qid} bytes) " if exists $size{$qid};
#   print GREEN, "$stat{$qid}" if exists $stat{$qid};
#   if ( exists($spam_score{$qid}) ) {
#       print " $spam_score{$qid}/$required_score{$qid}";
#       if ( exists($spam_report{$qid}) ) {
#           print YELLOW, "$spam_report{$qid}" if $reports;
#       } else {
#           print YELLOW, "\n\t\t$spam_tests{$qid}" if $reports;
#       }
#   }
#}

#print "\n", RESET;
#my $events = keys %timestamp;
#my $emails = keys %times;
#my $spam = keys %spam_score;
##my $realmail = keys %realmails;
#print "Sent: Total events:\t$events\n";
#print "Sent: Total emails:\t$emails\n";
##print "Sent: Real emails:\t$realmail\n";
#print "Sent: Spam emails:\t$spam\n";


### subroutines
sub by_timestamp_and_qid {
    $timestamp{$a} <=> $timestamp{$b} or
    $a cmp $b
}

sub parse_5_digit_pid() {
    # Parse for the 5 digit PID (can be 4 digits too)
    my $log = shift;
    my $line = shift;
    if ( $line =~ /^([A-Z][a-z]{2} [0-9 ]{2} [0-9:]{8}) (.*) sendmail\[([0-9]+)\]: (.*)$/) {
        my $date=$1;
        my $hostname=$2;
        my $pid=$3;
        my $data=$4;
        $pid =~ sprintf ( "%5s", $pid );
        #$pid=$log.$pid;
        if ( $log =~ /\.gz$/) { $pid.=".1"; } else { $pid.=".0"; }
        print RED, "\tdate:\t$date\n" if $verbose;
        print RED, "\thostname:\t$hostname\n" if $verbose;
        print RED, "\tpid:\t$pid\n" if $verbose;
        print RED, "\tdata:\t$data\n" if $verbose;
        if ( $data =~ /NOQUEUE: connect from (.*)(\[[0-9.]+\]).*$/ ){
            #this never has the qid, but we can count connections
            my $ip_addr=$2;
            my $host=$1;
            #my $times{$pid}=$date;
            my ($month, $day, $time) = split /\s+/, $date, 3;
            my ($hours, $minutes, $seconds) = split /:+/, $]time;
            my $mnum=$months{$month};
            my $timestamp=timelocal($seconds, $minutes, $hours, $day, $mnum, $year-1900);
            $connecting_hosts{$ip_addr}++;
            $connections{$pid} = Connection->new($pid, $ip_addr, $host, $timestamp)
        }
        if ( $data =~ /NOQUEUE: tcpwrappers (.*)(\[[0-9.]+\]) rejection$/ ) {
            $connections{$pid}->{reject_reason} = "tcpwrappers rejection";
        }
        if ( $data =~ /STARTTLS/)
    }
    # build a table of imap connections
    if ( $line =~ /^([A-Z][a-z]{2} [0-9 ]{2} [0-9:]{8}) (.*) imapd\[([0-9]+)\]: (.*)$/) {
        my $date=$1;
        my $hostname=$2;
        my $pid=$3;
        my $data=$4;
        $pid =~ sprintf ( "%5s", $pid );
        #$pid=$log.$pid;
        if ( $log =~ /\.gz$/) { $pid.=".1"; } else { $pid.=".0"; }
        print RED, "\tdate:\t$date\n" if $verbose;
        print RED, "\thostname:\t$hostname\n" if $verbose;
        print RED, "\tpid:\t$pid\n" if $verbose;
        print RED, "\tdata:\t$data\n" if $verbose;
        if ( $data =~ /imaps SSL service init from \[([0-9.]+)\]/) {
            my $ip_addr = $1;
        }
        if ( $data =~ /(Authenticated|Logout|Killed \(lost mailbox lock\)) user=(.*) host=(.*) \[([0-9.]+)\]/) {
            my $action = $1;
            my $userid = $2;
            my $hostname = $3;
            my $ip_addr = $4;
        }
    }
}

sub parse_14_digit_pid() {
    # Parse for the 5 digit PID
    my $log = shift;
    my $line = shift;
    if ( $line =~ /^([A-Z][a-z]{2} [0-9 ]{2} [0-9:]{8}) (.*) sendmail\[([0-9]*)\]: ([a-zA-Z0-9]{9}[0-9]{5}): (.*)$/) {
        my $date=$1;
        my $hostname=$2;
        my $pid=$3;
        my $qid=$4;
        my $data=$5;
        print RED, "\tdate:\t($qid)\t$date\n" if $verbose;
        print RED, "\thostname:\t($qid)\t$hostname\n" if $verbose;
        print RED, "\tpid:\t($qid)\t$pid\n" if $verbose;
        print RED, "\tqid:\t($qid)\t$qid\n" if $verbose;
        print RED, "\tdata:\t($qid)\t$data\n" if $verbose;
        my ($month, $day, $time) = split /\s+/, $date, 3;
        my ($hours, $minutes, $seconds) = split /:+/, $time;
            my $mnum=$months{$month};
        my $timestamp=timelocal($seconds, $minutes, $hours, $day, $mnum, $year-1900);
        if ($timestamp>$runtime) {
            print "\t$timestamp in the future!  Assuming " if $verbose;
            $timestamp=timelocal($seconds, $minutes, $hours, $day, $mnum, $year-1901);
            print "\t$timestamp \n" if $verbose;
            }
        $timestamp{$qid}=$timestamp;
        $transaction_completed{$qid} = 0 if not(exists($transaction_completed{$qid}));

        if ( $data =~ /from=([^ ]*),/ ) {
            $from{$qid}=$1;
            $from{$qid}=~s/[\<\>]//g;
            $times{$qid}=$date;
            print YELLOW "\tfrom:\t($qid)\t$from{$qid}\n" if $verbose;
            $transaction_completed{$qid} += 0.5;
        }
        if ( $data =~ /^to=([^ ]*),/ ) {
            if ( exists($to{$qid})) {
                $to{$qid}.=", $1";
            } else {
                $to{$qid}=$1;
            }
            $to{$qid}=~s/[\<\>]//g;
            $times{$qid}=$date;
            print YELLOW "\tto:\t($qid)\t$to{$qid}\n" if $verbose;
        }
        if ( $data =~ /ruleset=check_rcpt, arg1=([^ ]*),/ ) {
            $to{$qid}=$1;
            $to{$qid}=~s/[\<\>]//g;
            $times{$qid}=$date;
            print YELLOW "\tto:\t($qid)\t$to{$qid}\n" if $verbose;
        }
        if ( $data =~ /reject=(.*)$/ ) {
            $stat{$qid}=$1;
            $times{$qid}=$date;
            print YELLOW "\tstat1:\t($qid)\t$stat{$qid}\n" if $verbose;
        }
        if ( $data =~ /<([^>]*)>...  550 (.*)$/ ) {
            $to{$qid}=$1;
            $stat{$qid}=$2;
            $times{$qid}=$date;
            print YELLOW "\tstat2:\t($qid)\t$stat{$qid}\n" if $verbose;
            if ($stat{$qid} =~ /Address (.*) does not exist at this domain/) {
                $invalid_userids{$to{$qid}}++;
            }
            $transaction_completed{$qid} += 0.5;
        }
        if ( $data =~ /stat=(.*)/ ) {
            $stat{$qid}=$1;
            $times{$qid}=$date;
            print YELLOW "\tstat3:\t($qid)\t$stat{$qid}\n" if $verbose;
            if ( $stat{$qid} =~ /Sent.*Message accepted for delivery/) {
                $transaction_completed{$qid} += 1;
            }
        }
        if ( $data =~ /size=(.*), class/ ) {
            $size{$qid}=$1;
            $times{$qid}=$date;
            print YELLOW "\tsize:\t($qid)\t$size{$qid}\n" if $verbose;
        }
        if ( $data =~ /to=\<.*relay=.*\[([0-9.]+)\]/ ) {
            $to_relay{$qid}=$1;
            $times{$qid}=$date;
            print YELLOW "\tto_relay:\t($qid)\t$to_relay{$qid}\n" if $verbose;
        }
        if ( $data =~ /from=\<.*relay=.*\[([0-9.]+)\]/ ) {
            $from_relay{$qid}=$1;
            $times{$qid}=$date;
            print YELLOW "\tfrom_relay:\t($qid)\t$from_relay{$qid}\n" if $verbose;
        }
        if ( $data =~ /^Milter add: header: X-Spam-Report: (.*)$/){
            $spam_report{$qid}=$1;
            #$spam_report{$qid} =~ s/(["*\/])/\\$1/g;
            $spam_report{$qid} =~ s/\\n/\n/g;
            $spam_report{$qid} =~ s/\\t/\t\t/g;
        }
        if ( $data =~ /^Milter add: header: X-Spam-Status: Yes, score=([0-9.]+) required=([0-9.]+) tests=(.*)$/){
            $spam_score{$qid}=$1;
            $required_score{$qid}=$2;
            $spam_tests{$qid}=$3;
            $spam_tests{$qid} =~ s/\\n/\n/g;
            $spam_tests{$qid} =~ s/\\t/\t\t/g;
        }
        if ( $data =~ /^Milter change \(add\): header: X-Spam-Status: Yes, score=([0-9.]+) required=([0-9.]+) tests=(.*)$/){
            $spam_score{$qid}=$1;
            $required_score{$qid}=$2;
            $spam_tests{$qid}=$3;
            $spam_tests{$qid} =~ s/\\n/\n/g;
            $spam_tests{$qid} =~ s/\\t/\t\t/g;
        }
        if ( $data =~ /([^ ] )*\[([0-9.]+)\] (\(may be forged\) )*(did not .*)/ ) {
            $from_relay{$qid}=$2;
            $stat{$qid}=$4;
            $times{$qid}=$date;
            print YELLOW "\tstat4:\t($qid)\t$stat{$qid}\n" if $verbose;
            $transaction_completed{$qid}+=1;
        }
    if ( $data =~ /AUTH failure \(LOGIN\): .*, relay=\[([0-9.]+)\]$/ ) {
        my $host = $1;
        $authfailures{$host}++;
        $lastauthfailure{$host} = $date;
        # do something with this?
    }
        if ( $data =~ /done; delay=([0-9:]+), ntries=([0-9]+)/ ) {
            $delay{$qid}=$1;
            $ntries{$qid}=$2;
            print YELLOW "\tdone;\t($qid)\t$delay{$qid}\t$ntries{$qid}\n" if $verbose;
            $transaction_completed{$qid}+=1;
        }
        if ( ($transaction_completed{$qid}>=1) &&
            !($stat{$qid} =~ /did not issue MAIL/) &&
            !($stat{$qid} =~ /does not exist at this domain/)){
            print WHITE, "\n";
            print WHITE, "($transaction_completed{$qid}) $qid ";
            #print WHITE, "$qid " if $verbose;
            print WHITE, "$times{$qid} " if exists($times{$qid});
            print GREEN, "$ip_addr{$qid} " if exists($ip_addr{$qid});
            print GREEN, "[$from_relay{$qid}] " if exists $from_relay{$qid};
            print GREEN, "-> " if exists($to_relay{$qid}) && exists($from_relay{$qid});;
            print GREEN, "[$to_relay{$qid}] " if exists $to_relay{$qid};
            print CYAN, "$from{$qid} -> " if exists $from{$qid};
            print CYAN, "$to{$qid} " if exists $to{$qid};
            print CYAN, "($size{$qid} bytes) " if exists $size{$qid};
            print GREEN, "$stat{$qid}" if exists $stat{$qid};
            if ( exists($spam_score{$qid}) ) {
                print " $spam_score{$qid}/$required_score{$qid}";
                if ( exists($spam_report{$qid}) ) {
                    print YELLOW, "$spam_report{$qid}" if $reports;
                } else {
                    print YELLOW, "\n\t\t$spam_tests{$qid}" if $reports;
                }
            print "\n", RESET;
            # remove the objects ?
            }
        }
    }
}

package connecting_host;
sub new {
    my $class = shift;
    my $self = {
        pid => shift, # five digit PID
        ipaddr => shift, # ip address
        hostname =>shift, # hostname
        attempts => shift, # how many times
    };
    bless $self, $class;
    return $self;
}

package Connection;
sub new {
    my $class = shift;
    my $self = {
        pid => shift, # five digit PID
        ipaddr => shift, # ip address
        hostname =>shift, # hostname
        timestamp =>shift,
        reject_reason => "",
    };
    bless $self, $class;
    return $self;
}

package mail_transaction;
sub new {
    my $class = shift;
    my $self = {
        pid => shift, # 14 digit PID
    };
    bless $self, $class;
    return $self;
}
