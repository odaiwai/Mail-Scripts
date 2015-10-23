#!/usr/bin/perl
use Term::ANSIColor qw (:constants);
use DBI;
use strict;
use warnings;

my $verbose=0;
my @logfiles=`ls -t /var/log/maillog /var/log/maillog.1.gz`;
if ( $ARGV[0] = "all" ) {
    @logfiles=`ls -t /var/log/maillog*`;
}
my %events;
my %files;
my %sources;
my %last_source;
my %entries;
my $iptable="SMTP_ATTACK";
my @ports=("25", "465","587");
my %login_attempts;
my %accepted_users;
my %accepted_users_by_reason;
my %rejected_users;
my %rejected_users_by_reason;
my %accepted_addresses;
my %accepted_addresses_by_reason;
my %rejected_addresses;
my %rejected_addresses_by_reason;
my %attack_matrix;
my %ports;
my %protocols;
my %reasons;

my $result = make_iptable($iptable, $ports);
#check if out iptable exists and make it it doesn't.
#each sub category of rejection should have it's own table.
sub make_iptable {
    my $iptable = shift;
    my $iptable_exists  =`/sbin/iptables -n -L $IPTABLE`;
    chomp $iptable_exists;
    if ( $iptable_exists eq "" ) {
        print GREEN, "$IPTABLE doesn't exist.  Creating now...", RESET;
        system "/sbin/iptables -N $IPTABLE";
        system "/sbin/iptables -A INPUT -p all --dport 22 -j $IPTABLE";
        print "\n";
    } else {
        print GREEN, "$IPTABLE exists.  Reading in entries now...\n", RESET;
        my @entries = `/sbin/iptables -n -L $IPTABLE`;
        foreach my $entry (@entries) {
            chomp $entry;
            print BLUE, "\t$entry\n", RESET if $verbose;
            if ( $entry =~ /^REJECT\s+tcp\s+[-]+\s+([0-9.]+)\s+([0-9.\/]+)\s+(.*)$/ ) {
                my $source=$1;
                my $dest=$2;
                $entries{$source}++;
                print GREEN, "\tiptable entry: $source\n", RESET;
            }
        }
    }
}
#parse through the logfiles and collect statistics, etc.
foreach my $log (@logfiles) {
    chomp $log;
    print "$log...\n";
    if ( $log =~ /\.gz$/){
        open LOG," gunzip -c $log |";
    } else {
        open LOG,"<$log";
    }

    while (my $line=<LOG>) {
        chomp $line;
        print BLUE, "$line\n", RESET if $verbose;
        if ( $line =~ /^([A-Z][a-z][a-z]) ([ 0-9][0-9]) ([0-9:]{8}) (.*) (.*]:) (.*)$/) {
            my $month=$1;
            my $day=$2;
            my $time=$3;
            my $hostname=$4;
            my $pid=$5;
            my $message=$6;
            print GREEN, "$month | $day | $time | $hostname | $pid | " if $verbose;
            print RED, "$message\n", RESET if $verbose;
            # check for ssshd messages
            if ( $pid =~ /^sshd/ ) {
                # Successful logins
                if ($message =~ /Accepted (publickey|password) for (.*) from (.*) port ([0-9]+) (.*)$/) {
                    my $reason = "Accepted $1";
                    my $user = $2;
                    my $address = $3;
                    my $port = $4;
                    my $protocol = $5;
                    $reasons{$reason}++;
                    $accepted_users{$user}++;
                    $accepted_users_by_reason{$user}{$reason}++;
                    $accepted_addresses{$address}++;
                    $accepted_addresses_by_reason{$address}{$reason}++;
                    $ports{$port}++;
                    $protocols{$protocol}++;
                }
                #Unsuccessful logins
                if ( $message =~ /^(Did not receive identification string) from (.*)$/) {
                    my $reason=$1;
                    my $address=$2;
                    $reasons{$reason}++;
                    $rejected_addresses{$address}++;
                    $rejected_addresses_by_reason{$address}{$reason}++;
                    print CYAN, "\tDid not receive identification string from ", YELLOW, "$address", CYAN, ".\n", RESET if $verbose;
                }
                if ( $message =~ /^(Illegal|Invalid) user (.*) from (.*)$/) {
                    my $reason=$1;
                    my $user=$2;
                    my $address=$3;
                    $reasons{$reason}++;
                    $rejected_users{$user}++;
                    $rejected_users_by_reason{$user}{$reason}++;
                    $rejected_addresses{$address}++;
                    $rejected_addresses_by_reason{$address}{$reason}++;
                    $attack_matrix{$address}{$user}++;
                    print CYAN, "\tIllegal or Invalid user ", YELLOW, "$user", CYAN, " from ", YELLOW, "$address", CYAN, ".\n", RESET if $verbose;
                }
                if ( $message =~ /^User (.*) from ([0-9.]+) not allowed because (.*)$/) {
                    my $user=$1;
                    my $address=$2;
                    my $reason=$3;
                    $reasons{$reason}++;
                    $rejected_users{$user}++;
                    $rejected_users_by_reason{$user}{$reason}++;
                    $rejected_addresses{$address}++;
                    $rejected_addresses_by_reason{$address}{$reason}++;
                    $attack_matrix{$address}{$user}++;
                    print CYAN, "\tUnallowed user ", YELLOW, "$user", CYAN, " from ", YELLOW, "$address", CYAN, ".\n", RESET if $verbose;
                }
                if ( $message =~ /^(Failed .*) for (illegal|invalid)* user (\w+) from ([0-9.]+) port ([0-9]+) (ssh[0-9])$/) {
                    my $reason=$1;
                    my $user=$3;
                    my $address=$4;
                    my $port=$5;
                    my $protocol=$6;
                    $reasons{$reason}++;
                    $rejected_users{$user}++;
                    $rejected_users_by_reason{$user}{$reason}++;
                    $rejected_addresses{$address}++;
                    $rejected_addresses_by_reason{$address}{$reason}++;
                    $ports{$port}++;
                    $protocols{$protocol}++;
                    $attack_matrix{$address}{$user}++;
                    print CYAN, "\tFailed password for Illegal or Invalid user ", YELLOW, "$user", CYAN, " from ", YELLOW, "$address", CYAN, ".\n", RESET if $verbose;
                }
                # This one is for genuine users.  Don't block on this one, or it's
                # too easy to lock myself out with a mistyped password.
                # Any attempting to break in is trying hundreds of username/passwords, anyway.
                #if ( $message =~ /^Failed password for ([a-zA-Z0-9-]+) from ([0-9.]+) port ([0-9]+) (ssh[0-9])$/) {
                #   my $user=$1;
                #   my $intruder=$2;
                #   my $port=$3;
                #   my $version=$4;
                #   $users{$user}++;
                #   $probes{$intruder}++;
                #   print CYAN, "\tFailed password for ", YELLOW, "$user", CYAN, " from ", YELLOW, "$intruder", CYAN, ".\n", RESET if $verbose;
                #}
            }
        }
    }
}

#foreach my $user (sort {$users{$a}<=>$users{$b}} %users) {
#   if (exists $users{$user}) {
#       print "$user\t$users{$user} attempts\n";
#   }
#}

#sleep 10;

#foreach my $intruder (sort keys %rejected_addresses) {
#   if ( !($intruder =~ /(192\.168\.[12]\.|202\.82\.77\.4)/) ) {
#       if ( !exists($entries{$intruder}) ) {
#           print "Blocking $intruder for $rejected_addresses{$intruder} attempts to login via the ssh server\n";
#           system "/sbin/iptables -v -t filter -A $IPTABLE -p all -s $intruder  -j REJECT --reject-with icmp-host-prohibited";
#       }
#   }
#}


my %top_users;
my %top_addresses;
#Build and Populate the database Tables
print "Build and Populate the database Tables\n";
my $db = DBI->connect("dbi:SQLite:dbname=/tmp/logcheck_ssh.sqlite","","") or die $DBI::errstr;
$db->do ("BEGIN") or die $db->errstr;
$db->do ("DROP TABLE if exists RejectedUsers") or die $db->errstr;
$db->do ("CREATE TABLE RejectedUsers (Name TEXT, Reason TEXT, Count INT)") or die $db->errstr;
$db->do ("DROP TABLE if exists RejectedIP") or die $db->errstr;
$db->do ("CREATE TABLE RejectedIP (Addr TEXT, Count INT)") or die $db->errstr;
$db->do ("DROP TABLE if exists AttackMatrix") or die $db->errstr;
$db->do ("CREATE TABLE AttackMatrix(Addr TEXT, Name TEXT, Count INT)") or die $db->errstr;
$db->do ("DROP TABLE if exists Reasons") or die $db->errstr;
$db->do ("CREATE TABLE Reasons (Reason TEXT, Count INT)") or die $db->errstr;
$db->do ("COMMIT") or die $db->errstr;

foreach my $user (sort keys %accepted_users) {
    print "USER_ACC: $user logged in $accepted_users{$user} times.\n" if exists($accepted_users{$user});
}
foreach my $user (sort keys %rejected_users) {
    if (exists($rejected_users{$user})) {
        $db->do ("INSERT INTO RejectedUsers (Name, Count) VALUES (\"$user\", $rejected_users{$user})") or die $db->errstr;
        if ($rejected_users{$user} > 500) {
            print "USER_REJ: $user rejected $rejected_users{$user} times.\n";
        }
    }
}foreach my $reason (sort keys %reasons) {
    if (exists($reasons{$reason})) {
        $db->do ("INSERT INTO Reasons (Reason, Count) VALUES (\"$reason\", $reasons{$reason})") or die $db->errstr;
        print "REASONS: $reason $reasons{$reason} times.\n";
    }
}
foreach my $address (sort keys %accepted_addresses) {
    print "IP_ACC: $address logged in $accepted_addresses{$address} times.\n" if exists($accepted_addresses{$address});
}
foreach my $address (sort keys %rejected_addresses) {
    if (exists($rejected_addresses{$address})) {
        $db->do ("INSERT INTO RejectedIP (Addr, Count) VALUES (\"$address\", $rejected_addresses{$address})") or die $db->errstr;
        if ($rejected_addresses{$address} > 5000) {
            print "IP_REJ: $address rejected $rejected_addresses{$address} times.\n";
        }
    }
}
#foreach my $address (sort keys %rejected_addresses) {
#   if (exists($rejected_addresses{$address})) {
#       foreach my $user (sort keys %rejected_users) {
#           if (exists($rejected_users{$user})) {
#               if ( exists($attack_matrix{"$address.$user"})){
#                   $db->do ("INSERT INTO AttackMatrix (Addr, Name, Count) VALUES (\"$address\", \"$user\", ".$attack_matrix{"$address.$user"}.")") or die $db->errstr;
#               }
#           }
#       }
#   }
#}
#foreach my $ports (sort keys %ports) {
#}
#foreach my $protocol (sort keys %protocols) {
#}

# print out the attack matrix
# need the top 20 addresses, and the top 20 usernames

#print "<table>";
#print "\t<tr>";
#foreach my $address (sort {$rejected_addresses{$a}<=>$rejected_addresses{$b}} %top_addresses) {
#   print "\t\t<td>$address ($rejected_addresses{$address})</td>\n";
#   foreach my $user (sort {$attack_matrix{$a}<=>$attack_matrix{$b}} %attack_matrix) {
#       if (exists($attack_matrix{"$address.$user"}) ) {
#           print "\t\t<td>$user (".$attack_matrix{"$address.$user"}.")</td>\n";
#       }
#   }
#   print "\t</tr>\n";
#}
#print "</table>\n";
$db->disconnect;
