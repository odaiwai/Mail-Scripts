#!/usr/bin/perl
use strict;
use warnings;

# script to read in the /etc/hosts.deny (or allow) and make sure there's no
# duplicates in there.
#
# hosts.deny, looks like this:
# some comment
#smtp : 190.42.88.80 : spawn /usr/bin/echo "IP Address blocked for unauthorised access attempts"
#smtp : 197.156.77.139 : spawn /usr/bin/echo "IP Address blocked for unauthorised access attempts"
#smtp : 94.102.52.31 : spawn /usr/bin/echo "IP Address blocked for unauthorised access attempts"
#ssh : 114.112.32.0/19 : spawn /usr/bin/echo "IP Address blocked for unauthorised access attempts"
#ssh : 182.96.0.0/12 : spawn /usr/bin/echo "IP Address blocked for unauthorised access attempts"
#
# dave o'brien 2015/07/27

my $verbose = 0;
my @files = "/etc/hosts.deny";
my %services;
my %ipaddrs;
foreach my $file (@files) {
    print "FILE: $file\n" if $verbose;
    my @outputs; # array to hold the output lines
    open (my $inputh, "<", $file) or die "Can't open $file\n";
    while (my $line = <$inputh>) {
        chomp $line;
        print "\t$line\n" if $verbose;
        if ($line =~ /^#/) {
            # comment - preserve in place
            push @outputs, $line;
        } else {
            my @matches = lc($line) =~ /^([a-z0-9]+) : ([0-9.\/]+)( : (.*))*$/;
            #print "\tMatches: $#matches\n" if $verbose;
            my $service = $1;
            my $ipaddr = $2;
            my $action = $3 if ($3);
            $ipaddrs{$ipaddr}++;
            $services{$service}++;
                print "\tBlock access from $ipaddr on $service " if $verbose;
            if ($3) {
                print "($action)" if $verbose;
            }
            print "\n" if $verbose;
            if ($ipaddrs{$ipaddr} == 1) {
                push @outputs, $line;
            } else {
                print "\tDuplicate. Ignoring.\n" if $verbose;
            }

        }
    }
    close $inputh;
    # print the output
    open (my $outputh, ">", $file) or die "Can't open $file\n";
    foreach my $line (@outputs) {
        print "$line\n" if $verbose;
        print $outputh "$line\n";
    }
    close $outputh;
}
