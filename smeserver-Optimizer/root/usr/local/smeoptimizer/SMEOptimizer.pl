#!/usr/bin/perl -w
#####################################################################################################################
#
# This script provides interface to SME Optimizer services
#
# This script has been developed
# by Jesper Knudsen at http://smeoptimizer.com
#
# Revision History:
#
# September 26, 2016:      Initial version
# October   9, 2016:       Added support for status and configuration of contact and alerts
# October   13, 2016:      Updated to use HTTPS for reporting.
#                          Now reporting only sender domain rather than entire address
#
#####################################################################################################################

use Getopt::Long;
use strict;
use English;
use LWP::UserAgent;
use DBI;
use JSON;
use Data::Dumper;
use Digest::MD5::File qw(file_md5_hex);
use POSIX qw(strftime);

# SME Server specific
use esmith::db;
use esmith::ConfigDB;
use esmith::AccountsDB;
use esmith::DomainsDB;

use lib '/usr/local/smeoptimizer/';

# Data submission URL
my $SubmitURL = 'https://smeoptimizer.com/report.php';

my %optctl = ();
GetOptions( \%optctl,     "crontab", "debug",     "reportspam", "getconfig", "help",
            "initialize", "status",  "contact=s", "alerts=s",   "VTAPI=s",   "DNSBL=s" );

my $crontab = $optctl{"crontab"} ? 1 : 0;
my $debug   = $optctl{"debug"}   ? 1 : 0;
my $alerts  = $optctl{"alerts"};
my $VTAPI   = $optctl{"VTAPI"};
my $DNSBL   = $optctl{"DNSBL"};

# VirusTotal
my $last_VT_call = 0;

my $dbh = esmith::ConfigDB->open();
if ( not $dbh ) {
    printf("ERROR: Unable to open SME Server configuration database.");
    exit;
}

my $SystemID       = $dbh->get('sysconfig')->prop('SystemID')       || '';
my $ReleaseVersion = $dbh->get('sysconfig')->prop('ReleaseVersion') || '';
my $InstallEpoch   = $dbh->get('sysconfig')->prop('InstallEpoch')   || '';

my $primary_domain = '';

# Find the primary domain so we can se an upgrade notification
FindPrimaryDomain();

my $ModulesAvailable = 1;
eval { require Email::MIME };
if ($@) {
    $ModulesAvailable = 0;
}

if ( $optctl{"DNSBL"} ) {
    PrintHeader();

    my $dnsbl = $optctl{"DNSBL"};
    if ( not( $dnsbl eq 'qpsmtpd' or $dnsbl eq 'sa' ) ) {
        printf("\033[5mERROR: DNSBL must be either \"qpsmtpd\" or \"sa\".\n\n\033[0m");
        exit;
    }

    my $rec = $dbh->get("smeoptimizer");
    if ( not $rec ) {
        $rec = $dbh->new_record( "smeoptimizer", { type => "service" }, { status => "enabled" }, );
    }
    if ( not $rec ) {
        printf("\033[5mERROR: Cannot access or create SMEOptimizer configuration database.\n\n\033[0m");
        exit;
    }
    $rec->set_prop( 'DNSBL', $dnsbl );

    # Need to expand qpsmtpd plugin template and restart qpsmtpd
    my $cmd = `/sbin/e-smith/expand-template /var/service/qpsmtpd/config/peers/0;sv t qpsmtpd`;

    printf("DNSBL configured succesfully.\n");
    exit;
}

if ( $optctl{"VTAPI"} ) {
    PrintHeader();
    if ( length( $optctl{"VTAPI"} ) == 64 ) {
        my $apikey = $optctl{"VTAPI"};

        my $rec = $dbh->get("smeoptimizer");
        if ( not $rec ) {
            $rec = $dbh->new_record( "smeoptimizer", { type => "service" }, { status => "enabled" }, );
        }
        if ( not $rec ) {
            printf("\033[5mERROR: Cannot access or create SMEOptimizer configuration database.\n\n\033[0m");
            exit;
        }
        $rec->set_prop( 'VTAPI', $apikey );

        eval { require VirusTotal };
        if ($@) {
            printf("\033[5mERROR: VirusTotal module not present - run --initialize command!\n\n\033[0m");
            exit;
        }

        my $VT = VirusTotal->new();
        $VT->debug(1) if ($debug);
        $VT->apikey($apikey);

        # Check whether the API key is valid
        my $check = $VT->_connect(1);

        #    printf("VT Check=%s",$check);
        if ( not $check ) {
            printf("\033[5mERROR: VTAPI is not valid according to VirusTotal!\n\n\033[0m");
            exit;
        }

        # Need to expand qpsmtpd plugin template and restart qpsmtpd
        my $cmd = `/sbin/e-smith/expand-template /var/service/qpsmtpd/config/peers/0;sv t qpsmtpd`;

        printf("VirusTotal API key configured succesfully.\n");

    }
    else {
        printf("\033[5mERROR: VTAPI must be 64 characters long.\n\n\033[0m");
    }
    exit;
}

if ( $optctl{"alerts"} ) {
    PrintHeader();
    if ( $optctl{"alerts"} eq 'Yes' or $optctl{"alerts"} eq 'No' ) {
        if ( SetOption( 'Alerts', $optctl{"alerts"} ) ) {
            printf("Alerts configured succesfully.\n");
        }
    }
    else {
        printf("\033[5mERROR: Alerts must be either \"Yes\" or \"No\".\n\n\033[0m");
    }
    exit;
}

if ( $optctl{"contact"} ) {
    PrintHeader();
    if ( validate_email( $optctl{"contact"} ) ) {
        if ( SetOption( 'Contact_Email', $optctl{"contact"} ) ) {
            printf("Contact Email configured succesfully.\n");
        }
    }
    else {
        printf("\033[5mERROR: Contect email not a valid email address.\n\n\033[0m");
    }
    exit;
}

if ( $optctl{"status"} ) {
    BuildTables();
    ShowStatus();
    exit;
}

if ( $optctl{"reportspam"} ) {
    BuildTables();
    CheckAttachments();
    ReportSpam();
    exit;
}

if ( $optctl{"getconfig"} ) {
    BuildTables();
    GetAndUpdateInstallation();
    exit;
}

if ( $optctl{"initialize"} ) {
    PrintHeader();

    if ( not BuildTables() ) {
        printf("\033[5mERROR: Cannot create MySQL tables\n\n\033[0m");

        printf("Remeber that you have to create a MySQL database for the SMEOptimizer services.\n");
        printf("On you command prompt please issue the following commands:\n\n");
        printf("# mysqladmin create smeoptimizer\n");
        printf("# mysql smeoptimizer\n\n");
        printf("From within the MySQL command shell please issue:\n\n");
        printf("GRANT ALL PRIVILEGES ON smeoptimizer.* TO 'smeoptimizer'\@'localhost' IDENTIFIED BY 'password';\n");
        printf("FLUSH PRIVILEGES;\n");
        printf("EXIT;\n");
        printf("\n");
        exit;
    }

    my $pwd = `pwd`;
    $pwd =~ s/[\n\r]//;

    if ( $pwd ne '/usr/local/smeoptimizer' or $0 =~ m/"SMEOptimizer.pl"/ ) {

        printf(
"\033[5mERROR: The SMEOptimizer.pl script must be located in the /usr/local/smeoptimizer folder ($pwd).\n\n\033[0m" );
        exit;
    }

    printf("Trying to register with SMEOptimizer...\n");

    if ( not RegisterOnline() ) {

        printf(
"Online registration for this specific SME server (Version %s), requires you to e-mail below unique indentifier to register\@smeoptimizer.com.\n",
            $ReleaseVersion );
        printf("\n");
        printf( "UUID: %s\n", $SystemID );
        printf("\n");
        printf(
"You will receive a regitration confirmation back within 24 hours and the services will automatically be activated.\n"
        );
    }

    my $rc = GetAndUpdateInstallation();
    exit;
}

Help();

exit;

sub PrintHeader {

    printf("\n         SMEOptimizer - Optimize your SME server\n");
    printf("by SMEOptimizer.com - Copyright (c) 2016-17, all rights reserved.\n");
    printf(" Servers hosted and operated by ScanMailX - www.scanmailx.com\n\n");

}

sub Help {

    PrintHeader();
    printf("Command line options:\n");
    printf("-help:      \t\t Shows this help\n");
    printf("-initialize:\t\t Register and retrieve the configuration and enable the cronjob services.\n");
    printf(
"            \t\t When the registration has been confirmed, then all services will be activated automatically.\n" );
    printf("-status:    \t\t Shows the current status of the SME Optimizer.\n");
    printf(
"-alerts=[Yes|No]:\t Enable checks and alerts for SME server downtime or registration in DNS Blacklist - default Yes.\n"
    );
    printf(
        "-contact=[Email]:\t Set the contact email address where alerts are sent to - default admin\@$primary_domain.\n"
    );
    printf(
          "-VTAPI=[API Key]:\t This is the VirusTotal public API key used to check attachments (will remain local).\n");
    printf(
"-DNSBL=[qpsmtpd|sa]:\t This configures whether the DNS blacklist lookup rejects directly (qpsmtpd) or scores (sa=SpamAssassin)."
    );
    printf("\n");
}

sub FindPrimaryDomain {

    my $domain_db = esmith::DomainsDB->open_ro;
    if ( not $domain_db ) {
        printf("ERROR: Unable to open SME Server domain configuration database.");
        exit;
    }

    # Find the primary domain so we can se an upgrade notification
    my @domains = $domain_db->get_all_by_prop( 'type' => 'domain' );
    foreach my $domain (@domains) {
        if ( ( $domain->prop('SystemPrimaryDomain') || ' no' ) eq 'yes' ) {
            $primary_domain = $domain->key;
            last;
        }
    }
}

sub SetOption {
    my $option = shift;
    my $value  = shift;

    my $browser = LWP::UserAgent->new( 'agent' => 'SMEOptimizer Agent/1.0', );
    $browser->timeout(10);

    my %parameters = ( 'UUID'      => $SystemID,
                       'SetOption' => $option,
                       'Value'     => $value,
    );

    my $response = $browser->post( $SubmitURL, \%parameters );

    if ( $response->is_success ) {
        my $return_code = $response->decoded_content;
        $return_code =~ s/[\n\r]//ig;
        if ( $return_code eq 'OK' ) {
            return 1;
        }
        else {
            printf( "\033[5mERROR: Command not issued - %s\n\n\033[0m", $return_code );
        }
    }
    else {
        my $err = $response->status_line;
        printf("\033[5mERROR: Command not issued - try again later ($err)!\033[0m");
    }
    return 0;

}

sub ShowStatus {

    my $browser = LWP::UserAgent->new( 'agent' => 'SMEOptimizer Agent/1.0', );
    $browser->timeout(10);

    my %parameters = ( 'UUID'       => $SystemID,
                       'ShowStatus' => 1, );

    my $response = $browser->post( $SubmitURL, \%parameters );

    if ( $response->is_success ) {
        my $config_json = decode_json( $response->decoded_content );

        PrintHeader();

        foreach my $entry ( keys %$config_json ) {

            printf( "%-20s:\t%s\n", $entry, $config_json->{$entry} );

        }

        if ( not $ModulesAvailable ) {
            printf( "%-20s:\t%s\n", 'Attachment Filter', 'Disabled - The MIME::Email module is not available' );
        }
        else {
            # Now print the VirusTotal status
            my $VTAPI = $dbh->get('smeoptimizer')->prop('VTAPI') || '';
            printf( "%-20s:\t%s\n",
                    'Attachment Filter',
                    $VTAPI ne ''
                    ? 'Enabled'
                    : 'Disabled - Please provide VirusTotal API key via the VTAPI configuration option' );
        }

        printf("\n");
    }
    else {
        my $err = $response->status_line;
        printf("\033[5mERROR: Couldn't get status right now - try again later!\033[0m");
    }
    return 0;

}

sub RegisterOnline {

    my $browser = LWP::UserAgent->new( 'agent' => 'SMEOptimizer Agent/1.0', );
    $browser->timeout(10);

    my %parameters = ( 'UUID'     => $SystemID,
                       'SMEVer'   => $ReleaseVersion,
                       'SMEIE'    => $InstallEpoch,
                       'Primary'  => $primary_domain,
                       'Register' => 1,
    );

    my $response = $browser->post( $SubmitURL, \%parameters );

    if ( $response->is_success ) {
        my $return_code = $response->decoded_content;
        $return_code =~ s/[\n\r]//ig;
        if ( $return_code eq 'OK' ) {
            printf("Registration successfull!\n\n");
            return 1;
        }
        else {
            printf( "\033[5mERROR: Instant and Online registration failed - %s\n\n\033[0m", $return_code );
        }
    }
    else {
        my $err = $response->status_line;
        printf("\033[5mERROR: Couldn't register right now - try again later!\033[0m");
    }
    return 0;
}

sub GetAndUpdateInstallation {

    my $browser = LWP::UserAgent->new( 'agent' => 'SMEOptimizer Agent/1.0', );
    $browser->timeout(10);

    my %parameters = ( 'UUID'      => $SystemID,
                       'SMEVer'    => $ReleaseVersion,
                       'GetConfig' => 1,
    );

    my $response = $browser->post( $SubmitURL, \%parameters );

    if ( $response->is_success ) {
        my $config_json = decode_json( $response->decoded_content );

        foreach my $entry (@$config_json) {

            if ( $entry->{'File'} ) {
                printf( "File: %s\n", $entry->{'File'} ) if ($debug);

                my $md5sum = 0;
                if ( -e "$entry->{'Filelocation'}/$entry->{'File'}" ) {
                    $md5sum = file_md5_hex("$entry->{'Filelocation'}/$entry->{'File'}");
                }

                if ( $md5sum ne $entry->{'MD5SUM'} ) {

                    printf( "Our=%s - New=%s\n", $md5sum, $entry->{'MD5SUM'} ) if ($debug);

                    if ( -e "$entry->{'Filelocation'}/$entry->{'File'}.tmp" ) {
                        unlink "$entry->{'Filelocation'}/$entry->{'File'}.tmp";
                    }

                    my %parameters = ( 'UUID'    => $SystemID,
                                       'GetFile' => $entry->{'File'}, );

                    my $response = $browser->post( $SubmitURL, \%parameters );

                    if ( $response->is_success ) {

                        if ( open( my $fh, '>', "$entry->{'Filelocation'}/$entry->{'File'}.tmp" ) ) {
                            print $fh $response->decoded_content;
                            close $fh;
                        }

                        if ( -e "$entry->{'Filelocation'}/$entry->{'File'}.tmp" ) {

                            my $md5sum_new = file_md5_hex("$entry->{'Filelocation'}/$entry->{'File'}.tmp");

                            printf( "Received=%s - New=%s\n", $md5sum_new, $entry->{'MD5SUM'} ) if ($debug);

                            if ( $md5sum_new eq $entry->{'MD5SUM'} ) {
`mv $entry->{'Filelocation'}/$entry->{'File'}.tmp $entry->{'Filelocation'}/$entry->{'File'}`;

                                print_log( 'LOGINFO', "Updated $entry->{'Filelocation'}/$entry->{'File'}" );

                                if ( $entry->{'PostAction'} ne '' ) {
                                    print_log( 'LOGINFO', "Executing: $entry->{'PostAction'}" );
                                    my $cmd = `$entry->{'PostAction'}`;
                                }
                            }
                        }
                        else {
                            print_log( 'LOGERROR', "ERROR: Did not get file: $entry->{'File'}.tmp" );
                        }
                    }
                    else {
                        my $err = $response->status_line;
                        print_log( 'LOGERROR', "ERROR: Get failed for file: $entry->{'File'} ($err)" );
                    }
                }
            }
        }
    }
}

sub CheckAttachments {

    print_log( 'LOGINFO', "Checking for attachments" );

    my $VTAPI = $dbh->get('smeoptimizer')->prop('VTAPI') || '';
    if ( $VTAPI eq '' ) {
        print_log( 'LOGINFO', "No VirusTotal API configured" );
        return;
    }

    my $DB = DatabaseConnect();
    if ( not $DB ) {
        print_log( 'LOGERROR', "Cannot connect to DB" );
        return;
    }

    my $myquery = "SELECT * FROM attachments ORDER BY abstime";

    my $sth = $DB->prepare($myquery);
    my $rv  = $sth->execute();

    if ( not defined($rv) ) {
        my $err = $DB->errstr();
        print_log( 'LOGERROR', "ERROR: Cannot get attachment from table attachments - $err" );
        return undef;
    }

    my $last_id      = 0;
    my $last_VT_call = 0;
    my $start_time   = time();

    while ( my $results = $sth->fetchrow_hashref() ) {

        # Maximum checking for 10 minutes
        last if ( ( time() - $start_time ) > ( 10 * 60 ) );

        my $id = $$results{'id'};
        $last_id = $id;
        my $abstime  = $$results{'abstime'};
        my $sha1     = $$results{'sha1'};
        my $sha256   = $$results{'sha256'};
        my $filename = $$results{'filename'} || '';
        my $size     = $$results{'size'} || 0;

        printf( "%s: ID=%s SHA1:%s F:%s (%s bytes)\n", _date( time() ), $id, $sha1, $filename, $size ) if ($debug);

        # make sure not to violate VT rate limits (4 calls per minute)
        if ( $last_VT_call != 0 ) {
            my $sleep_time = 15 - ( time() - $last_VT_call );
            sleep($sleep_time);
        }

        CheckWithVT( $sha1, $sha256, $size, $filename );

        $last_VT_call = time();
    }

    if ( $last_id != 0 ) {
        $myquery = "DELETE FROM attachments WHERE id<=$last_id";

        $sth = $DB->prepare($myquery);
        $rv  = $sth->execute();

        if ( not defined($rv) ) {
            my $err = $DB->errstr();
            print_log( 'LOGERROR', "ERROR: Cannot delete old attachments - $err" );
        }
    }

    $DB->disconnect;

}

sub CheckWithVT {
    my $sha1   = shift;
    my $sha256 = shift;
    my $size   = shift;
    my $file   = shift;

    my $VTAPI = $dbh->get('smeoptimizer')->prop('VTAPI') || '';

    eval { require VirusTotal };
    if ($@) {
        print_log( 'LOGINFO', " VT: VirusTotal.pm not present " );
        return;
    }

    my $VT = VirusTotal->new();
    $VT->debug(1) if ($debug);
    $VT->apikey($VTAPI);

    my ( $infected, $description, $scans ) = $VT->check_result($sha256);

    if ( not defined($infected) and defined($description) and $description =~ m/Rate limited/ ) {
        print_log( 'LOGINFO', " VT: Rate Limited at VirusTotal" );
        return;
    }

    if ( !defined $infected ) {
        return;
    }
    elsif ($infected) {
        print_log( 'LOGINFO', " VT: virus found in \"$file\": $description" );

        my $browser = LWP::UserAgent->new( 'agent' => 'SMEOptimizer Agent/1.0', );
        $browser->timeout(10);

        my %report_hash = ( 'filename'    => $file,
                            'sha1'        => $sha1,
                            'sha256'      => $sha256,
                            'size'        => $size,
                            'description' => $description
        );

        my $json = encode_json( \%report_hash );

        my %parameters = ( 'UUID'       => $SystemID,
                           'Attachment' => $json, );

        my $response = $browser->post( $SubmitURL, \%parameters );

        if ( not $response->is_success ) {
            my $err = $response->status_line;
            print_log( 'LOGERROR', "Cannot deliver attachment report ($err)" );
        }

        #  } else {
        #    print_log('LOGINFO', " VT: OK - \"$file\" didn't have any detected virus");
    }
    return;
}

sub ReportSpam {

    my $DB = DatabaseConnect();
    if ( not $DB ) {
        print_log( 'LOGERROR', "Cannot connect to DB" );
        return;
    }

    my $err;
    my $myquery = sprintf("SELECT * FROM log ORDER BY abstime ASC");
    my $sth     = $DB->prepare($myquery);
    my $rv      = $sth->execute();

    if ( not defined($rv) ) {
        $err = $DB->errstr();
        print_log( 'LOGERROR', "ERROR: Cannot get entries from table log - $err" );
        return undef;
    }

    my $last_abstime = 0;

    my $rows = $sth->rows;
    if ( $rows != 0 ) {

        my $browser = LWP::UserAgent->new( 'agent' => 'SMEOptimizer Agent/1.0', );
        $browser->timeout(10);

        my $count = 0;

        # Only 200 in each report run
        my $max_report = 200;

        while ( my $results = $sth->fetchrow_hashref() ) {

            my $abstime         = $$results{'abstime'};
            my $ipaddress       = $$results{'ipaddress'};
            my $from_addr       = $$results{'from_addr'} || '';
            my $to_addr         = $$results{'to_addr'} || '';
            my $qpsmtpd_hook    = $$results{'qpsmtpd_hook'};
            my $qpsmtpd_retval  = $$results{'qpsmtpd_retval'};
            my $qpsmtpd_rettext = $$results{'qpsmtpd_rettext'};

            my ( $username, $from_domain ) = $from_addr =~ m/([^\@]+)\@(.*)/;

            printf( "%s: T:%s IP:%s - F:%s - T:%s - H:%s - V:%s - T:%s\n",
                    _date( time() ),
                    $abstime, $ipaddress, $from_addr, $to_addr, $qpsmtpd_hook, $qpsmtpd_retval, $qpsmtpd_rettext )
              if ($debug);

            my %report_hash = ( 'abstime'         => $abstime,
                                'ipaddress'       => $ipaddress,
                                'from_domain'     => $from_domain,
                                'qpsmtpd_hook'    => $qpsmtpd_hook,
                                'qpsmtpd_retval'  => $qpsmtpd_retval,
                                'qpsmtpd_rettext' => $qpsmtpd_rettext
            );

            my $json = encode_json( \%report_hash );

            my %parameters = ( 'UUID' => $SystemID,
                               'Data' => $json, );

            my $response = $browser->post( $SubmitURL, \%parameters );

            if ( not $response->is_success ) {
                $err = $response->status_line;
                print_log( 'LOGERROR', "Cannot deliver spam report ($err)" );
                last;
            }
            else {
                $last_abstime = $abstime;
                $count++;
            }

            # Enough is enough
            last if ( $count > $max_report );
        }

        print_log( 'LOGINFO', "Providing $count spam reports" );

    }

    # make sure to delete the old logs
    $myquery = sprintf( "DELETE FROM log WHERE abstime<='%s'", $last_abstime );

    $sth = $DB->prepare($myquery);
    $rv  = $sth->execute();

    if ( not defined($rv) ) {
        $err = $DB->errstr();
        print_log( 'LOGERROR', "ERROR: Cannot delete old logs - $err" );
    }

    $DB->disconnect;
}

sub BuildTables {

    my $rec = $dbh->get("smeoptimizer");
    if ( not $rec ) {
        $rec = $dbh->new_record( "smeoptimizer", { type => "service" }, { status => "enabled" }, );
    }

    my $DB = DatabaseConnect(0);
    if ( not $DB ) {
        print_log( 'LOGINFO', "Cannot connect to DB" );
        return undef;
    }

    my $myquery = "SHOW tables";

    my $sth = $DB->prepare($myquery);
    my $rv  = $sth->execute();

    if ( not defined($rv) ) {
        my $err = $DB->errstr();
        print_log( 'LOGERROR', "ERROR: Cannot check for correct table format - $err" );
        return undef;
    }

    my $found_table = 0;
    while ( my @row = $sth->fetchrow_array() ) {
        if ( $row[0] eq 'log' ) {
            $found_table = 1;
            last;
        }
    }

    if ( $found_table == 1 ) {

        # Lets create if it doesn't exist
        $myquery = "SHOW INDEX FROM log WHERE Column_name='id'";

        $sth = $DB->prepare($myquery);
        $rv  = $sth->execute();

        if ( not defined($rv) ) {
            my $err = $DB->errstr();
            print_log( 'LOGERROR', "ERROR: Cannot check for correct table format - $err" );
            return undef;
        }

        my $rows = $sth->rows;
        if ( $rows == 0 ) {

            # Drop the current log table and replace it
            $myquery = "DROP TABLE log";

            $sth = $DB->prepare($myquery);
            $rv  = $sth->execute();

            if ( not defined($rv) ) {
                my $err = $DB->errstr();
                print_log( 'LOGERROR', "ERROR: Cannot connect create table reporting - $err" );
                return undef;
            }
        }
    }

    # Lets create if it doesn't exist
    $myquery = "CREATE TABLE IF NOT EXISTS log (\
                    id int(6) NOT NULL auto_increment, \
              abstime TIMESTAMP(2) NOT NULL DEFAULT CURRENT_TIMESTAMP, \
                    ipaddress varchar(255), \
                    from_addr TEXT, \
                    to_addr TEXT, \
                    subject TEXT, \
                    header TEXT, \
                    qpsmtpd_hook TEXT, \
                    qpsmtpd_retval varchar(10), \
                    qpsmtpd_rettext TEXT, \
                    PRIMARY KEY (id))";

    $sth = $DB->prepare($myquery);
    $rv  = $sth->execute();

    if ( not defined($rv) ) {
        my $err = $DB->errstr();
        print_log( 'LOGERROR', "ERROR: Cannot connect create table logs - $err" );
        return undef;
    }

    # Lets create if it doesn't exist
    $myquery = "CREATE TABLE IF NOT EXISTS reporting (\
                    abstime TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, \
                    lastreport TIMESTAMP NOT NULL , \
                    answer TEXT, \
                    PRIMARY KEY (abstime))";

    $sth = $DB->prepare($myquery);
    $rv  = $sth->execute();

    if ( not defined($rv) ) {
        my $err = $DB->errstr();
        print_log( 'LOGERROR', "ERROR: Cannot connect create table reporting - $err" );
        return undef;
    }

    # Lets create if it doesn't exist
    $myquery = "CREATE TABLE IF NOT EXISTS attachments (\
                    id int(6) NOT NULL auto_increment, \
                    abstime TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, \
                    sha256 varchar(64) NOT NULL UNIQUE, \
                    sha1 varchar(40) DEFAULT 0, \
                    filename varchar(255), \
                    size INT DEFAULT 0, \
                    PRIMARY KEY (id))";

    $sth = $DB->prepare($myquery);
    $rv  = $sth->execute();

    if ( not defined($rv) ) {
        my $err = $DB->errstr();
        print_log( 'LOGERROR', "ERROR: Cannot connect create table attachments - $err" );
        return undef;
    }

    $DB->disconnect;
    return 1;
}

sub DatabaseConnect {

    # Open the DB
    my $host     = "localhost";
    my $database = "smeoptimizer";
    my $user     = "smeoptimizer";
    my $pw       = "password";

    my $dsn = "dbi:mysql:database=$database;host=$host;port=3306";

    my $dbh = DBI->connect( $dsn, $user, $pw, { PrintError => 0, RaiseError => 0, mysql_connect_timeout => 10 } );

    return $dbh;

}

sub print_log {
    my $log_level = shift, my $msg = shift;

    my $LOG = OpenLog();

    return if ( not $msg );

    $msg =~ s/[\n\r]//;

    $msg =~ s /[^[:ascii:]]+//g;    # get rid of non-ASCII characters

    if (    $log_level eq 'LOGINFO'
         or $log_level eq 'LOGWARN'
         or $log_level eq 'LOGERROR' ) {

        printf LOG ( "%s - %s\n", _date(), $msg );
    }

}

sub OpenLog {

    my $logfile = sprintf("smeoptimizer.log");
    my $logdir  = '/var/log/';
    my $LOG;

    my $LogFile = sprintf( "%s/%s", $logdir, $logfile );
    if ( not( open( LOG, ">> $LogFile" ) ) ) {
        printf( "Cannot open logfile %s (%s)\n", $LogFile, $! ) if ($debug);
        return;
    }
    else {
        #    select LOG; $| = 1; # make unbuffered
        autoflush LOG 1;
    }
    return $LOG;
}

sub _date {

    my $time = shift;

    $time = time() if ( not defined($time) );

    my @weekday = ( "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" );
    my @month = ( "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" );

    my @date_info = localtime($time);
    my $date      = sprintf( "%s %d %s %4d, %02d:%02d:%02d",
                        $weekday[ $date_info[6] ],
                        $date_info[3],
                        $month[ $date_info[4] ],
                        $date_info[5] + 1900,
                        $date_info[2], $date_info[1], $date_info[0] );

    $date = sprintf( "%d-%d-%4d, %02d:%02d:%02d",
                     $date_info[3],
                     $date_info[4] + 1,
                     $date_info[5] + 1900,
                     $date_info[2], $date_info[1], $date_info[0] );

    return $date;
}

sub validate_email {
    my $email_address = shift;

    if ( $email_address =~ m/^[a-z0-9_-]+[a-z0-9_.-]*@[a-z0-9_-]+[a-z0-9_.-]*\.[a-z]{2,5}$/ ) {
        return 1;
    }
    else {
        return 0;
    }
}
