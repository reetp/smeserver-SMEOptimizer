# smeserver-SMEOptimizer
Add further mail checks for Koozali SME Server

https://wiki.contribs.org/SMEOptimizer

This code aims to create a RPM for easier installation on Koozali SME Server

You still need to manually create the DB

 mysqladmin create smeoptimizer
 mysql smeoptimizer
 GRANT ALL PRIVILEGES ON smeoptimizer.* TO 'smeoptimizer'@'localhost' IDENTIFIED BY 'password';
 FLUSH PRIVILEGES; 
 EXIT

Now initialise:

 /SMEOptimizer.pl --initialize
 
For help:

 ./SMEOptimizer.pl --help

Command line options:
-help:                   Shows this help
-initialize:             Register and retrieve the configuration and enable the cronjob services.
                         When the registration has been confirmed, then all services will be activated automatically.
-status:                 Shows the current status of the SME Optimizer.
-alerts=[Yes|No]:        Enable checks and alerts for SME server downtime or registration in DNS Blacklist - default Yes.
-contact=[Email]:        Set the contact email address where alerts are sent to - default admin@<your domain>.
-VTAPI=[API Key]:        This is the VirusTotal public API key used to check attachments (will remain local).
-DNSBL=[qpsmtpd|sa]:     This configures whether the DNS blacklist lookup rejects directly (qpsmtpd) or scores (sa=SpamAssassin).