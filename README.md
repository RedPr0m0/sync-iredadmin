# sync-iredadmin 

## Overview

Sync-iredadmin is an python scrypt for syncing domain, user, copying and migrating email
mailboxes between two iRedAdmin servers, one way, and without duplicates.
Sync domain and user only used iRedAdmin LDAP backend.
Mail sync run in multithreading process. Set up count multithreading process in setting.py

Before starting, copy settings.py.exampl to settings.py, and be sure to set all the necessary 
parameters in the settings.py file.

## Used scrypt command line
 
    sync-iredadmin-LDAP.py [-h] [-d [DOMAINSYNC]] [-u [USERSYNC]] [-m] {filter} ...

    options: 
        -h, --help            show this help message and exit
        -d [DOMAINSYNC]       Sync domain [only domain]
        -u [USERSYNC],        Sync user [only user]
        -m, --mailsync        sync mail on imap protocol

        filter                parameters filter email sync
          {min,max}   type age email
          countage    count days age mail (min or max)     

## Need to do

[ ] Connect LDAP server over SSH

## License

ImapSync Client is licensed under the [MIT License](LICENSE)