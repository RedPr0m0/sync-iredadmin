# sync-iredadmin 

## Overview

Sync-iredadmin is an python scrypt for syncing domain, user, copying and migrating email
mailboxes between two iRedAdmin servers, one way, and without duplicates.
Sync domain and user only used iRedAdmin LDAP backend.

## Download
Download the latest version from the [releases](https://github.com/d0codesoft/sync-iredadmin/releases/latest) page.

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

## TODO
- [ ] Write log file
- [ ] Check error used LDAP and IMAP sync

## License

ImapSync Client is licensed under the [MIT License](LICENSE)