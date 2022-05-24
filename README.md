# sync-iredadmin

sync-iRedAdmin is a python scrypt to sync LDAP database backend

usage: sync-iredadmin-LDAP.py [-h] [-d [DOMAINSYNC]] [-u [USERSYNC]] [-m] {filter} ...
Sync user ldap backend iredadmin

options:
-h, --help            show this help message and exit
-d [DOMAINSYNC]       Sync domain [only domain]
-u [USERSYNC],        Sync user [only user]
-m, --mailsync        sync mail on imap protocol

filter                parameters filter email sync
  {min,max}   type age email
  countage    count days age mail (min or max)     

For the script to work correctly, you must set the configuration file 'setting.py'. 
Mail synchronize used master password from instruction on iRedMail  

>https://docs.iredmail.org/dovecot.master.user.html
