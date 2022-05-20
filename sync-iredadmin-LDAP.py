#!/usr/bin/env python3
# Author: Alexandr Maievsky <softstar2004@gmail.com>
# Purpose: Synchronization domains and mails of two iredadmin servers with LDAP backend.
#
# Usage:
#   write setting access to ldap server to setting.py, example setting.py.exampl
#   python MigrateUserLDAP.py
# ------------------------------------------------------------------

import os
import sys
import logging
import time
import datetime
import argparse
from subprocess import Popen, PIPE
from typing import List, Dict
import re
import ldap3
from ldap3 import Server, Connection, ALL
import settings

# Default groups which will be created while create a new domain.
# WARNING: Don't use unicode string here.
DEFAULT_GROUPS = ('Users', 'Groups', 'Aliases', 'Externals')
LDAP_SEARCH_ALL_DOMAINS = '(&(objectClass=mailDomain)(!(accountStatus=disabled))(enabledService=mail))'
LDAP_SEARCH_DOMAIN = '(&(objectClass=mailDomain)(!(accountStatus=disabled))(enabledService=mail)(domainName={dN}))'
LDAP_SEARCH_ALL_USERS = '(&(objectClass=mailUser)(!(domainStatus=disabled))(enabledService=mail))'
LDAP_SEARCH_USERS_DOMAIN = '(&(objectClass=mailUser)(!(domainStatus=disabled))(enabledService=mail)(mail=*@{dM}))'
LDAP_SEARCH_ALL_GROUP_DOMAIN = '(&(objectClass=organizationalUnit))'
LDAP_SEARCH_USER = '(&(objectClass=mailUser)(!(domainStatus=disabled))(enabledService=mail)(mail={uMail}))'
DOMAIN_ATTRS_ALL = (
    # Normal attributes.
    'domainName', 'domainPendingAliasName', 'domainAliasName',
    'cn', 'description', 'accountStatus', 'domainBackupMX',
    'domainAdmin', 'mtaTransport', 'enabledService',
    'domainRecipientBccAddress', 'domainSenderBccAddress',
    'senderRelayHost', 'disclaimer',
    'domainCurrentQuotaSize',
    # 'domainCurrentUserNumber',
    # 'domainCurrentListNumber',
    # 'domainCurrentAliasNumber',
    'accountSetting',
)
USER_ATTRS_SYNC = (
    'mail', 'cn', 'sn', 'uid', 'accountStatus', 'mailQuota',
    'employeeNumber', 'title', 'senderRelayHost',
    'shadowAddress', 'mailForwardingAddress', 'memberOfGroup',
    'enabledService', 'disabledService',
    'domainGlobalAdmin',    # Global admin
    'shadowLastChange',     # Password last change, it's number of days since
    'givenName',
    'mobile', 'telephoneNumber', 'preferredLanguage', 'memberOfGroup',
    'userRecipientBccAddress', 'userSenderBccAddress',
    'mtaTransport',
    'accountSetting',
    'allowNets',
    'street',
    'postalCode',
    'postalAddress',
)
USER_ATTRS_ALL = tuple(list(USER_ATTRS_SYNC) + [
    'storageBaseDirectory', 'mailMessageStore', 'homeDirectory'
])

# Email address.
email = r"""[\w\-\#][\w\-\.\+\=\/\&\#]*@[\w\-][\w\-\.]*\.[a-zA-Z0-9\-]{2,15}"""
cmp_email = re.compile(r"^" + email + r"$", re.IGNORECASE | re.DOTALL)

class LdapServer:

    def __init__(self):
        self.con = None
        self.srvdn = ''
        self.srvport = ''
        self.use_ssl = False
        self.baseDN = ''
        self.bind_dn = ''
        self.bind_password = ''
        self.ssh_server = ''
        self.ssh_port = None
        self.ssh_username = ''
        self.ssh_password = ''
        self.privatekey = ''

    def __del__(self):
        self.__disconnect()

    def __str__(self):
        if self.con:
            return str(self.con)

        return 'None connect'

    def __disconnect(self):
        if not self.con:
            self.con.unbind()
            self.con = None

    def connect(self, setting_сonnect):
        if not setting_сonnect:
            raise RuntimeError('Error setting server connected')

        self.srvdn = setting_сonnect.get('server')
        self.srvport = setting_сonnect.get('port')
        self.baseDN = setting_сonnect.get('basedn')
        self.bind_dn = setting_сonnect.get('bind_dn')
        self.bind_password = setting_сonnect.get('bind_password')
        self.use_ssl = setting_сonnect.get('use_ssl', False)
        if not self.baseDN:
            self.baseDN = self.__getBaseDNFromUser(self.bind_dn)

        s = Server(self.srvdn, self.srvport, use_ssl=self.use_ssl, get_info=ALL)
        if self.use_ssl:
            self.con = Connection(s, user=self.bind_dn, password=self.bind_password, authentication=ldap3.SIMPLE)
        else:
            self.con = Connection(s, user=self.bind_dn, password=self.bind_password)

        if not self.con.bind():
            return (False, self.con.result)

        return (True,)

    def __parceserverldap(self, paramserver: str):
        p = paramserver.split(':')
        if len(p) != 3:
            raise RuntimeError('Error parametr server \'ldap[s]://[ip]:port\': {}'.format(paramserver))

        ssl = False
        if p[0] == 'ldaps':
            ssl = True

        srv = p[1].replace('//', '')
        port = int(p[2])
        return dict(server=srv, port=port, use_ssl=ssl)

    def __getBaseDNFromUser(self, usename: str):
        bDN = ''
        p = usename.split(',')
        for dc in p:
            if dc.find('dc=') != -1:
                bDN += ',' + dc

        return 'o=domains{dn}'.format(dn=bDN)

    #region Domain
    def getDomainList(self):
        searchDN = self.baseDN
        domain_list = self.con.extend.standard.paged_search(search_base=searchDN,
                                                            search_filter=LDAP_SEARCH_ALL_DOMAINS,
                                                            search_scope=ldap3.SUBTREE,
                                                            attributes=DOMAIN_ATTRS_ALL,
                                                            generator=False)
        return domain_list

    def getDomain(self, domain):
        dn = self.baseDN
        search_filter = LDAP_SEARCH_DOMAIN.format(dN=domain)
        self.con.search(search_base=dn,
                        search_filter=search_filter,
                        search_scope=ldap3.LEVEL,
                        attributes=DOMAIN_ATTRS_ALL,
                        paged_size=5)
        if self.con.result['description'] != 'success':
            return []

        return self.con.response

    def addDomain(self, domain, attr):
        dn = 'domainName={dN},{bDN}'.format(dN=domain, bDN=self.baseDN)
        self.con.add(dn=dn, attributes=attr)
        res = self.con.result['description'] == 'success'
        if res:
            # adding default group domain
            for itemgroup in DEFAULT_GROUPS:
                dng = 'ou={dG},domainName={dN},{bDN}'.format(dG=itemgroup, dN=domain, bDN=self.baseDN)
                self.con.add(dn=dng, object_class='organizationalUnit')

        return res

    def updateDomain(self, domain, attr):
        dn = 'domainName={dN},{bDN}'.format(dN=domain, bDN=self.baseDN)
        self.con.modify(dn=dn, changes=attr)

        return self.con.result['description'] == 'success'

    def checkDomain(self, domain, attr):
        dn = self.baseDN
        search_filter = LDAP_SEARCH_DOMAIN.format(dN=domain)
        self.con.search(search_base=dn,
                        search_filter=search_filter,
                        search_scope=ldap3.LEVEL,
                        attributes=DOMAIN_ATTRS_ALL,
                        paged_size=5)
        if self.con.result['description'] != 'success':
            return 'ERROR', 'Not search domain name {dN}'.format(dN=domain)

        domains = self.con.response
        if len(domains) == 0:
            return 'ADD', domain, attr

        dm = domains[0]
        resDiff = self.__getDiffAttr(attr, dm['attributes'], DOMAIN_ATTRS_ALL, False)
        if resDiff:
            return 'NONE', domain, None

        return 'MODIFY', domain, resDiff
    #endregion

    def getUserList(self, domain='*'):
        searchDN = self.baseDN
        if domain == '*':
            searchUser = LDAP_SEARCH_ALL_USERS
        else:
            searchUser = LDAP_SEARCH_USERS_DOMAIN.format(dM=domain)

        users_list = self.con.extend.standard.paged_search(search_base=searchDN,
                                                           search_filter=searchUser,
                                                           search_scope=ldap3.SUBTREE,
                                                           attributes=ldap3.ALL_ATTRIBUTES,
                                                           generator=False)

        return users_list

    def getUser(self, user):
        dn = self.baseDN
        search_filter = LDAP_SEARCH_USER.format(uMail=user)
        self.con.search(search_base=dn,
                        search_filter=search_filter,
                        search_scope=ldap3.LEVEL,
                        attributes=ldap3.ALL_ATTRIBUTES,
                        paged_size=5)
        if self.con.result['description'] != 'success':
            return []

        return self.con.response

    def checkUser(self, user_mail, attr):

        if not self.is_email(user_mail):
            return 'ERROR', 'Name user not valid'

        segment_mail = user_mail.split('@')
        domain = segment_mail[1]
        dn = 'ou=Users,domainName={dN},{bDN}'.format(dN=domain, bDN=self.baseDN)
        search_filter = LDAP_SEARCH_USER.format(uMail=user_mail)
        self.con.search(search_base=dn,
                        search_filter=search_filter,
                        search_scope=ldap3.LEVEL,
                        attributes=ldap3.ALL_ATTRIBUTES,
                        paged_size=5)
        if self.con.result['description'] != 'success':
            return 'ERROR', 'Not search user name {dN}'.format(dN=user_mail)

        users = self.con.response
        if len(users) == 0:
            return 'ADD', user_mail, attr

        usr = users[0]
        resDiff = self.__getDiffAttr(attr, usr['attributes'], USER_ATTRS_SYNC, False)
        if not resDiff:
            return 'NONE', user_mail

        return 'MODIFY', user_mail, resDiff

    def addUser(self, user_mail, attr, setting_account):

        if not self.is_email(user_mail):
            return 'ERROR', 'Name user not valid'

        segment_mail = user_mail.split('@')

        domain = segment_mail[1]
        username = segment_mail[0]
        dn = 'mail={uN},ou=Users,domainName={dN},{bDN}'.format(uN=user_mail, dN=domain, bDN=self.baseDN)

        # add attributes directory new server
        storage_base_directory = setting_account.get('storage_mail_base_directory')
        if not storage_base_directory:
            raise BaseException('Not setting storage base directory')

        # Get base directory and storage node.
        std = storage_base_directory.rstrip('/').split('/')
        dst_mail_message_store = std.pop()
        dst_storage_base = '/'.join(std)

        maildir_domain = str(domain).lower()
        indexstr, str1 = self.__getnextchar(username)
        str2 = str3 = str1
        if len(username) >= 3:
            indexstr, str2 = self.__getnextchar(username, indexstr)
            indexstr, str3 = self.__getnextchar(username, indexstr)
        elif len(username) == 2:
            str2 = str3 = username[1]

        timestamp_maildir = '-%s' % time.strftime('%Y.%m.%d.%H.%M.%S')
        maildir_user = "%s/%s/%s/%s%s/" % (str1, str2, str3, username, timestamp_maildir,)

        dst_home_directory = '{}/{}'.format(storage_base_directory, maildir_user)
        dst_mail_message_store = '{}/{}'.format(dst_mail_message_store, maildir_user)
        attr['homeDirectory'] = dst_home_directory
        attr['mailMessageStore'] = dst_mail_message_store
        attr['storageBaseDirectory'] = dst_storage_base

        self.con.add(dn=dn, attributes=attr)
        res = self.con.result['description'] == 'success'
        return res

    def updateUser(self, user_mail, attr):
        segment_mail = user_mail.split('@')

        domain = segment_mail[1]
        dn = 'mail={uN},ou=Users,domainName={dN},{bDN}'.format(uN=user_mail, dN=domain, bDN=self.baseDN)
        self.con.modify(dn=dn, changes=attr)
        res = self.con.result['description'] == 'success'
        return res

    @staticmethod
    def __getnextchar(source_string, index=0):
        i_len = len(source_string)
        ret_str = source_string[index]
        while index < i_len:
            char_str = source_string[index]
            if char_str not in ['.', '_', '-']:
                ret_str = char_str
                index += 1
                break
            index += 1

        return index, ret_str

    @staticmethod
    def __getDiffAttr(src_attr, dst_attr, list_available_attr=None, delete_dst=False):
        diffAttr = {}

        for attr in src_attr:
            if list_available_attr and attr not in list_available_attr:
                continue

            src_val = src_attr.get(attr)
            if attr not in dst_attr:
                if isinstance(src_val, list):
                    diffAttr[attr] = [(ldap3.MODIFY_ADD, src_val)]
                else:
                    diffAttr[attr] = [(ldap3.MODIFY_ADD, [src_val])]
            else:
                dst_val = dst_attr.get(attr)
                if isinstance(src_val, list):
                    for item_src_val in src_val + dst_val:
                        if item_src_val not in dst_val or item_src_val not in src_val:
                            diffAttr[attr] = [(ldap3.MODIFY_REPLACE, src_val)]
                            break
                elif src_val != dst_val:
                    diffAttr[attr] = [(ldap3.MODIFY_REPLACE, [src_val])]

        if delete_dst:
            for attr in dst_attr:
                src_val = dst_attr.get(attr)
                if attr not in src_attr:
                    diffAttr[attr] = [(ldap3.MODIFY_DELETE, [])]

        return diffAttr

    def addGroupDomain(self, domain, group_name, group_object, attr):
        dn = 'ou={gName},domainName={dN},{bDN}'.format(gName=group_name, dN=domain, bDN=self.baseDN)
        self.con.add(dn=dn, object_class=group_object, attributes=attr)

        return self.con.result

    def getGroupDomain(self, domain):
        searchDN = 'domainName={dN},{bDN}'.format(dN=domain, bDN=self.baseDN)
        group_domain_list = self.con.extend.standard.paged_search(search_base=searchDN,
                                                                  search_filter=LDAP_SEARCH_ALL_GROUP_DOMAIN,
                                                                  search_scope=ldap3.LEVEL,
                                                                  paged_size=100,
                                                                  generator=False)

        return group_domain_list

    @staticmethod
    def getDomainNameFromFullDN(full_dn):
        items_dn = ldap3.utils.dn.parse_dn(full_dn)
        for descrDn, valDn, spDn in items_dn:
            if descrDn == 'domainName':
                return valDn

        return None

    @staticmethod
    def getUserMailNameFromFullDN(full_user_dn):
        usr = ''
        dn = ''
        items_dn = ldap3.utils.dn.parse_dn(full_user_dn)
        for descrDn, valDn, spDn in items_dn:
            if descrDn == 'mail':
                usr = valDn
            elif descrDn == 'domainName':
                dn = valDn

        return dn, usr

    @staticmethod
    def is_email(s) -> bool:
        try:
            s = str(s).strip()
        except UnicodeEncodeError:
            return False

        if cmp_email.match(s):
            return True

        return False


class main:
    NAME = 'Sync iredadmin LDAP backend user'
    VERSION = '0.1'

    def __init__(self):
        self.ldap_src = None
        self.ldap_dst = None

    def __del__(self):
        self.ldap_src = None
        self.ldap_dst = None

    def run(self):
        print('Start sync')

        # Instantiate the parser
        parser = argparse.ArgumentParser(description='Sync user ldap backend iredadmin')
        parser.add_argument('-d', '--domainsync', help='Sync domain [only domain]', nargs='?', const='*', type=str)
        parser.add_argument('-u', '--usersync', help='Sync user [only user]', nargs='?', const='*', type=str)
        parser.add_argument('-m', '--mailsync', help='sync mail on imap protocol', action='store_true')

        program_args = parser.parse_args()
        param_usernsync = program_args.usersync
        param_domainsync = program_args.domainsync
        param_mailsync = program_args.mailsync

        if param_domainsync or param_usernsync:
            self.ldap_src = LdapServer()
            res = self.ldap_src.connect(settings.SERVER_SOURCE)
            if not res[0]:
                print('Error connect to ldap server source : %s' % res[1])

            self.ldap_dst = LdapServer()
            res = self.ldap_dst.connect(settings.SERVER_DESTINATION)
            if not res[0]:
                print('Error connect to ldap server destination : %s' % res[1])

            if param_domainsync:
                self.__syncDomain(param_domainsync)
            else:
                param_domainsync = '*'

            if param_usernsync:
                self.__syncUsers(param_domainsync, param_usernsync)

            print(self.ldap_src)
            print(self.ldap_dst)

    def __syncDomain(self, domain_sync):
        # sync domain
        if domain_sync == '*':
            src_domains = self.ldap_src.getDomainList()
            if len(src_domains) == 0:
                print('Source LDAP not contains domain list status in enabled')
                return
        else:
            src_domains = self.ldap_src.getDomain(domain_sync)
            if len(src_domains) == 0:
                print('Source LDAP not contains domain list status in enabled')
                return

        for src_domain in src_domains:
            attr = src_domain['attributes']
            dn = self.ldap_src.getDomainNameFromFullDN(src_domain['dn'])
            print('Sync domain : %s' % dn)
            resultCheck = self.ldap_dst.checkDomain(dn, attr)
            print(resultCheck)
            if resultCheck[0] == 'NONE':
                print('Ned add domain')
            elif resultCheck[0] == 'MODIFY':
                self.ldap_dst.updateDomain(resultCheck[1], resultCheck[2])
            elif resultCheck[0] == 'ADD':
                self.ldap_dst.addDomain(resultCheck[1], resultCheck[2])

    def __syncUsers(self, domain, user):
        user_list = self.ldap_src.getUserList(domain)
        for src_user in user_list:
            dn_mail, usr_mail = self.ldap_src.getUserMailNameFromFullDN(src_user['dn'])
            src_attr = src_user['attributes']

            if user and user != '*' and usr_mail != user:
                continue

            print('Sync user: %s' % usr_mail)
            resultCheck = self.ldap_dst.checkUser(usr_mail, src_attr)
            print(resultCheck)
            if resultCheck[0] == 'NONE':
                print('User source and destination is the same')
            elif resultCheck[0] == 'MODIFY':
                print('Modify user :', resultCheck[2])
                self.ldap_dst.updateUser(resultCheck[1], resultCheck[2])
            elif resultCheck[0] == 'ADD':
                print('Dst not found, adding user :', resultCheck[2])
                self.ldap_dst.addUser(resultCheck[1], resultCheck[2]
                                      , settings.SERVER_DESTINATION)


if __name__ == '__main__':
    app = main()
    app.run()
    sys.exit(0)
