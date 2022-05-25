#!/usr/bin/env python3
# Author: Alexandr Maievsky <softstar2004@gmail.com>
# Purpose: Synchronization domains and mails of two iredadmin servers with LDAP backend.
#
# Usage:
#   write setting access to ldap server to setting.py, example setting.py.exampl
#   python MigrateUserLDAP.py
# ------------------------------------------------------------------

import argparse
import imaplib
import re
import socket
import sys
import time
import ssl
import ldap3
from ldap3 import Server, Connection, ALL
import email
import datetime
import settings
import concurrent.futures
import functools
import logging

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
    'domainGlobalAdmin',  # Global admin
    'shadowLastChange',  # Password last change, it's number of days since
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
RE_EMAIL_TEST = r"""[\w\-\#][\w\-\.\+\=\/\&\#]*@[\w\-][\w\-\.]*\.[a-zA-Z0-9\-]{2,15}"""
cmp_email = re.compile(r"^" + RE_EMAIL_TEST + r"$", re.IGNORECASE | re.DOTALL)
PATTERN_FLAGS_ID = r'FLAGS \(\\\\(.*?)\)'
cmp_flags_email = re.compile(PATTERN_FLAGS_ID)
PATERN_SIZE_MAIL = r'RFC822.SIZE\s(.*?)\s'
cmp_size_mail = re.compile(PATERN_SIZE_MAIL)

# logger
logging.basicConfig(filename='sync-iredadmin.log', encoding='utf-8', level=logging.INFO)
logger = logging.getLogger('sync-iredadmin')
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


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
            logger.error('Error parameter server \'ldap[s]://[ip]:port\': {}'.format(paramserver))
            return None

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

    # region Domain
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

    # endregion

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


class IMAPServer:

    def __init__(self):
        self.server = None
        self.connect_imap = None
        self.master_login = None
        self.master_pwd = None

    def __del__(self):
        self.disconnect()

    def disconnect(self):
        if not self.connect_imap:
            self.server = None
            self.connect_imap = None

    def connect(self, config):
        self.disconnect()

        l_timeout = float(config.get('timeout', 30))
        l_server = config.get('server')
        self.server = l_server
        l_port = config.get('port', 143)
        l_secure = config.get('secure', 'None')
        self.master_login = config.get('master_usr')
        self.master_pwd = config.get('master_pwd')

        result_connect = False

        try:
            socket.setdefaulttimeout(l_timeout)
            if 'SSL' in l_secure:
                print("Connecting to '%s' TCP port %d, SSL" % (l_server, l_port))
                if 'insecure' in l_secure:
                    ssl_context = ssl._create_unverified_context()
                    self.connect_imap = imaplib.IMAP4_SSL(host=l_server, port=l_port, ssl_context=ssl_context)
                else:
                    self.connect_imap = imaplib.IMAP4_SSL(l_server, l_port)
            elif 'TLS' in l_secure:
                print("Connecting to '%s' TCP port %d, SSL" % (l_server, l_port))
                self.connect_imap = imaplib.IMAP4(l_server, l_port)

                if 'insecure' in l_secure:
                    tls_context = ssl._create_unverified_context()
                else:
                    tls_context = ssl.create_default_context()

                self.connect_imap.starttls(ssl_context=tls_context)
            else:
                print("Connecting to '%s' TCP port %d" % (l_server, l_port))
                self.connect_imap = imaplib.IMAP4(l_server, l_port)

            result_connect = True
        except socket.gaierror as e:
            (err, desc) = e
            print("ERROR: problem looking up server '%s' (%s %s)" % (l_server, err, desc))
        except socket.error as e:
            print("ERROR: could not connect to '%s' (%s)" % (l_server, e))
        except Exception as e:
            print("ERROR: Host %s" % l_server)
            print(str(e))

        return result_connect

    def loginUser(self, user):

        l_pw = self.master_pwd
        l_login_user = '{user}*{master}'.format(user=user, master=self.master_login)

        result_login = False

        try:
            self.connect_imap.login(l_login_user, l_pw)
            result_login = True
            logger.info("IMAP connect, success login on [%s] with user [%s]", self.server, user)
        except socket.gaierror as e:
            (err, desc) = e
            logger.error("IMAP connect ERROR: problem looking up server '%s' (%s %s)", self.server, err, desc)
        except socket.error as e:
            logger.error("IMAP connect ERROR: could not connect to '%s' (%s)", self.server, e)
        except Exception as e:
            logger.error("IMAP connect ERROR: Host %s, user=%s", self.server, user)
            logger.error(str(e))

        return result_login

    def logOut(self):
        self.connect_imap.logout()

    def listMailboxes(self):
        (res, data) = self.connect_imap.list()
        list_folder = []
        if res != 'OK':
            logger.error('IMAP Error list folder %s - %s', res, str(data))
            return list_folder

        list_re = re.compile(r'\((?P<flags>.*)\)\s+"(?P<delimiter>.*)"\s+"?(?P<name>[^"]*)"?')
        for f in data:
            m = list_re.match(f.decode('UTF-8'))
            if not m:
                logger.error('IMAP Error decode folder name, size, flags: %s', f.decode('UTF-8'))
                return None

            flags, delimiter, mailbox = m.groups()
            # print('server:', self.server, 'folder:', f.decode('UTF-8'), 'mailbox:', mailbox)
            list_folder.append({
                'flags': flags,
                'delimiter': delimiter,
                'mailbox': mailbox,
                'noselect': ('Noselect' in flags)
                # 'messages': mcount,
                # 'size': msize
            })

        return list_folder

    def capability(self):
        typ, data = self.connect_imap.capability()
        return data[0].decode('utf-8')

    def createMailbox(self, name_mailbox):
        self.connect_imap.create(name_mailbox)

    def openFolder(self, folder_name, read_only=True):
        rv, data = self.connect_imap.select(folder_name, read_only)
        res = rv == 'OK'
        return res, data

    def closeFolder(self):
        self.connect_imap.unselect()

    def getListMessagesMailBox(self, param_search={}):
        msg_ids = []
        result = False
        cmd_search = self.__getCmdSearchMail(param_search)
        try:
            rv, data = self.connect_imap.search(None, '(ALL)', cmd_search)
            if rv != 'OK':
                logger.error('IMAP error list message mailbox %s, result %s - %s', self.server, rv, str(data))
                return False, []

            msg_ids = data[0].split()
            result = True
        except Exception as e:
            logger.error('IMAP error list message mailbox %s, %s', self.server, str(e))
            return False, []

        return result, msg_ids

    def __getCmdSearchMail(self, param_search):
        maxage = param_search.get('maxage')
        minage = param_search.get('minage')

        cmd = '(undeleted'
        if maxage:
            date = (datetime.date.today() - datetime.timedelta(int(maxage))).strftime("%d-%b-%Y")
            cmd += ' SENTSINCE {data}'.format(data=date)

        if minage:
            date = (datetime.date.today() - datetime.timedelta(int(minage))).strftime("%d-%b-%Y")
            cmd += ' SENTBEFORE {data}'.format(data=date)
        cmd += ')'
        return cmd

    def getMessageId(self, mail_imap_id):
        res, data = self.connect_imap.fetch(mail_imap_id, '(BODY.PEEK[HEADER] FLAGS RFC822.SIZE)')
        if res != 'OK':
            logger.error('IMAP error get message ID %s, result %s - %s', mail_imap_id, res, str(data))
            return None, None, None

        flag = ''
        rem = cmp_flags_email.search(str(data[0][0]))
        if rem:
            flag = rem.group(1).replace('\\\\', '').replace('\\', '')

        size = 0
        rem = cmp_size_mail.search(str(data[0][0]))
        if rem:
            try:
                size = int(rem.group(1))
            except:
                size = 0

        headers = email.message_from_bytes(data[0][1])
        return headers['Message-ID'], flag, size

    def getMessage(self, mail_imap_id):
        res, data = self.connect_imap.fetch(mail_imap_id, '(RFC822)')
        if res != 'OK':
            logger.error('IMAP error get message %s, result %s - %s', mail_imap_id, res, str(data))
            return None

        return data[0][1]

    def appendMessage(self, folder, data_message, flags):
        try:
            typ, dat = self.connect_imap.append(folder, flags, None, data_message)
        except Exception as e:
            logger.error('IMAP error append message %s with flags %s, folder %s, ex: %s',
                         self.server, str(flags), folder, str(e))
            try:
                typ, dat = self.connect_imap.append(folder, None, None, data_message)
            except Exception as e:
                logger.error('IMAP error append message %s without flags %s, folder %s, ex: %s',
                             self.server, str(flags), folder, str(e))

        return typ == 'OK'


def secondsToStr(t):
    return "%d:%02d:%02d.%03d" % \
           functools.reduce(lambda ll, b: divmod(ll[0], b) + ll[1:],
                            [(t * 1000,), 1000, 60, 60])


def runThreadSyncMail(user, settings_imap):
    append_messages = 0
    append_size_byte = 0

    start_time = time.time()
    logger.info('Thread %s start sync', user)

    src_imap_conn = IMAPServer()
    dst_imap_conn = IMAPServer()
    if not src_imap_conn.connect(settings_imap.get('SERVER_IMAP_SOURCE')):
        return

    if not dst_imap_conn.connect(settings_imap.get('SERVER_IMAP_DESTINATION')):
        return

    result = src_imap_conn.loginUser(user) \
             and dst_imap_conn.loginUser(user)
    if result:
        logger.info('Capability source: %s', src_imap_conn.capability())
        logger.info('Capability source: %s', dst_imap_conn.capability())
        src_list_folder = src_imap_conn.listMailboxes()
        # dst_list_folder = self.dst_imap_conn.listMailboxes()
        for item_folder in src_list_folder:
            current_mailbox = item_folder.get('mailbox')
            # print('Folder: %s, Delimiter: %s, Flags: %s' % (current_mailbox,
            #                                                item_folder.get('delimiter'),
            #                                                item_folder.get('flags')))

            if not item_folder.get('noselect'):
                dst_imap_conn.createMailbox(current_mailbox)

                # Fetch destination messages ID
                logger.info('Thread %s fetch messages ID from %s', user, current_mailbox)
                dst_message_ids = {}

                src_imap_conn.openFolder(current_mailbox, True)
                dst_imap_conn.openFolder(current_mailbox)

                result, dst_ids = dst_imap_conn.getListMessagesMailBox(settings_imap.get('filter_email'))
                if result:
                    count_dst = 0
                    for did in dst_ids:
                        count_dst += 1
                        msgid, flg, size_msg = dst_imap_conn.getMessageId(did)
                        dst_message_ids[msgid] = {'flag': flg, 'id': did, 'size_byte': size_msg}
                        # dst_message_ids.append(msgid)

                    src_message_ids = {}
                    count_src = 0
                    result, src_ids = src_imap_conn.getListMessagesMailBox(settings_imap.get('filter_email'))
                    if result:
                        for did in src_ids:
                            count_src += 1
                            msgid, flg, size_msg = src_imap_conn.getMessageId(did)
                            if not src_message_ids.get(msgid):
                                src_message_ids[msgid] = {'flag': flg, 'id': did, 'size_byte': size_msg}
                            elif size_msg != src_message_ids[msgid].get('size_byte'):
                                src_message_ids[msgid] = {'flag': flg, 'id': did, 'size_byte': size_msg}
                            # src_message_ids.append(msgid)

                    # print('Source:', len(src_message_ids), "message IDs acquired.")
                    logger.info('Thread %s, start sync mail %s, count src:%s dst:%s',
                                user, current_mailbox, str(count_src), str(count_dst))
                    append_messages_folder = 0
                    append_size_folder = 0
                    duplicate_msg = {}
                    for src_msg_id in src_message_ids:
                        if src_msg_id not in dst_message_ids:
                            msg_data = src_message_ids.get(src_msg_id)
                            data_message = src_imap_conn.getMessage(msg_data.get('id'))
                            dst_imap_conn.appendMessage(current_mailbox, data_message, msg_data.get('flag'))

                            append_messages_folder += 1
                            append_size_folder += msg_data.get('size_byte')

                            logger.info('Thread %s, append message id:%s size:%i', user, src_msg_id,
                                        msg_data.get('size_byte'))
                        else:
                            count_duplicate_msg = duplicate_msg.get(src_msg_id)
                            if not count_duplicate_msg:
                                count_duplicate_msg = 1
                            else:
                                count_duplicate_msg += 1
                            duplicate_msg[src_msg_id] = count_duplicate_msg

                    logger.info('Thread %s, Appends to destination count:%i size:%i',
                                user, append_messages_folder, append_size_folder)
                    append_messages += append_messages_folder
                    append_size_byte += append_size_folder

                dst_imap_conn.closeFolder()
                src_imap_conn.closeFolder()

        src_imap_conn.logOut()
        dst_imap_conn.logOut()
    logger.info('Thread %s, Finish sync append message count:%i size:%i',
                user, append_messages, append_size_byte)

    second_execute = secondsToStr(time.time() - start_time)
    return 'Finish Sync: {uSr}, append messages: {countmsg}, ' \
           'size: {sZ} byte time executed: {tEx}'.format(uSr=user,
                                                         countmsg=append_messages,
                                                         sZ=append_size_byte,
                                                         tEx=second_execute)


class main:
    NAME = 'Sync iredadmin LDAP backend user'
    VERSION = '0.1'

    def __init__(self):
        self.ldap_src = None
        self.ldap_dst = None
        self.src_imap_conn = None
        self.dst_imap_conn = None
        self.param_filter_email = {}

    def __del__(self):
        self.ldap_src = None
        self.ldap_dst = None
        self.src_imap_conn = None
        self.dst_imap_conn = None

    def setFilter(self, argv):
        if argv.age == 'min':
            self.param_filter_email['minage'] = argv.countage
        else:
            self.param_filter_email['maxage'] = argv.countage

    def run(self):
        logger.info('Start sync iRedMail')

        # Instantiate the parser
        parser = argparse.ArgumentParser(description='Sync user ldap backend iredadmin')
        subparser = parser.add_subparsers(help='List of commands')

        parser.add_argument('-d', '--domainsync', help='Sync domain [only domain]', nargs='?', const='*', type=str)
        parser.add_argument('-u', '--usersync', help='Sync user [only user]', nargs='?', const='*', type=str)
        parser.add_argument('-m', '--mailsync', help='sync mail on imap protocol', action='store_true')

        parser_filter = subparser.add_parser('filter', help='parameters filter email sync')
        parser_filter.add_argument('age', type=str, choices=['min', 'max'], help='type age email')
        parser_filter.add_argument('countage', type=int, help='count days age mail (min or max)')
        parser_filter.set_defaults(func=self.setFilter)

        program_args = parser.parse_args()
        param_usernsync = program_args.usersync
        param_domainsync = program_args.domainsync
        param_mailsync = program_args.mailsync

        if param_domainsync or param_usernsync:
            self.ldap_src = LdapServer()
            res = self.ldap_src.connect(settings.SERVER_SOURCE)
            if not res[0]:
                logger.error('Error connect to ldap server source : %s' % res[1])

            self.ldap_dst = LdapServer()
            res = self.ldap_dst.connect(settings.SERVER_DESTINATION)
            if not res[0]:
                logger.error('Error connect to ldap server destination : %s' % res[1])

            if param_domainsync:
                self.__syncDomain(param_domainsync)
            else:
                param_domainsync = '*'

            if param_usernsync:
                self.__syncUsers(param_domainsync, param_usernsync)

            logger.info(self.ldap_src)
            logger.info(self.ldap_dst)

        if param_mailsync:
            if not param_usernsync:
                param_usernsync = '*'
            self.__syncIMAPEmail(param_domainsync, param_usernsync)

    def __syncDomain(self, domain_sync):
        # sync domain
        if domain_sync == '*':
            src_domains = self.ldap_src.getDomainList()
            if len(src_domains) == 0:
                logger.warning('Source LDAP not contains domain list status in enabled')
                return
        else:
            src_domains = self.ldap_src.getDomain(domain_sync)
            if len(src_domains) == 0:
                logger.warning('Source LDAP not contains domain list status in enabled')
                return

        for src_domain in src_domains:
            attr = src_domain['attributes']
            dn = self.ldap_src.getDomainNameFromFullDN(src_domain['dn'])
            logger.info('Sync domain : %s' % dn)
            resultCheck = self.ldap_dst.checkDomain(dn, attr)
            if resultCheck[0] == 'MODIFY':
                self.ldap_dst.updateDomain(resultCheck[1], resultCheck[2])
                logger.info('Modify attribute domain %s - %s', str(resultCheck[1]), str(resultCheck[2]))
            elif resultCheck[0] == 'ADD':
                self.ldap_dst.addDomain(resultCheck[1], resultCheck[2])
                logger.info('Create domain %s - %s', str(resultCheck[1]), str(resultCheck[2]))

    def __syncUsers(self, domain, user):
        user_list = self.ldap_src.getUserList(domain)
        for src_user in user_list:
            dn_mail, usr_mail = self.ldap_src.getUserMailNameFromFullDN(src_user['dn'])
            src_attr = src_user['attributes']

            if user and user != '*' and usr_mail != user:
                continue

            logger.info('Sync user: %s', usr_mail)
            resultCheck = self.ldap_dst.checkUser(usr_mail, src_attr)
            if resultCheck[0] == 'MODIFY':
                logger.info('Modify user : %s - %s', str(resultCheck[1]), str(resultCheck[2]))
                self.ldap_dst.updateUser(resultCheck[1], resultCheck[2])
            elif resultCheck[0] == 'ADD':
                logger.info('Create user : %s - %s', str(resultCheck[1]), str(resultCheck[2]))
                self.ldap_dst.addUser(resultCheck[1], resultCheck[2]
                                      , settings.SERVER_DESTINATION)

    def __syncIMAPEmail(self, domain, user):
        # The specified user has advantage over the domain
        if not user or user == '*':
            user_list = []
            raw_user_list = self.ldap_src.getUserList(domain)
            for item_user_list in raw_user_list:
                dn_mail, usr_mail = self.ldap_src.getUserMailNameFromFullDN(item_user_list['dn'])
                user_list.append(usr_mail)
        else:
            user_list = [user]

        setting_thread = {
            'SERVER_IMAP_SOURCE': settings.SERVER_IMAP_SOURCE,
            'SERVER_IMAP_DESTINATION': settings.SERVER_IMAP_DESTINATION,
            'filter_email': self.param_filter_email
        }

        r_sync = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=settings.max_thread_sync_mail) as executor:

            threadSync = {executor.submit(runThreadSyncMail, user=item_user, settings_imap=setting_thread): item_user
                          for item_user in user_list}

            for future in concurrent.futures.as_completed(threadSync):
                user_sync = threadSync[future]
                try:
                    result_sync = future.result()
                except Exception as exc:
                    logger.error('%s generated an exception: %s', user_sync, str(exc))
                    r_sync[user_sync] = {'result': False, 'msg': str(exc)}
                else:
                    logger.info('%s sync: %s', user_sync, result_sync)
                    r_sync[user_sync] = {'result': True, 'msg': result_sync}

        logger.info('Finish all sync')
        for item_user in user_list:
            result_sync_user = r_sync.get(item_user)
            if result_sync_user:
                logger.info('%s [%s]:%s', item_user, result_sync_user.get('result'), result_sync_user.get('msg'))
            else:
                logger.info('%s [ERROR]: NOT', item_user)


if __name__ == '__main__':
    app = main()
    app.run()
    sys.exit(0)
