# ------------------------- SETTINGS -------------------------------
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


class main:
    NAME = 'Sync iredadmin LDAP backend user'
    VERSION = '0.1'

    def run(self):
        print('Start sync')

        # Instantiate the parser
        parser = argparse.ArgumentParser(description='Sync user ldap backend iredadmin')
        parser.add_argument('srvsrc', type=str,
                            help='address source server ldap format \'ldap[s]://[ip]:port\'')
        parser.add_argument('srvdest', type=str,
                            help='address destination server ldap format \'ldap[s]://[ip]:port\'')
        parser.add_argument('usersrc', type=str,
                            help='username connect to source server')
        parser.add_argument('pwdsrc', type=str,
                            help='credentials user connect to source server')
        parser.add_argument('userdst', type=str,
                            help='username connect to destination server')
        parser.add_argument('pwddst', type=str,
                            help='credentials user connect to source server')
        parser.add_argument(
            '--log', default=sys.stdout, type=argparse.FileType('w'),
            help='log file write sync user')
        args = parser.parse_args()

        pconnsrc = self.__parceserverldap(args.srvsrc)
        pconndst = self.__parceserverldap(args.srvdest)

        con_src = self.__connectldap(pconnsrc['srv'], args.usersrc, args.pwdsrc, pconnsrc['port'], pconnsrc['ssl'])
        con_dst = self.__connectldap(pconndst['srv'], args.userdst, args.pwddst, pconndst['port'], pconndst['ssl'])

        print(con_src)
        print(con_dst)

        dDNsrc = self.__getBaseDNfromUser(args.usersrc)
        dDNdst = self.__getBaseDNfromUser(args.userdst)

        src_userlist = self.__getuserlistsource(con_src, dDNsrc)
        total_entries = len(src_userlist)
        if total_entries > 0:
            print('Total entries user %i' % total_entries)
            for usr in src_userlist:
                self.__syncUserLDAPEntries(con_src, con_dst, dDNdst, usr)

        con_src.unbind()
        con_dst.unbind()

    def __syncUserLDAPEntries(self, consrc, condst, dndst, usrEnt):
        # search user from dst
        entusr = self.__finduserDN(condst, dndst, usrEnt['mail'])
        print(entusr)

    def __connectldap(self, server: str, user: str, pwd: str, port=363, ssl=False):
        s = Server(server, port, use_ssl=ssl, get_info=ALL)
        if ssl:
            c = Connection(s, user=user, password=pwd, authentication=ldap3.SIMPLE)
        else:
            c = Connection(s, user=user, password=pwd)

        if not c.bind():
            raise RuntimeError('Error connected to server {}: {}'.format(server, c.result))

        return c

    def __parceserverldap(self, paramserver: str):
        p = paramserver.split(':')
        if len(p) != 3:
            raise RuntimeError('Error parametr server \'ldap[s]://[ip]:port\': {}'.format(paramserver))

        ssl = False
        if p[0] == 'ldaps':
            ssl = True

        srv = p[1].replace('//', '')
        port = int(p[2])
        return dict(srv=srv, port=port, ssl=ssl)

    def __getBaseDNfromUser(self, usename: str):
        bDN = ''
        p = usename.split(',')
        for dc in p:
            if dc.find('dc=') != -1:
                bDN += ',' + dc

        return bDN

    def __getuserlistsource(self, conn, basedn: str):
        searchDN = 'o=domains' + basedn;
        conn.search(search_base=searchDN,
                    search_filter='(&(objectClass=mailUser)(!(domainStatus=disabled))(enabledService=mail))',
                    search_scope=ldap3.SUBTREE,
                    paged_size=1000)

        return conn.response

    def __finduserDN(self, conn, basedn: str, mail: str):
        searchDN = 'o=domains' + basedn;
        filtr = '(&(objectClass=mailUser)(accountStatus=active)(!(domainStatus=disabled))(enabledService=mail)(mail={}}))'.format(
            mail)
        conn.search(search_base=searchDN,
                    search_filter=filtr,
                    search_scope=ldap3.SUBTREE,
                    paged_size=1000)

        return conn.response


# print("* Connecting to LDAP server:", LDAP_SOURCE)
# server_source = Server(LDAP_SOURCE, LDAP_PORT)
# conn_source = Connection(server_source, user=BASEDN_SOURCE, password=BINDPW_SOURCE)

# print(conn_source)

# print("* Connecting to LDAP server:", LDAP_DEST)
# server_dest = Server(LDAP_DEST, LDAP_PORT_DEST, use_ssl=True)
# conn_dest = Connection(server_dest, user=BINDDN_DEST, password=BINDPW_DEST, version=3, authentication=ldap3.SIMPLE)
# BINDDN_DEST BINDPW_DEST

# print(conn_dest)

# Start sync bind dn users

# conn_source.search(search_base='o=domains,dc=mail,dc=belaz,dc=com,dc=ua',
#                   search_filter='(&(objectClass=mailUser)(!(domainStatus=disabled))(enabledService=mail))',
#                   search_scope=ldap3.SUBTREE,
#                   paged_size=1000)

# total_entries = len(conn_source.response)
# print('Total entries user %i' % total_entries)

# for entry in conn_source.response:
#    print(entry['dn'], entry['attributes'])


if __name__ == '__main__':
    app = main()
    app.run()
    sys.exit(0)
