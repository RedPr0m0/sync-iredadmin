# General settings.
#
# Mail address send protocol.
mailsend = 'xxx@iredmail.org'

# Setting source server LDAP.
SERVER_SOURCE = dict(
    server='192.168.0.11',
    port=389,
    basedn='o=domains,dc=mail,dc=belaz,dc=com,dc=ua',
    bind_dn='cn=Manager,dc=mail,dc=belaz,dc=com,dc=ua',
    bind_password='XGLXcF4LScoSCboDWDybIiXLMebkQ3',
    use_ssl=False,
    storage_mail_base_directory='/var/vmail/vmail1',
    #over_ssh=dict(
    #    server='',
    #    port=22,
    #    username='',
    #    password='',
    #    privatekey=''
    #)
)

# Setting destination server LDAP.
SERVER_DESTINATION = dict(
    server='176.9.72.26',
    port=636,
    basedn='o=domains,dc=tdgm,dc=com,dc=ua',
    bind_dn='cn=Manager,dc=tdgm,dc=com,dc=ua',
    bind_password='a15Dmp4bLp8s9Mc2ozMsWYTXZOf10XVu',
    use_ssl=True,
    storage_mail_base_directory='/var/vmail/vmail1',
    #over_ssh=dict(
    #    server='',
    #    port=22,
    #    username='',
    #    password='',
    #    privatekey=''
    #)
)

