# Kerberos authentication
Since version 6.3, Metasploit has included authentication via Kerberos for multiple types of modules. Kerberos
authentication allows Metasploit users to request and utilize Ticket Granting Tickets (TGTs) and Ticket Granting
Services (TGSs) to authenticate with supported modules. Metasploit uses an internal caching and storage machanism but
tickets are stored able to be both exported and imported from [MIT Credential Cache][1] (CCACHE) files. A converter for
Kirbi to and from CCACHE files is also available in the `auxiliary/admin/kerberos/ticket_converter` module.

The following types of modules support Kerberos authentication:

* HTTP
* LDAP
* MSSQL
* SMB
* WinRM

## Datastore options
Kerberos authentication requires additional options to be set. Some of them are prefixed with the protocol the module
is authenticating. For example, the PSexec module which operates over SMB would use the "SMB" prefix.

Required options:
* `$PrefixAuth` -- The authentication modes this module supports. Set it to "kerberos" to use Kerberos authentication.
* `$PrefixRhostname` -- The hostname of the target system. This value should be either the hostname `WIN-MIJZ318SQH` or 
   the FQDN like `WIN-MIJZ318SQH.msflab.local`.
* `$PrefixDomain` -- The domain name of the target system, e.g. `msflab.local`.
* `DomainControllerRhost` -- The IP address of the domain controller to use for kerberos authentication.

Optional options:
* `$PrefixKrb5Ccname` -- The path to a CCACHE file to use for authentication. This is comparable to setting the
   `KRB5CCNAME` environment variable for other tools. If specified, the tickets it contains will be used.
* `KrbCacheMode` -- The cache storage mode to use, one of the following four options:
  * `none` -- No cache storage is used, new tickets are requested and no tickets are stored.
  * `read-only` -- Stored tickets from the cache will be used, but no new tickets are stored.
  * `write-only` -- New tickets are requested and they are stored for reuse.
  * `read-write` -- Stored tickets from the cache will be used and new tickets will be stored for reuse.

## Ticket management
When a write-enabled `KrbCacheMode` is used, tickets that are issued to Metasploit will be stored for reuse. The `klist`
command can be used to view tickets. It is a top level command and can be run even if a module is in use.

```
msf6 > klist
Kerberos Cache
==============
host            principal               sname                              issued                     status       path
----            ---------               -----                              ------                     ------       ----
192.168.159.10  smcintyre@MSFLAB.LOCAL  krbtgt/MSFLAB.LOCAL@MSFLAB.LOCAL   2022-12-15 18:25:48 -0500  >>expired<<  /home/smcintyre/.msf4/loot/20221215182546_default_192.168.159.10_mit.kerberos.cca_867855.bin
192.168.159.10  smcintyre@MSFLAB.LOCAL  cifs/DC.msflab.local@MSFLAB.LOCAL  2022-12-15 18:25:48 -0500  >>expired<<  /home/smcintyre/.msf4/loot/20221215182546_default_192.168.159.10_mit.kerberos.cca_699376.bin
192.168.159.10  smcintyre@MSFLAB.LOCAL  krbtgt/msflab.local@MSFLAB.LOCAL   2022-12-16 14:51:50 -0500  valid        /home/smcintyre/.msf4/loot/20221216145149_default_192.168.159.10_mit.kerberos.cca_782487.bin
192.168.159.10  smcintyre@MSFLAB.LOCAL  cifs/DC.msflab.local@MSFLAB.LOCAL  2022-12-16 17:07:48 -0500  valid        /home/smcintyre/.msf4/loot/20221216170747_default_192.168.159.10_mit.kerberos.cca_156303.bin
192.168.159.10  smcintyre@MSFLAB.LOCAL  cifs/DC@MSFLAB.LOCAL               2022-12-16 17:08:26 -0500  valid        /home/smcintyre/.msf4/loot/20221216170825_default_192.168.159.10_mit.kerberos.cca_196712.bin
192.168.159.10  smcintyre@MSFLAB.LOCAL  krbtgt/msflab.local@MSFLAB.LOCAL   2022-12-16 15:03:03 -0500  valid        /home/smcintyre/.msf4/loot/20221216150302_default_192.168.159.10_mit.kerberos.cca_729805.bin
192.168.159.10  aliddle@MSFLAB.LOCAL    krbtgt/msflab.local@MSFLAB.LOCAL   2022-12-16 15:25:16 -0500  valid        /home/smcintyre/.msf4/loot/20221216152515_default_192.168.159.10_mit.kerberos.cca_934698.bin
```

More detailed information can be displayed by using the verbose (`-v` / `--verbose`) option.

```
msf6 > klist -v
Kerberos Cache
==============
Cache[0]:
  Primary Principal: Administrator@ADF3.LOCAL
  Ccache version: 4

  Creds: 1
    Credential[0]:
      Server: krbtgt/ADF3.LOCAL@ADF3.LOCAL
      Client: Administrator@ADF3.LOCAL
      Ticket etype: 18 (AES256)
      Key: 9c66cb7de8f4d3100690771a753012eafa44a3d128342939ff9230b39aeb1713
      Subkey: false
      Ticket Length: 1090
      Ticket Flags: 0x50e10000 (FORWARDABLE, PROXIABLE, RENEWABLE, INITIAL, PRE_AUTHENT, CANONICALIZE)
      Addresses: 0
      Authdatas: 0
      Times:
        Auth time: 2022-12-13 12:57:49 +0000
        Start time: 2022-12-13 12:57:49 +0000
        End time: 2022-12-13 22:57:49 +0000
        Renew Till: 2022-12-14 12:57:49 +0000
      Ticket:
        Ticket Version Number: 5
        Realm: ADF3.LOCAL
        Server Name: krbtgt/ADF3.LOCAL
        Encrypted Ticket Part:
          Ticket etype: 18 (AES256)
          Key Version Number: 2
          Cipher:
            [truncated]
```

The `klist` command can also be used for deleting tickets from the cache.

## Ticket cache storage
Metasploit stores tickets for future use in a user configurable way as controlled by the `KrbCacheMode` datastore
option. When a user attempts to use Kerberos to authenticate to a remote service such as SMB, if the cache mode is
read-enabled (e.g. set to `read-only` or `read-write`) and Metasploit is connected to a database, it will attempt to
fetch an existing ticket using the following steps.

1. First Metasploit will use the datastore options, including the target host and username to search though the stored
   tickets for an SMB-specific Ticket Granting Service (TGS). If one is found, it will be used. Tickets that are expired
   will not be used.
2. If no TGS is found, Metasploit will repeat the search process looking for a Ticket Granting Ticket (TGT). If one is
   found, it will be used to contact the Key Distribution Center (KDC) and request a TGS for authentication to the SMB
   service.
3. If no TGT is found, Metasploit will contact the KDC and authenticate using the username and password from the
   datastore to request a TGT then an SMB-specific TGS before authenticating to the SMB service.

If the cache mode is write-enabled (e.g. set to `write-only` or `read-write`) then any ticket, either TGT or TGS that is
obtained either from the KDC or through other means, is stored for use in the cache. **If the cache mode is not
write-enabled, tickets will not be stored.** Tickets are saved as loot, allowing them to be stored even if the database
is not connected, however without the database, Metasploit can not lookup tickets for reuse as required by the
read-enabled modes. Metasploit stores exactly one ticket per CCACHE file.

Use a read-enabled cache mode to avoid unnecessary contact with the KDC. Use a write-enabled cache mode to store tickets
for use with either Metasploit or other tools.

## Using tickets with external tools
When a ticket (either TGT or TGS) is stored, it is saved along with the other loot Metasploit has collected. The raw
CCACHE files can be viewed with the `loot --type mit.kerberos.ccache` command (the `--type` argument filters for the
specified type).

```
msf6 auxiliary(admin/dcerpc/icpr_cert) > loot --type mit.kerberos.ccache

Loot
====

host            service  type                 name             content                   info                                                                  path
----            -------  ----                 ----             -------                   ----                                                                  ----
192.168.159.10           mit.kerberos.ccache                   application/octet-stream  realm: MSFLAB.LOCAL, client: smcintyre, server: krbtgt/msflab.local   /home/smcintyre/.msf4/loot/20221219105440_default_192.168.159.10_mit.kerberos.cca_905330.bin
192.168.159.10           mit.kerberos.ccache                   application/octet-stream  realm: MSFLAB.LOCAL, client: smcintyre, server: cifs/dc.msflab.local  /home/smcintyre/.msf4/loot/20221219105440_default_192.168.159.10_mit.kerberos.cca_539055.bin
```

The path on the far right is where the CCACHE file is on disk. This path can be used with other tools such as Impacket
through the `KRB5CCNAME` environment variable.

For example:

```
[user@localhost]$ KRB5CCNAME=/home/smcintyre/.msf4/loot/20221219105440_default_192.168.159.10_mit.kerberos.cca_539055.bin \
  python examples/smbclient.py  dc.msflab.local -target-ip 192.168.159.10 -k
Impacket v0.9.22.dev1+20200327.103853.7e505892 - Copyright 2021 SecureAuth Corporation

Type help for list of commands
# info
Version Major: 10
Version Minor: 0
Server Name: DC
Server Comment: 
Server UserPath: c:\
Simultaneous Users: 16777216
# 
```

[1]: http://web.mit.edu/KERBEROS/krb5-devel/doc/formats/ccache_file_format.html
