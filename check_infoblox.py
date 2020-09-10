#!/usr/bin/python3

import re
import sys
import argparse
from pysnmp.hlapi import *


def get_args():
    parser = argparse.ArgumentParser(
        description='Available parameters to be passed to check_infoblox.py:')
    parser.add_argument('-H', '--host', required=True, action='store',
                        help='Hostname of SNMP enabled IB device')
    parser.add_argument('-V', '--snmpver', type=int, required=True, action='store',
                        help='SNMP version 1, 2, or 3')
    parser.add_argument('-C', '--check', required=True, action='store',
                        help='Type of check to perform; cpu, mem, swap, dns, dhcp, ' +
                             'dbusage, diskusage, systemp, pdu1/pdu2, replication')
    parser.add_argument('-w', '--warning', type=int, required=False, action='store',
                        help='Warning Threshold in percentage')
    parser.add_argument('-c', '--critical', type=int, required=False, action='store',
                        help='Critical Threshold in percentage')
    parser.add_argument('-l', '--level', required=True, action='store',
                        help='SNMP security level: none, authNoPriv, or authPriv')
    parser.add_argument('-u', '--user', required=False, action='store',
                        help='SNMP user')
    parser.add_argument('-a', '--auth', required=False, action='store',
                        help='Set authentication protocol: MD5 or SHA')
    parser.add_argument('-A', '--authpass', required=False, action='store',
                        help='Set authentication protocol pass phrase')
    parser.add_argument('-x', '--priv', required=False, action='store',
                        help='Set privacy protocol: DES or AES')
    parser.add_argument('-X', '--privpass', required=False, action='store',
                        help='Set privacy protocol pass phrase')
    args = parser.parse_args()

    if args.snmpver == 3 and (args.level is None or args.user is None):
        parser.error("--snmpver 3 requires --level and --user.")
    elif args.level == 'authNoPriv' and (args.auth is None or args.authpass is None):
        parser.error("--level authNoPriv requires --auth and --authpass.")
    elif args.auth != 'MD5' and args.auth != 'SHA':
        parser.error("--auth only accepts MD5 or SHA.")
    elif args.level == 'authPriv' and (args.priv is None or args.privpass is None):
        parser.error("--level authPriv requires --auth, --authpass, --priv, and --privpass.")

    check_type = ['cpu',
                  'mem',
                  'swap',
                  'dns',
                  'dhcp',
                  'dbusage',
                  'diskusage',
                  'systemp',
                  'pdu1',
                  'pdu2',
                  'replication']
    types = set(check_type)

    if args.check not in types:
        parser.error("--check " + args.check + " is not supported.")

    threshold_checks = ['cpu', 'mem', 'swap', 'dbusage', 'diskusage', 'systemp']
    thresholds = set(threshold_checks)

    if args.check in thresholds and (args.warning is None or args.critical is None):
        parser.error("--check " + args.check + " requires --warning and --critical")
    elif args.check not in thresholds and (args.warning is not None or args.critical is not None):
        parser.error("--check " + args.check + " does not take --warning and --critical")

    if args.check in thresholds:
        if args.warning not in range(1,101) or args.critical not in range(1,101):
            parser.error("--warning and --critical must in the range 1 through 100")
        elif (args.warning >= args.critical):
            parser.error("--warning percentage can not be equal or greater than --critical percentage")

    return args

def snmpv3(host, oid, level, user, auth, authpass, priv, privpass):
    snmpwalk = getCmd(SnmpEngine(),
                      UsmUserData(user, authpass, privpass,
                                  authProtocol=usmHMACSHAAuthProtocol,
                                  privProtocol=usmAesCfb128Protocol),
                      UdpTransportTarget((host, 161)),
                      ContextData(),
                      ObjectType(ObjectIdentity(oid)))

    error_indication, error_status, error_index, var_binds = next(snmpwalk)

    if error_indication:
        sys.exit(error_indication)

    oid, value = var_binds[0]

    return value

def basic_check(local_check, snmpdata, warning, critical):
    if snmpdata >= critical:
        print("CRITICAL - %s utilization is at %d%%." % (local_check, snmpdata))
        sys.exit(2)
    elif snmpdata >= warning:
        print("WARNING - %s utilization is at %d%%." % (local_check, snmpdata))
        sys.exit(1)
    elif snmpdata < warning:
        print("OK - %s utilization is at %d%%." % (local_check, snmpdata))
        sys.exit(0)
    else:
        print("UNKNOWN - %s utilization is at %d%%." % (local_check, snmpdata))
        sys.exit(3)

def service_check(local_check, snmpdata, warning=None, critical=None):
    if snmpdata == 1:
        print("OK - %s is running." % (local_check))
        sys.exit(0)
    elif snmpdata == 2:
        print("WARNING - %s has a warning state." % (local_check))
        sys.exit(1)
    elif snmpdata == 3 or snmpdata == 4:
        print("CRITICAL - %s is inactive or failed state" % (local_check))
        sys.exit(2)
    else:
        print("UNKNOWN - %s is in an unknown state." % (local_check))
        sys.exit(3)

def space_check(local_check, snmpdata, warning, critical):
    snmpdata = int(re.findall('[0-9]+', str(snmpdata))[0])

    basic_check(local_check, snmpdata, warning, critical)


def temp_check(local_check, snmpdata, warning, critical):
    snmpdata = int(re.findall('[0-9]+', str(snmpdata))[0])

    fahrenheit = (snmpdata * 9/5) + 32

    if snmpdata >= critical:
        print("CRITICAL - %s is at %d\N{DEGREE SIGN}F" % (local_check, fahrenheit))
        sys.exit(2)
    elif snmpdata >= warning:
        print("WARNING - %s is at %d\N{DEGREE SIGN}F" % (local_check, fahrenheit))
        sys.exit(1)
    elif snmpdata < warning:
        print("OK - %s is at %d\N{DEGREE SIGN}F" % (local_check, fahrenheit))
        sys.exit(0)
    else:
        print("UNKNOWN - %s is at %d\N{DEGREE SIGN}F" % (local_check, fahrenheit))
        sys.exit(3)


def pdu_check(local_check, snmpdata, warning=None, critical=None):
    if str(snmpdata).endswith('OK'):
        print("OK - %s is functioning properly." % local_check)
        sys.exit(0)
    elif str(snmpdata).startswith('No'):
        print("CRITICAL - %s is not available or failed." % local_check)
        sys.exit(2)
    else:
        print("UNKNOWN - %s has unknown status: %s" % (local_check, snmpdata))
        sys.exit(3)


def replication_check(host, level, user, auth, authpass, priv, privpass):
    member_status = {}
    for (error_indication,
         error_status,
         error_index,
         var_binds) in nextCmd(SnmpEngine(),
                      UsmUserData(user, authpass, privpass,
                                  authProtocol=usmHMACSHAAuthProtocol,
                                  privProtocol=usmAesCfb128Protocol),
                      UdpTransportTarget((host, 161)),
                      ContextData(),
                      ObjectType(ObjectIdentity(".1.3.6.1.4.1.7779.3.1.1.2.1.2.1.1")),
                      ObjectType(ObjectIdentity(".1.3.6.1.4.1.7779.3.1.1.2.1.2.1.2")),
                      lexicographicMode=False):

        if error_indication:
            sys.exit(error_indication)

        for result in var_binds:
            if re.search("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", str(result[1])):
                ipaddr = str(result[1])
            elif str(result[1]) == 'Online' or 'Offline':
                status = str(result[1])

        member_status[ipaddr] = status

    if 'Offline' in member_status.values():
        print("CRITICAL - %s" % member_status)
        sys.exit(2)
    elif 'Online' in member_status.values():
        print("OK - %s" % member_status)
        sys.exit(0)
    else:
        print("UNKNOWN - %s" % member_status)
        sys.exit(3)

def main():
    args = get_args()

    checkoids =  {
        "cpu": ".1.3.6.1.4.1.7779.3.1.1.2.1.8.1.1.0",
        "mem": ".1.3.6.1.4.1.7779.3.1.1.2.1.8.2.1.0",
        "swap": ".1.3.6.1.4.1.7779.3.1.1.2.1.8.3.1.0",
        "dns": ".1.3.6.1.4.1.7779.3.1.1.2.1.9.1.2.2",
        "dhcp": ".1.3.6.1.4.1.7779.3.1.1.2.1.9.1.2.1",
        "dbusage": ".1.3.6.1.4.1.7779.3.1.1.2.1.10.1.3.18",
        "diskusage": ".1.3.6.1.4.1.7779.3.1.1.2.1.10.1.3.10",
        "systemp": ".1.3.6.1.4.1.7779.3.1.1.2.1.10.1.3.41",
        "pdu1": ".1.3.6.1.4.1.7779.3.1.1.2.1.10.1.3.36",
        "pdu2": ".1.3.6.1.4.1.7779.3.1.1.2.1.10.1.3.37"
    }

    if args.check == 'replication':
        replication_check(args.host, args.level, args.user, args.auth, args.authpass, args.priv, args.privpass)

    if args.snmpver == 1:
        walkresults = ()
    elif args.snmpver == 2:
        walkresults = ()
    elif args.snmpver == 3:
        walkresults = snmpv3(args.host,
                         checkoids.get(args.check),
                         args.level,
                         args.user,
                         args.auth,
                         args.authpass,
                         args.priv,
                         args.privpass)
    else:
        sys.exit("--snmpver must be 1, 2, or 3")

    checkdict = {
        "cpu": basic_check,
        "mem": basic_check,
        "swap": basic_check,
        "dns": service_check,
        "dhcp": service_check,
        "dbusage": space_check,
        "diskusage": space_check,
        "systemp": temp_check,
        "pdu1": pdu_check,
        "pdu2": pdu_check
    }

    checkdict[args.check](args.check,walkresults,args.warning,args.critical)


if __name__ == '__main__':
    main()
[root@mdrprdlmon01 libexec]# cat check_infoblox.py ^C
[root@mdrprdlmon01 libexec]# cp check_infoblox.py /tmp/
[root@mdrprdlmon01 libexec]# cat check_infoblox.py
#!/usr/bin/python3

import re
import sys
import argparse
from pysnmp.hlapi import *


def get_args():
    parser = argparse.ArgumentParser(
        description='Available parameters to be passed to check_infoblox.py:')
    parser.add_argument('-H', '--host', required=True, action='store',
                        help='Hostname of SNMP enabled IB device')
    parser.add_argument('-V', '--snmpver', type=int, required=True, action='store',
                        help='SNMP version 1, 2, or 3')
    parser.add_argument('-C', '--check', required=True, action='store',
                        help='Type of check to perform; cpu, mem, swap, dns, dhcp, ' +
                             'dbusage, diskusage, systemp, pdu1/pdu2, replication')
    parser.add_argument('-w', '--warning', type=int, required=False, action='store',
                        help='Warning Threshold in percentage')
    parser.add_argument('-c', '--critical', type=int, required=False, action='store',
                        help='Critical Threshold in percentage')
    parser.add_argument('-l', '--level', required=True, action='store',
                        help='SNMP security level: none, authNoPriv, or authPriv')
    parser.add_argument('-u', '--user', required=False, action='store',
                        help='SNMP user')
    parser.add_argument('-a', '--auth', required=False, action='store',
                        help='Set authentication protocol: MD5 or SHA')
    parser.add_argument('-A', '--authpass', required=False, action='store',
                        help='Set authentication protocol pass phrase')
    parser.add_argument('-x', '--priv', required=False, action='store',
                        help='Set privacy protocol: DES or AES')
    parser.add_argument('-X', '--privpass', required=False, action='store',
                        help='Set privacy protocol pass phrase')
    args = parser.parse_args()

    if args.snmpver == 3 and (args.level is None or args.user is None):
        parser.error("--snmpver 3 requires --level and --user.")
    elif args.level == 'authNoPriv' and (args.auth is None or args.authpass is None):
        parser.error("--level authNoPriv requires --auth and --authpass.")
    elif args.auth != 'MD5' and args.auth != 'SHA':
        parser.error("--auth only accepts MD5 or SHA.")
    elif args.level == 'authPriv' and (args.priv is None or args.privpass is None):
        parser.error("--level authPriv requires --auth, --authpass, --priv, and --privpass.")

    check_type = ['cpu',
                  'mem',
                  'swap',
                  'dns',
                  'dhcp',
                  'dbusage',
                  'diskusage',
                  'systemp',
                  'pdu1',
                  'pdu2',
                  'replication']
    types = set(check_type)

    if args.check not in types:
        parser.error("--check " + args.check + " is not supported.")

    threshold_checks = ['cpu', 'mem', 'swap', 'dbusage', 'diskusage', 'systemp']
    thresholds = set(threshold_checks)

    if args.check in thresholds and (args.warning is None or args.critical is None):
        parser.error("--check " + args.check + " requires --warning and --critical")
    elif args.check not in thresholds and (args.warning is not None or args.critical is not None):
        parser.error("--check " + args.check + " does not take --warning and --critical")

    if args.check in thresholds:
        if args.warning not in range(1,101) or args.critical not in range(1,101):
            parser.error("--warning and --critical must in the range 1 through 100")
        elif (args.warning >= args.critical):
            parser.error("--warning percentage can not be equal or greater than --critical percentage")

    return args

def snmpv3(host, oid, level, user, auth, authpass, priv, privpass):
    snmpwalk = getCmd(SnmpEngine(),
                      UsmUserData(user, authpass, privpass,
                                  authProtocol=usmHMACSHAAuthProtocol,
                                  privProtocol=usmAesCfb128Protocol),
                      UdpTransportTarget((host, 161)),
                      ContextData(),
                      ObjectType(ObjectIdentity(oid)))

    error_indication, error_status, error_index, var_binds = next(snmpwalk)

    if error_indication:
        sys.exit(error_indication)

    oid, value = var_binds[0]

    return value

def basic_check(local_check, snmpdata, warning, critical):
    if snmpdata >= critical:
        print("CRITICAL - %s utilization is at %d%%." % (local_check, snmpdata))
        sys.exit(2)
    elif snmpdata >= warning:
        print("WARNING - %s utilization is at %d%%." % (local_check, snmpdata))
        sys.exit(1)
    elif snmpdata < warning:
        print("OK - %s utilization is at %d%%." % (local_check, snmpdata))
        sys.exit(0)
    else:
        print("UNKNOWN - %s utilization is at %d%%." % (local_check, snmpdata))
        sys.exit(3)

def service_check(local_check, snmpdata, warning=None, critical=None):
    if snmpdata == 1:
        print("OK - %s is running." % (local_check))
        sys.exit(0)
    elif snmpdata == 2:
        print("WARNING - %s has a warning state." % (local_check))
        sys.exit(1)
    elif snmpdata == 3 or snmpdata == 4:
        print("CRITICAL - %s is inactive or failed state" % (local_check))
        sys.exit(2)
    else:
        print("UNKNOWN - %s is in an unknown state." % (local_check))
        sys.exit(3)

def space_check(local_check, snmpdata, warning, critical):
    snmpdata = int(re.findall('[0-9]+', str(snmpdata))[0])

    basic_check(local_check, snmpdata, warning, critical)


def temp_check(local_check, snmpdata, warning, critical):
    snmpdata = int(re.findall('[0-9]+', str(snmpdata))[0])

    fahrenheit = (snmpdata * 9/5) + 32

    if snmpdata >= critical:
        print("CRITICAL - %s is at %d\N{DEGREE SIGN}F" % (local_check, fahrenheit))
        sys.exit(2)
    elif snmpdata >= warning:
        print("WARNING - %s is at %d\N{DEGREE SIGN}F" % (local_check, fahrenheit))
        sys.exit(1)
    elif snmpdata < warning:
        print("OK - %s is at %d\N{DEGREE SIGN}F" % (local_check, fahrenheit))
        sys.exit(0)
    else:
        print("UNKNOWN - %s is at %d\N{DEGREE SIGN}F" % (local_check, fahrenheit))
        sys.exit(3)


def pdu_check(local_check, snmpdata, warning=None, critical=None):
    if str(snmpdata).endswith('OK'):
        print("OK - %s is functioning properly." % local_check)
        sys.exit(0)
    elif str(snmpdata).startswith('No'):
        print("CRITICAL - %s is not available or failed." % local_check)
        sys.exit(2)
    else:
        print("UNKNOWN - %s has unknown status: %s" % (local_check, snmpdata))
        sys.exit(3)


def replication_check(host, level, user, auth, authpass, priv, privpass):
    member_status = {}
    for (error_indication,
         error_status,
         error_index,
         var_binds) in nextCmd(SnmpEngine(),
                      UsmUserData(user, authpass, privpass,
                                  authProtocol=usmHMACSHAAuthProtocol,
                                  privProtocol=usmAesCfb128Protocol),
                      UdpTransportTarget((host, 161)),
                      ContextData(),
                      ObjectType(ObjectIdentity(".1.3.6.1.4.1.7779.3.1.1.2.1.2.1.1")),
                      ObjectType(ObjectIdentity(".1.3.6.1.4.1.7779.3.1.1.2.1.2.1.2")),
                      lexicographicMode=False):

        if error_indication:
            sys.exit(error_indication)

        for result in var_binds:
            if re.search("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", str(result[1])):
                ipaddr = str(result[1])
            elif str(result[1]) == 'Online' or 'Offline':
                status = str(result[1])

        member_status[ipaddr] = status

    if 'Offline' in member_status.values():
        print("CRITICAL - %s" % member_status)
        sys.exit(2)
    elif 'Online' in member_status.values():
        print("OK - %s" % member_status)
        sys.exit(0)
    else:
        print("UNKNOWN - %s" % member_status)
        sys.exit(3)

def main():
    args = get_args()

    checkoids =  {
        "cpu": ".1.3.6.1.4.1.7779.3.1.1.2.1.8.1.1.0",
        "mem": ".1.3.6.1.4.1.7779.3.1.1.2.1.8.2.1.0",
        "swap": ".1.3.6.1.4.1.7779.3.1.1.2.1.8.3.1.0",
        "dns": ".1.3.6.1.4.1.7779.3.1.1.2.1.9.1.2.2",
        "dhcp": ".1.3.6.1.4.1.7779.3.1.1.2.1.9.1.2.1",
        "dbusage": ".1.3.6.1.4.1.7779.3.1.1.2.1.10.1.3.18",
        "diskusage": ".1.3.6.1.4.1.7779.3.1.1.2.1.10.1.3.10",
        "systemp": ".1.3.6.1.4.1.7779.3.1.1.2.1.10.1.3.41",
        "pdu1": ".1.3.6.1.4.1.7779.3.1.1.2.1.10.1.3.36",
        "pdu2": ".1.3.6.1.4.1.7779.3.1.1.2.1.10.1.3.37"
    }

    if args.check == 'replication':
        replication_check(args.host, args.level, args.user, args.auth, args.authpass, args.priv, args.privpass)

    if args.snmpver == 1:
        walkresults = ()
    elif args.snmpver == 2:
        walkresults = ()
    elif args.snmpver == 3:
        walkresults = snmpv3(args.host,
                         checkoids.get(args.check),
                         args.level,
                         args.user,
                         args.auth,
                         args.authpass,
                         args.priv,
                         args.privpass)
    else:
        sys.exit("--snmpver must be 1, 2, or 3")

    checkdict = {
        "cpu": basic_check,
        "mem": basic_check,
        "swap": basic_check,
        "dns": service_check,
        "dhcp": service_check,
        "dbusage": space_check,
        "diskusage": space_check,
        "systemp": temp_check,
        "pdu1": pdu_check,
        "pdu2": pdu_check
    }

    checkdict[args.check](args.check,walkresults,args.warning,args.critical)


if __name__ == '__main__':
    main()
