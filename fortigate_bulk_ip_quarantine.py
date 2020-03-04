#!/usr/bin/env python2
# Quarantines  on Fortigate a list of specific FortiSIEM malware IP elements
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND
# changelog: v0.3 added support to run the remediation from either a collector or super.
__license__ = "GPL"
__version__ = "0.3"

import re
import sys
import os
import requests
import pg8000 as dbapi
import xml.dom.minidom
from ftntlib import FortiOSREST
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

sys.path.append('/opt/phoenix/data-definition/remediations')
from remediation import HttpRemediation, Logger

# User Settings
MAX_IP_COUNT='15000'
QUARANTINE_SECONDS=86400 # 1 day

# Internal Settings
#phLicenseTool --showDatabasePassword # <== get db passwd on super with this command and paste it in db_password
db_username='phoenix'
db_password=''

mIncidentXML 	= sys.argv[1]
mUser 			= sys.argv[2]
mPassword 		= sys.argv[3]
mAccessIp 		= sys.argv[4]
mHostName 		= sys.argv[5]
mPort 			= sys.argv[6]

def get_super_ip():
	for line in open("/opt/phoenix/config/phoenix_config.txt"):
		if "MON_ROLE=" in line:
			role = line.split('=')[1]
	if not role:
		print('cannot determine FSM Supervisor IP')
		exit()
	if 'phMonitorSupervisor' in role:
		return '127.0.0.1'
	elif 'phMonitorAgent' in role:
		for file in os.listdir('/opt/phoenix/cache/'):
			if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",file):
				return file

def pg_query(username,password,query,host='127.0.0.1',database='phoenixdb',port=5432):
	records=[]
	try:
		conn=dbapi.connect(database=database,host=host, port=port,user=username ,password=password,ssl=False)
		curr=conn.cursor()
		curr.execute(query)
		return list(curr.fetchall())

	except Exception as err:
		print('DB Query failed',err)
		exit()

def is_good_ip(ip):
	pieces = ip.split('.')
	if len(pieces) != 4: return False
	try: return all(0<=int(p)<256 for p in pieces)
	except ValueError: return False

def run_fg_remediation(mIncidentXML, mAccessIp, mPort, mUser, mPassword, ioc_list, quarantine_seconds):

	if len(ioc_list) > 0:
		fgt = FortiOSREST()
		#fgt.debug('on')
		fgt.login(mAccessIp, mPort, mUser, mPassword)
		for ioc in ioc_list:
			if not is_good_ip(ioc):
				print(ioc,' is not a valid IP address')
				exit(1)

		json_data={'ip_addresses':ioc_list,'expiry':quarantine_seconds}
		response = fgt.post('monitor', 'user', 'banned','add_users', parameters={'vdom': 'root'}, data=json_data)
		print("returned by FortiGate:\n%s" % response)
		fgt.logout()


def main():
	ip_list=[]
	super_ip=get_super_ip()
	print('Super: ',super_ip)
	group_id=pg_query(db_username,db_password,"select id from ph_group where display_name='CTIBLACKLIST'",super_ip)[0][0]
	if isinstance(group_id, int):
		bad_ips=pg_query(db_username,db_password,"select low_ip from ph_malware_ip where group_id='"+str(group_id)+"' LIMIT " + MAX_IP_COUNT,super_ip)
		for ip in bad_ips:
			ip_list.append(ip[0])

		run_fg_remediation(mIncidentXML, mAccessIp, mPort, mUser, mPassword, ip_list, QUARANTINE_SECONDS)


if __name__ == "__main__":
	main()
