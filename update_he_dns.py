#!/usr/bin/python
# update_he_dns.py
# Author: Colin Dearborn cdearborn@gmail.com
# Update DNS zones hosted by dns.he.net via their dynamic DNS API
# documented at https://dns.he.net/docs.html
# requests lib from http://docs.python-requests.org/en/master/
# debian/ubuntu install "sudo apt install python3-requests"

import logging
import subprocess
import re
import os
import sys
import ipaddress
import dns.resolver
import requests
import socket
import requests.packages.urllib3.util.connection as urllib3_cn


# get path of script for file opening.
path = os.path.dirname(os.path.realpath(sys.argv[0]))

log_path = path # set to /var/log or other directory if you don't want it in the same directory as the install.
# TODO set up logging into syslog.

# if file path includes "/dev/" then we're operating in dev mode.
# currently no different than "regular" mode.
dev = False
if re.search(r'dev', path):
  dev = True
#set log file
log_file = path + "/he_dyn_dns.log"
#set hosts configuration file
hosts_file = path + "/hosts.cfg"
#start logging to log_file, set logging to DEBUG if we're in the dev path, otherwise, set logging level to ERROR
logging.basicConfig(filename=log_file, encoding='utf-8', format='%(asctime)s %(message)s', level=logging.INFO)
if dev:
  logging.getLogger().setLevel(logging.DEBUG)
  logging.getLogger().addHandler(logging.StreamHandler())

logging.info('Starting DNS check')
logging.debug('Debug mode enabled')
# update HE DNS.
# get current system IP from 'http//checkip.dns.he.net'
## configure host,key,IP
# get host,key,mode from hosts_file
# get current host:ip from DNS
# check if both system IP and host IP match
# if not, update HE DNS with system IP.

# Function: get_ip_address(ipv)
# get active IPv4 or IPv6 address from http//checkip.dns.he.net
# Requires ipv = IPv4 or IPv6
# Returns IPv4 or IPv6 address, or False if no address found.
def get_ip_address(ipv):
  # my re references fail unless I import it again?
  import re
  logging.debug('Retreiving current active global IPv4 address from checkip.dns.he.net')
  url = 'https://checkip.dns.he.net/'
  if ipv == 'IPv4':
    #If ipv6 is available on the system, we'll need to disable it, do the call, then re-enable it.
    logging.debug('Forcing IPv4 via urllib3')
    # have to assume IPv6 = False, because there is no urllib3_cn.HAS_IPV4
    got_v6=False
    if urllib3_cn.HAS_IPV6:
      # ensure we reset urllib3_cn.HAS_IPV6 after we're done running our IPv4 check, if IPv6 is available.
      got_v6 = True
      # force IPv4 connections via urllib3
      urllib3_cn.HAS_IPV6 = False
  elif ipv == 'IPv6':
    if not urllib3_cn.HAS_IPV6:
      logging.info('System does not have a valid IPv6 address')
      return(False)
  try:
    r = requests.get(url)
  except ConnectionError as ce:
    logging.error('Failed connecting to %s over %s, Connection Error is:\n%s', url, ipv, ce)
    if ipv == 'IPv4' and got_v6:
      # force IPv4 connections via urllib3
      urllib3_cn.HAS_IPV6 = True
    return(False)
#  except RequestException as re:
#    logging.error('Failed connecting to %s over %s, Request Exception is:\n%s', url, ipv, re)
#    if ipv == 'IPv4' and got_v6:
#      # force IPv4 connections via urllib3
#      urllib3_cn.HAS_IPV6 = True
#    return(False)
  except:
    logging.error('Failed connecting to %s over %s, Unknown Exception occured\n%s', url, ipv, sys.exc_info()[0])
    if ipv == 'IPv4' and got_v6:
      # force IPv4 connections via urllib3
      urllib3_cn.HAS_IPV6 = True
    return(False)
  else:
    out = r.text
    logging.debug('checkip.dns.he.net output:\n%s', out)
    # if the output includes "Your IP address is :" then we were successful and can grab the address
    # TODO: need a bit more logic here, one more if statement to verify that r.text had something?
    if out:
      matchObj = re.search( 'Your IP address is : (.*)</body', out)
      ip_out = matchObj.group(1)
      logging.debug('%s check succeeded, %s address is %s',ipv, ipv, ip_out)
      # verify ip is actually an ip addresses, or blank
      try:
        ip = ipaddress.ip_address(ip_out)
      except ValueError:
        logging.error('system detected %s address is invalid: %s', ipv, ip_out)
        if dev:
          # since we are checking to see if we're in dev/debug mode before running "ip a" we might as well put all debug logging under here too.
          logging.debug('full output of webpage:\n%s', out)
          logging.debug('full output of ip a:')
          ipaout = subprocess.run(['ip', 'a'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
          logging.debug(ipaout.stdout.decode('utf-8'))
        if ipv == 'IPv4' and got_v6:
          # force IPv4 connections via urllib3
          urllib3_cn.HAS_IPV6 = True
        return(False)
      else:
        if ipv == 'IPv4' and got_v6:
          # force IPv4 connections via urllib3
          urllib3_cn.HAS_IPV6 = True
        return(ip_out)
    else:
      if ipv == 'IPv4' and got_v6:
        # force IPv4 connections via urllib3
        urllib3_cn.HAS_IPV6 = True
        return(False)

def update_ip(payload, ipv):
  try:
    ip_update_request = requests.get('https://dyn.dns.he.net/nic/update', params=payload)
  except RequestsException as e:
    logging.error('Updating % address for host %s failed with error %s', ipv, hostname[1], e)
  else:
    matchObj = re.search('(nochg|good|badauth|abuse)', ip_update_request.text)
    if matchObj:
      if matchObj.group(1) == "nochg" or matchObj.group(1)== "good":
        logging.info('%s update was successful, output message was %s',ipv, matchObj.group(1))
      elif matchObj.group(1) == "badauth":
        #using elif here, in case we enoounter other messages later.
        logging.error('Host password was incorrect for %s host %s, bad authorization message received from dyn.dns.he.net', ipv, hostname[1])
      elif matchObj.group(1) == "abuse":
        logging.error('Abuse messagesf for % host %s from dyn.dns.he.net! SLOW DOWN!', ipv, hostname[1])
        logging.error('Exiting to protect future updates!')
        sys.exit(2)
      else:
        logging.error('%s update for host %s returned unknown message!', ipv, hostname[1])
        logging.debug('Full output of %s update reply for host %s:\n%s', ipv, hostname[1], ip_update_request.text)

# get_dns_ip
# requires hostname, ipv
#   hostname = fqdn of host
#   ipv = IPv4|IPv6
# returns:
#   IPv4 or IPv6 address on a successful lookup
#   False on a failed lookup
def get_dns_ip(hostname, ipv):
  if ipv == "IPv6":
    record = "AAAA"
  elif ipv == "IPv4":
    record = "A"
  else:
    logging.error('Unknown IP version specified: %s.')
    return(False)
  logging.debug('Lookup current %s DNS for %s', record, hostname)
  try:
    answers = dns.resolver.resolve(hostname, record)
  except Exception as e:
    logging.error('Error with resolving %s address for host %s, ErrorMessage: %s', ipv, hostname, e)
    # sys.exit(1)
    return(False)
  else:
    # dyn.dns.he.net can't deal with multiple addresses for a single host
    if(len(answers)==1):
      #get addresses out of ipv6answers
      for val in answers:
        #print ('AAAA Record :', val.to_text())
        dnsip = val.to_text()
        logging.debug('%s address for host %s retrieved from DNS is %s', ipv, hostname, dnsip)
        return(dnsip)
    else:
      # too many records returned
      logging.error('Multiple IPv6 addresses found for host %s, update cannot happen', hostname[1])
      return(False)


ipv4 = get_ip_address('IPv4')
logging.debug('IPv4 = %s', ipv4)
ipv6 = get_ip_address('IPv6')
logging.debug('IPv6 = %s', ipv6)

logging.info('Opening config file %s', log_file)
with open(hosts_file) as f:
  for line in f:
    if not (re.search(r'^#', line)):
      host,key,mode = line.split(",")
      # mode = [ipv4|ipv6|dual]
      mode = mode.rstrip('\n')
      hostname = host.split("=")
      logging.debug('hostname = %s', hostname[1])
      logging.debug('mode = %s', mode)
      # modes can be ipv4, ipv6 or dual (well, anything other than ipv4 or ipv6 will equate to dual)
      # if the mode is ipv6, then it's not ipv4, and we'll only do ipv6 things
      # else, if the mode is ipv4, then it's not ipv6 and we'll only do ipv4 things
      # otherwise, if the mode is not ipv4 or ipv6, we'll do both.
      # TODO: make logic to change mode==dual to an array and step through array (length = 1 if IPv4 or IPv6, length = 2 if dual (one IPv4, one IPv6)
      mode_array=[]
      if mode == "dual":
        mode_array=["IPv6", "IPv4"]
      elif mode == "ipv6":
        mode_array=["IPv6"]
      elif mode == "ipv4":
        mode_array=["IPv4"]
      else:
        logging.error("Unknown mode \"%s\" in configuration file for host %s, please check and configure correctly", mode, hostname[1])
        # no need to exit, we can go to the next line, and since mode_array = [], the for loop will be skipped. (maybe?)
      for ipv in mode_array:
        logging.info('Performing %s update for host %s', ipv, hostname[1])
        if ipv == "IPv6" or ipv == "IPv4":
          if ipv == "IPv6":
            ip = ipv6
            # first, check to see if IPv6 is available
            if not ipv6:
              if urllib3_cn.HAS_IPV6:
                logging.error('Unable to determine system IPv6 at this time')
                logging.error('Please verify system IPv6 configuration')
              else:
                logging.error('IPv6 appears to be unavailable on this system, exiting.')
                logging.error('Check your config and set mode for host %s to ipv4, or fix your IPv6 configuration', hostname[1])
                sys.exit(6)
          elif ipv == "IPv4":
            ip = ipv4
          # get IP for host from DNS
          dnsip = get_dns_ip(hostname[1], ipv)
          # if dnsip is different than ip, update IP address
          if((ip != dnsip and ip) or (dev == 1 and ip)):
            logging.info('Updating %s host %s to %s address %s', ipv, hostname[1], ipv, ip)
            # dyn.dns.he.net updates require hostname=host.name, password=key, myip=ip.address
            key_array = key.split("=")
            payload = {hostname[0] : hostname[1], key_array[0] : key_array[1], 'myip' : ip}
            update_ip(payload, ipv)
          elif ip:
            logging.info('No %s change detected for host %s', ipv, hostname[1])
#fin!
f.close



