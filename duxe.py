#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
from tabulate import tabulate
import re
import socket, socks
import shodan
import argparse
import requests
import sys, os
import logging
import datetime

"""
author: hihebark
. . . . . . . . . . 
 . . . . /\____. . .
. ./) . /  `'"'`> . 
 . ||. (   º  º |. .
. _\\ ./`    ˣ  ) . 
 | . \/_ _ __ "|___ 
.| | || | |\ \// ._|
 |___/\___|/\_\\___/
Information gathering
or Recon Tool
"""

GREEN = '\033[92m'
BLUE = '\033[94m'
RED = '\033[91m'
END = '\033[0m'
SHODAN_API_KEY = "-- YOUR API KEY --"
BUILTWITH = "-- YOUR API KEY --"
HUNTER_API = "-- YOUR API KEY --"
VIRUSTOTAL_API = "-- YOUR API KEY --"
VERSION = "duxe 0.0.2"
BANNER = """. . . . . . . . . . 
 . . . . /\____. . .
. ./) . /  `'"'`> . 
 . ||. (   .  . |. .
. _\\\ ./`    x  ) . 
 | . \/_ _ __¨„|___ 
.| | || | |\ \// ._|
 |___/\___|/\_\\\___/v0.0.2
"""
def redText(text): return RED + text + END
def greenText(text): return GREEN + text + END
def blueText(text): return BLUE + text + END
def warningText(text): return "[%s] %s"%(redText('!'), text)
logging.addLevelName( logging.WARNING, "\033[92m[!]\033[0m")
logging.addLevelName( logging.ERROR, "\033[91m[E]\033[0m")
logging.addLevelName( logging.INFO, "\033[94m[*]\033[0m")
logging.addLevelName( logging.CRITICAL, "\033[91m[?]\033[0m")
logging.addLevelName( logging.DEBUG, "")
logger = logging.getLogger('Duxe')
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_format = logging.Formatter('%(levelname)s %(message)s')
console_handler.setFormatter(console_format)
logger.addHandler(console_handler)
def init_logging(logtofile, log_file_name):
    if logtofile:
        file_handler = logging.FileHandler("logs/"+log_file_name+".log")
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter('%(asctime)s - %(message)s')
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)

def is_valid_url(m_url):
    return True if m_url.startswith('http://') or m_url.startswith('https://') else False

def make_valid_url(m_url):
    return 'http://'+m_url+'/'

def get_list_ip(m_port = dict()):
    m_path_duxe = os.path.dirname(__file__)
    m_libs_port_list = 'libs/port_list.txt' if m_path_duxe == "" else '/libs/port_list.txt'
    with open('%s%s'%(m_path_duxe, m_libs_port_list), 'r') as m_port_list:
        for line in m_port_list:
            m_port[line.rstrip('\n').split(' ')[0]] = line.rstrip('\n').split(' ')[1]
    return m_port

def get_base_url(m_url):
    if m_url.startswith('http://') or m_url.startswith('https://'):
        m_url = m_url.split('http://')[1] if m_url.startswith('http://') else m_url.split('https://')[1]
    if m_url.endswith('/'):
        m_url = m_url.split('/')[0]
    return m_url
def make_request(m_url):
    if not is_valid_url(m_url):m_url = make_valid_url(m_url)
    try:
        return requests.get(url=m_url, timeout=(3,7))
    except :
        #logger.critical("Requests: time out")
        return None

def get_ip_from_url(m_url):
    try:
        return socket.gethostbyname(m_url)
    except:
        return False

def make_nmap_test(m_ip):
    return requests.get(url="http://api.hackertarget.com/nmap/?q="+m_ip).text

def get_list_cms(m_cms = dict()):
    m_path_duxe = os.path.dirname(__file__)
    m_libs_cms_list = '/libs/cms_list.txt'
    with open('%s%s'%(m_path_duxe, m_libs_cms_list), 'r') as m_cms_list:
        for line in m_cms_list:
            m_cms[line.rstrip('\n')] = 0
    return m_cms

def get_information(m_url, m_nmap):
    m_url_ip = get_ip_from_url(m_url)
    if m_url_ip == False:
        print warningText("Didn't retrieve IP of the Host. Try again.")
    else:
        logger.info(" Host: %s\t\tIP: %s"%(m_url, m_url_ip))
        #print " Host: %s\t\tIP: %s"%(redText(m_url), redText(m_url_ip))
        try:
            m_shodan = shodan.Shodan(SHODAN_API_KEY)
            m_info_shodan = m_shodan.host(m_url_ip)
            logger.info(" Organization: %s\tOS: %s"%(m_info_shodan.get('org', 'None'), m_info_shodan.get('os', 'None')))
            logger.info(" Vulnerability: %s"%str(''.join(m_info_shodan.get('vulns', 'None'))))
            logger.info(" Number of open port: %s"%str(len(m_info_shodan.get('ports', '0'))))
            #print m_info_shodan
            for m_data in m_info_shodan.get('data'):
                name_port = get_list_ip()[str(m_data['port'])] if str(m_data['port']) in get_list_ip() else ""
                logger.debug("%s\t%s\t%s"%(m_data['port'], m_data['transport'], name_port))
            if m_nmap:
                logger.info("Making Nmap test:")
                logger.info(make_nmap_test(m_url_ip))
        except shodan.APIError, e:
            logger.error(" Error Shodan: %s"%e)
            if not m_nmap and raw_input("[?]Do you want to make nmap test y/n: ") == 'y':
                logger.info("Nmap test:\n%s"%make_nmap_test(m_url_ip))

def get_subdomains(m_url):
    m_url = get_base_url(m_url)
    m_subdomain_list = []
    logger.info("Searching for sub-domains of %s:"%m_url)
    m_request_tc = requests.get("http://www.threatcrowd.org/searchApi/v2/domain/report/", {"domain":m_url})
    json_response = m_request_tc.json()
    if json_response['response_code'] == '1':
        for m_subdomains in json_response['subdomains']:
            if m_subdomains not in m_subdomain_list:
                m_subdomain_list.insert(0, m_subdomains)
    m_request_ht = requests.get("http://api.hackertarget.com/hostsearch/?q="+m_url)
    if m_request_ht.status_code == 200:
        if not len(m_request_ht.text)==0:
            for m_subdomains in m_request_ht.text.split('\n'):
                if m_subdomains.split(',')[0] not in m_subdomain_list:
                    m_subdomain_list.insert(0, m_subdomains.split(',')[0])
    mparams = {'domain': m_url, 'apikey': VIRUSTOTAL_API}
    m_request_vt = requests.get(url='https://www.virustotal.com/vtapi/v2/domain/report', params = mparams)
    json_response_vt = m_request_vt.json()
    if m_request_vt.status_code == 200 and json_response_vt['response_code'] == 1:
        for msubdomain in json_response_vt['detected_urls']:
            if msubdomain['url'] not in m_subdomain_list:
                m_subdomain_list.insert(0, msubdomain['url'])
    #test if ther'is only one subdomain print to brut
    logger.info("Found {}".format(len(m_subdomain_list)))
    for m_subdomains in m_subdomain_list:
        if not m_subdomains == "":
            #m_status_code = make_request(m_subdomains).status_code if make_request(m_subdomains) else "500"
            m_status_code = greenText(u"✔") if make_request(m_subdomains) else redText(u"✘")
            logger.debug(u" {0} - {1}".format(m_subdomains, m_status_code))

def what_cms_is_using(m_url):
    if make_request(m_url) is not None:
        m_soupe = BeautifulSoup(make_request(m_url).text, 'html5lib')
        if m_soupe.find(attrs={'name':'generator'}):
            logger.info("I'am using: %s"%m_soupe.find(attrs={'name':'generator'}).get("content"))
            if re.search('wordpress', m_soupe.find(attrs={'name':'generator'}).get("content"),re.I):
                version = re.split(' ', m_soupe.find(attrs={'name':'generator'}).get("content"))[1]
                json_response = make_request("https://wpvulndb.com/api/v2/wordpresses/"+version.replace('.', "")).json()
                if len(json_response[version]['vulnerabilities']) is not 0:
                    for m_vuln in json_response[version]['vulnerabilities']:
                        #url_vuln = [' '.join(v) for v in m_vuln[u'references']]
                        print "id: %s - title: %s\n\treferences: %s"%(m_vuln['id'], m_vuln['title'], m_vuln[u'references'][u'url'])
                else:
                    logger.info("No vulnerabilitie found on this version")
    else:
        #intersting stuff here > https://wpvulndb.com/api | here to > https://hunter.io/api/docs#domain-search
        #error here to fix
        m_cms = get_list_cms()
        m_builtwith = requests.get(url = "https://api.builtwith.com/free1/api.json?KEY="+BUILTWITH+"&LOOKUP="+m_url)
        json_response = m_builtwith.json()
        #TODO hold error of unknown domain
        for m_group_name in json_response['groups']:
            for m_categories in m_group_name['categories']:
                for m in m_cms:
                    if re.search(re.escape(m.lower()), m_categories['name'].lower()):
                        m_cms[m] += 1
        #end Builtwith
        use_cms = "I'am using: None" if max(m_cms.values()) == 0 or None else "I'am using: %s"%max(m_cms, key=m_cms.get)
        logger.info(use_cms)

def get_personnel_info(m_url, m_table = []):
    m_request = make_request("https://api.hunter.io/v2/domain-search?domain="+m_url+"&api_key="+HUNTER_API)
    json_response = m_request.json()
    if json_response['meta']['results'] != 0:
        #print "Result: %s"%json_response['meta']['results']
        header = ['Nbr','Name', 'E-mail', 'Type', 'Position']
        for m_data in json_response['data']['emails']:
            m_name = "%s %s"%(m_data[u'last_name'], m_data[u'first_name'])
            m_table.insert(len(m_table), (len(m_table)+1,m_name, m_data[u'value'] , m_data['type'], m_data[u'position']))
        m_make_table = tabulate(m_table, headers=header, tablefmt="fancy_grid")
        logger.info("Personnel information \n%s"%m_make_table)
    else:
        logger.critical("Nothing to enumerate on this domain")

def main():
    parser = argparse.ArgumentParser(description="Duxe - Information gathering tool.")
    parser.add_argument("-host", help="The target to test exemple: 'exemple.com'")
    parser.add_argument("-nmap", help="Make a Nmap test", action="store_true")
    parser.add_argument("-log", help="Log the output to a file", action="store_true")
    parser.add_argument("-tor", help="Use tor to make the request", action="store_true")
    parser.add_argument("-e-user", help="Enumerating the users on the web site show if find 10 results", action="store_true")
    parser.add_argument("-version", help="Print version and exit", action="store_true")
    args = parser.parse_args()
    if args.version:
        print redText(VERSION)
        exit(1)
    m_host = args.host if args.host is not None else exit(1)
    m_nmap = True if args.nmap else False
    m_log_to_file = True if args.log else False
    if args.tor:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', 9050)
        socket.socket = socks.socksocket
    if not re.match(r'[0-9]+(?:\.[0-9]+){3}', m_host):
        m_date = datetime.datetime.today()
        init_logging(m_log_to_file, m_date.strftime("%Y-%M-%d-%H:%M:%S")+"-"+m_host)
        if m_log_to_file: logger.info("log file on /logs/%s.log"%(str(m_date.strftime("%Y-%M-%d-%H:%M:%S"))+"-"+m_host))
        get_information(m_host, m_nmap)
        get_subdomains(m_host)
        what_cms_is_using(m_host)
        if args.e_user:get_personnel_info(m_host)
        #to add this > https://crt.sh/

if __name__ == "__main__":
    try:
        print redText(BANNER)
        main()
    except KeyboardInterrupt:
        logger.critical("\n Exiting ...\n")
        exit(1)
