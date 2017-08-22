#!/usr/bin/env python
# -*- coding: utf-8 -*-

from requests import get, Session
from bs4 import BeautifulSoup
from re import search, escape, match
import socket, socks
import shodan
import argparse

"""
author: hihebark
. . . . . . . . . . 
 . . . . /\____. . .
. ./) . /  `'"'`> . 
 . ||. (   º  º |. .
. _\\ ./`    ˣ  ) . 
 | . \/_ _ __ "|___ 
.| | || | |\ \// ._|
 |___/\___|/\_\\___/v-0.0.1
. . .Information gathering.
"""

GREEN = '\033[92m'
BLUE = '\033[94m'
RED = '\033[91m'
END = '\033[0m'
SHODAN_API_KEY = "vbdpLUW9aUxJGw05kAkLTfti5wsQgz7s"
BUILTWITH = "e1cedafd-9a08-40ed-84d8-20537051d108"
VERSION = "duxe 0.0.1"
BANNER = """. . . . . . . . . . 
 . . . . /\____. . .
. ./) . /  `'"'`> . 
 . ||. (   .  . |. .
. _\\\ ./`    ×  ) . 
 | . \/_ _ __¨ |___ 
.| | || | |\ \// ._|
 |___/\___|/\_\\\___/v0.0.1
"""
def redText(text): return RED + text + END
def greenText(text): return GREEN + text + END
def blueText(text): return BLUE + text + END
def warningText(text): return "[%s] %s"%(redText('!'), text)

def is_valid_url(m_url):
    return True if m_url.startswith('http://') or m_url.startswith('https://') else False

def make_valid_url(m_url):
    return 'http://'+m_url+'/'

def get_base_url(m_url):
    if m_url.startswith('http://') or m_url.startswith('https://'):
        m_url = m_url.split('http://')[1] if m_url.startswith('http://') else m_url.split('https://')[1]
    if m_url.endswith('/'):
        m_url = m_url.split('/')[0]
    return m_url
def make_request(m_url):
    if not is_valid_url(m_url):m_url = make_valid_url(m_url)
    return get(url=m_url)

def get_ip_from_url(m_url):
    try:
        return socket.gethostbyname(m_url)
    except:
        return False

def make_nmap_test(m_ip):
    return make_request("http://api.hackertarget.com/nmap/?q="+m_ip).text

def get_list_cms(m_cms = dict()):
    with open('libs/cms_list.txt') as m_cms_list:
        for line in m_cms_list:
            m_cms[line.rstrip('\n')] = 0
    return m_cms

def get_information(m_url, m_nmap, m_robot):
    m_url_ip = get_ip_from_url(m_url)
    if m_url_ip == False:
        print warningText("didn't retrieve IP of the Host. Try again.")
    else:
        print " Host: %s\t\tIP: %s"%(redText(m_url), redText(m_url_ip))
        try:
            m_shodan = shodan.Shodan(SHODAN_API_KEY)
            m_info_shodan = m_shodan.host(m_url_ip)
            print " Organization: %s\tOS: %s"%(redText(str(m_info_shodan.get('org', 'n/a'))), redText(str(m_info_shodan.get('os', 'n/a'))))
            print " Vunrability: %s"%redText(''.join(m_info_shodan[u'vulns']))
            print " Number of open port: %s"%redText(str(len(m_info_shodan.get('ports', 'n/a'))))
            for m_data in m_info_shodan['data']:
                print "%s : %s"%(m_data['port'], m_data['data'])
            if m_nmap:
                print "Making Nmap test:"
                print make_nmap_test(m_url_ip)
        except shodan.APIError, e:
            print " error: %s"%redText(str(e))
            if not m_nmap and raw_input("[?]Do you want to make nmap test y/n: ") == 'y':
                print make_nmap_test(m_url_ip)

def get_subdomains(m_url):
    m_url = get_base_url(m_url)
    m_subdomain_list = []
    m_request_tc = get("http://www.threatcrowd.org/searchApi/v2/domain/report/", {"domain":m_url})
    json_response = m_request_tc.json()
    if json_response['response_code'] == '1':
        for m_subdomains in json_response['subdomains']:
            if m_subdomains not in m_subdomain_list:
                m_subdomain_list.insert(0, m_subdomains)
    m_request_ht = get("http://api.hackertarget.com/hostsearch/?q="+m_url)
    if not len(m_request_ht.text)==0:
        for m_subdomains in m_request_ht.text.split('\n'):
            if m_subdomains.split(',')[0] not in m_subdomain_list:
                m_subdomain_list.insert(0, m_subdomains.split(',')[0])
    for m_subdomains in m_subdomain_list:
        if not m_subdomains == "":
            print " %s \t\t- %s"%(redText(m_subdomains), make_request(m_subdomains).status_code)

def what_cms_is_using(m_url):
    m_soupe = BeautifulSoup(make_request(m_url).text, 'html5lib')
    if m_soupe.find(attrs={'name':'generator'}):
        print "I'am using: %s"%m_soupe.find(attrs={'name':'generator'}).get("content")
    else:
        m_cms = get_list_cms()
        m_builtwith = make_request("https://api.builtwith.com/free1/api.json?KEY="+BUILTWITH+"&LOOKUP="+m_url).json()
        for m_group_name in m_builtwith['groups']:
            for m_categories in m_group_name['categories']:
                for m in m_cms:
                    if search(escape(m.lower()), m_categories['name'].lower()):
                        m_cms[m] += 1
        #end Builtwith
        print "I'am using: None" if max(m_cms.values())== 0 else "I'am using: %s"%max(m_cms, key=m_cms.get)

def main():
    parser = argparse.ArgumentParser(description="Duxe - Information gathering tool.")
    parser.add_argument("-host", help="The target to test exemple: 'exemple.com'")
    parser.add_argument("-nmap", help="Make a Nmap test", action="store_true")
    parser.add_argument("-robot", help="search for robot file", action="store_true")
    parser.add_argument("-log", help="Log the output to a file", action="store_true")
    parser.add_argument("-tor", help="Use tor to make the request", action="store_true")
    parser.add_argument("-version", help="Use tor to make the request", action="store_true")
    args = parser.parse_args()
    if args.version:
        print redText(VERSION)
        exit(1)
    m_host = args.host if args.host is not None else exit(1)
    m_nmap = True if args.nmap else False
    m_robot = True if args.robot else False
    if args.tor:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', 9050)
        socket.socket = socks.socksocket
    if not match(r'[0-9]+(?:\.[0-9]+){3}', m_host):
        get_information(m_host, m_nmap, m_robot)
        get_subdomains(m_host)
        what_cms_is_using(m_host)
if __name__ == "__main__":
    try:
        print redText(BANNER)
        main()
    except KeyboardInterrupt:
        print warningText("User want to leave! exiting ...")
        exit(1)
