#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests

class Target:

    def __init__(self, mdomain):
        self.mdomain = mdomain
        self.ip_domain = str()
        self.subdomains = dict()
        self.mcms = str()
    def getDomain(self): return self.mdomain
    def setSubdomain(self, msubdomain, subdomain_ip): self.subdomains[msubdomain] = subdomain_ip
    def getSubdomains(self): return self.subdomains
#def makeShodan(mdomain, ip_domain):
#    try:
#        
#    except:
def reverseDns(cTarget):
    try:
        mrequest = requests.get(url = "https://api.hackertarget.com/reversedns/?q="+cTarget.getDomain())
    except requests.exceptions.ConnectTimeout: pass
    if mrequest.status_code == 200:
        for mrevesed in mrequest.text.split('\n'):
            #cTarget.setSubdomain(mrevesed.split[' '][1], mrevesed.split[' '][0])
            print mrevesed.split[' ']#, mrevesed.split[' '][0]
    else:
        print "Check you'r connection"
#def makeNmap():
#def getSubdomains():
#def getCms():
#def enumUsers():
def main():
    cTarget = Target("poste.dz")
    print cTarget.getDomain()
    reverseDns(cTarget)
if __name__ == '__main__':
    main()
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
