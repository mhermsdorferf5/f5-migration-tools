#!/bin/env python3

################################################################################
### avi2bigip.py
#
# Description:
# Creates BIG-IP config from Avi configuration
# 
# Example Usage:
# python3 aviConfigExplorer.py --avi-json <avi-config.json>
#
# Requirements:
#     python3 with requests & json libs.
#
# Generated Configuration Requires: BIG-IP LTM version 17.1 or later.
#
# Author: Mark Hermsdorfer <m.hermsdorfer@f5.com>
# Version: 1.0
# Version History:
# v1.0: Initial Version.
#
# (c) Copyright 2024-2025 F5 Networks, Inc.
#
# This software is confidential and may contain trade secrets that are the
# property of F5 Networks, Inc. No part of the software may be disclosed
# to other parties without the express written consent of F5 Networks, Inc.
# It is against the law to copy the software. No part of the software may
# be reproduced, transmitted, or distributed in any form or by any means,
# electronic or mechanical, including photocopying, recording, or information
# storage and retrieval systems, for any purpose without the express written
# permission of F5 Networks, Inc. Our services are only available for legal
# users of the program, for instance in the event that we extend our services
# by offering the updating of files via the Internet.
#
# DISCLAIMER:
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL F5
# NETWORKS OR ANY CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION), HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# IMPORTANT NOTE: Any use of this software implies acceptance of the terms as
# detailed above. If you do not agree to the terms as detailed above DO NOT
# USE THE SOFTWARE!
#
################################################################################


import sys
import os
import json
import copy
from types import SimpleNamespace
import f5_objects
from urllib.parse import urlparse, parse_qs
import re
import argparse
import logging
import traceback
import ipaddress


def loadJsonFile(filename) -> SimpleNamespace:
    file = open(filename, "r")
    jsonObj = json.loads(file.read(), object_hook=lambda d: SimpleNamespace(**d))
    file.close()
    return jsonObj

def printJson(obj):
    print(json.dumps(obj, indent=4, default=lambda o: o.__dict__, sort_keys=True))

def getRefName(url):
    ref_querystring = parse_qs(urlparse(url).query)
    name =  ref_querystring["name"][0]
    #name = name.replace(" ", "_")
    #name = name.replace("%20", "_")
    name = name.replace("*", "%2A")
    return name
def getRefTenant(url):
    ref_querystring = parse_qs(urlparse(url).query)
    name =  ref_querystring["tenant"][0]
    #name = name.replace(" ", "_")
    #name = name.replace("%20", "_")
    #name = name.replace("%2A", "wildcard")
    name = name.replace("*", "%2A")
    return name
def getRefCloud(url):
    ref_querystring = parse_qs(urlparse(url).query)
    name =  ref_querystring["cloud"][0]
    #name = name.replace(" ", "_")
    #name = name.replace("%20", "_")
    #name = name.replace("%2A", "wildcard")
    name = name.replace("*", "%2A")
    return name
def getRefType(url):
    name = urlparse(url).path
    name = name.replace("/api/", "")
    name = name.replace("/", "")
    return name

def getObjByRef(ref):
    objName = f5_objects.f5_sanitize(getRefName(ref))
    try:
        objTenant = f5_objects.f5_sanitize(getRefTenant(ref))
    except:
        objTenant = ""
    objType = getRefType(ref)
    
    match objType:
        case "cloud":
            testList = avi_config.Cloud
        case "vrfcontext":
            testList = avi_config.VrfContext
        case "httppolicyset":
            testList = avi_config.HTTPPolicySet
        case "analyticsprofile":
            testList = avi_config.AnalyticsProfile
        case "pool":
            testList = avi_config.Pool
        case "poolgroup":
            testList = avi_config.PoolGroup
        case "vsvip":
            testList = avi_config.VsVip
        case "virtualservice":
            testList = avi_config.VirtualService
        case "sslprofile":
            testList = avi_config.SSLProfile
        case "sslkeyandcertificate":
            testList = avi_config.SSLKeyAndCertificate
        case "networkprofile":
            testList = avi_config.NetworkProfile
        case "applicationpersistenceprofile":
            testList = avi_config.ApplicationPersistenceProfile
        case "applicationprofile":
            testList = avi_config.ApplicationProfile
        case "healthmonitor":
            testList = avi_config.HealthMonitor
        case "stringgroup":
            testList = avi_config.StringGroup
        case "ipaddrgroup":
            testList = avi_config.IpAddrGroup
        case "dnsprofile":
            testList = avi_config.DNSProfile
        case "httppolicy":
            testList = avi_config.HTTPPolicy
        case "httppolicyset":
            testList = avi_config.HTTPPolicySet
        case "networksecuritypolicy":
            testList = avi_config.NetworkSecurityPolicy
        case "tenant":
            testList = avi_config.Tenant
        case _:
            print("getObjByRef: Don't know how to handle object type: " + objType)
            raise Exception("getObjByRef: Don't know how to handle object type: " + objType)
            
    for testObj in testList:
        if hasattr(testObj, 'tenant_ref'):
            if f5_objects.f5_sanitize(testObj.name) == objName \
            and f5_objects.f5_sanitize(getRefName(testObj.tenant_ref)) == objTenant:
                return testObj
        else:
            if f5_objects.f5_sanitize(testObj.name) == objName:
                return testObj


def process_virtual(virtual):
    
    tenantName =  f5_objects.f5_sanitize(getRefName(virtual.tenant_ref))
    # List of F5 virtuals, this allows us to handle splitting
    virtuals = []

    sniParent = False
    sniChild = False

    match virtual.type:
        case "VS_TYPE_NORMAL":
            sniParent = False
            sniChild = False
        case "VS_TYPE_VH_PARENT":
            # If we have a parent vip, go find all the children vips and put them into a list.
            sniParent = True
            sniChild = False
        case "VS_TYPE_VH_CHILD":
            sniParent = False
            sniChild = True
        case _:
            sniParent = False
            sniChild = False
            print("Virtual: " + virtual.name + " Don't know how to handle type: " + virtual.type )
            raise Exception("Virtual: " + virtual.name + " Don't know how to handle type: " + virtual.type )

    print(f"\n### Virtual {virtual.name} ###")
    printJson(virtual)
    if hasattr(virtual, 'vsvip_ref'):
        print(f"\n### VsVIP {getRefName(virtual.vsvip_ref)} ###")
        printJson(getObjByRef(virtual.vsvip_ref))
    print(f"\n### VRF {getRefName(virtual.vrf_context_ref)} ###")
    printJson(getObjByRef(virtual.vrf_context_ref))
    print(f"\n### Network Profile {getRefName(virtual.network_profile_ref)} ###")
    printJson(getObjByRef(virtual.network_profile_ref))
    
    if hasattr(virtual, 'pool_ref'):
        print(f"\n### Pool {getRefName(virtual.pool_ref)} ###")
        pool = getObjByRef(virtual.pool_ref)
        printJson(pool)
        
        if hasattr(pool, 'health_monitor_refs'):
            for monitor in pool.health_monitor_refs:
                print(f"\n### Health Monitor {getRefName(monitor)} ###")
                printJson(getObjByRef(monitor))
        if hasattr(pool, 'application_persistence_profile_ref'):
            print(f"\n### Persistence Profile {getRefName(pool.application_persistence_profile_ref)} ###")
            printJson(getObjByRef(pool.application_persistence_profile_ref))
        if hasattr(pool, 'ssl_profile_ref'):
            print(f"\n### Pool SSL Profile {getRefName(pool.ssl_profile_ref)} ###")
            printJson(getObjByRef(pool.ssl_profile_ref))
        
    if hasattr(virtual, 'pool_group_ref'):
        print(f"\n### Pool Group {getRefName(virtual.pool_group_ref)} ###")
        poolGroup = getObjByRef(virtual.pool_group_ref)
        printJson(poolGroup)
        for subPoolIndex, subPool in enumerate(poolGroup.members):
            print(f"\n### Pool {getRefName(subPool.pool_ref)} ###")
            pool = getObjByRef(subPool.pool_ref)
            printJson(pool)
            if hasattr(pool, 'health_monitor_refs'):
                for monitor in pool.health_monitor_refs:
                    print(f"\n### Health Monitor {getRefName(monitor)} ###")
                    printJson(getObjByRef(monitor))
            if hasattr(pool, 'application_persistence_profile_ref'):
                print(f"\n### Persistence Profile {getRefName(pool.application_persistence_profile_ref)} ###")
                printJson(getObjByRef(pool.application_persistence_profile_ref))
            if hasattr(pool, 'ssl_profile_ref'):
                print(f"\n### Pool SSL Profile {getRefName(pool.ssl_profile_ref)} ###")
                printJson(getObjByRef(pool.ssl_profile_ref))
            
    
    if hasattr(virtual, 'application_profile_ref'):
        print(f"\n### Application Profile {getRefName(virtual.application_profile_ref)} ###")
        printJson(getObjByRef(virtual.application_profile_ref))
    
    if hasattr(virtual, 'network_security_policy_ref'):
        print(f"\n### Network Security Policy {getRefName(virtual.network_security_policy_ref)} ###")
        printJson(getObjByRef(virtual.network_security_policy_ref))
        
    if hasattr(virtual, 'http_policies'):
        for httpPolicy in virtual.http_policies:
            print(f"\n### HTTP Policy {getRefName(httpPolicy.http_policy_set_ref)} ###")
            printJson(printJson(getObjByRef(httpPolicy.http_policy_set_ref)))
        
    if hasattr(virtual, 'ssl_profile_ref') and not sniParent:
        print(f"\n### SSL Profile {getRefName(virtual.ssl_profile_ref)} ###")
        printJson(getObjByRef(virtual.ssl_profile_ref))
        print(f"\n### SSL Cert & Key {getRefName(virtual.ssl_key_and_certificate_refs[0])} ###")
        printJson(getObjByRef(virtual.ssl_key_and_certificate_refs[0]))
   
    # Now Handle SNI Parent Virtual and all children virtuals, SSL Profiles, and Content Switching
    if sniParent and not sniChild:
        childrenVirtuals = []
        if hasattr(virtual.extension, 'vh_child_vs_uuid'):
            childrenUUIDs = virtual.extension.vh_child_vs_uuid
            for testVirtual in avi_config.VirtualService:
                if testVirtual.uuid in childrenUUIDs:
                    childrenVirtuals.append(testVirtual)
        if len(childrenVirtuals) > 0 :
            for childVirtual in childrenVirtuals:
                print(f"\n### Child Virtual Server {childVirtual.name} ###")
                printJson(childVirtual)

    return 0


def main() -> int:

    global avi_config
    try:
        avi_config = loadJsonFile(args.aviJsonFile)
    except Exception as e:
        print("ERROR: problem loading Avi JSON Configuration. " + str(e))
        return 1

    if args.aviObjRef != "all":
        printJson(getObjByRef(args.aviObjRef))
        return 0

    for virtual in avi_config.VirtualService:
        tenantName =  f5_objects.f5_sanitize(getRefName(virtual.tenant_ref))
        if tenantName == "admin":
            tenantName = "Common"
        cloudName = getRefName(virtual.cloud_ref)
        if cloudName != args.aviCloud:
            continue
        if args.aviTenant != "all" and tenantName != args.aviTenant:
            continue
        if args.aviVirtual != "all" and virtual.name not in args.aviVirtual:
            continue
        process_virtual(virtual)
    
    #print("Avi Tenants:")
    #pprintpp.pprint(avi_tenants)


    return 0



# Main
if __name__ == '__main__':
    # ArgeParse stuff:
    parser = argparse.ArgumentParser(description="Explore Avi JSON Configuration")
    parser.add_argument("aviJsonFile", action="store", help="Avi JSON Configuration File")
    parser.add_argument("-c", "--avi-cloud", action="store", dest="aviCloud", default="VM-Default-Cloud", help="Avi Cloud to explore, by default it explores only the VM-Default-Cloud")
    parser.add_argument("-t", "--avi-tenant", action="store", dest="aviTenant", default="all", help="Avi Tenant to explore, by default it explores all tenants")
    parser.add_argument("-v", "--avi-virtuals", action="store", dest="aviVirtual", default="all", help="List of Avi Virtual Service to explore, by default it explores all Virtual Services")
    parser.add_argument("-o", "--avi-objectRef", action="store", dest="aviObjRef", default="all", help="List of Avi Objects to explore, by default it explores all.")
    global args
    args = parser.parse_args()

    # Call main function: 
    sys.exit(main())  