#!/bin/env python3

################################################################################
### avi2bigip.py
#
# Description:
# Creates BIG-IP config from Avi configuration
# 
# Example Usage:
# python3 avi2bigip.py --avi-json <avi-config.json>
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


class avi_tenant:
    def __init__(self, name):
        self.name = f5_objects.f5_sanitize(name)
        self.description = "Avi Tenant"
        self.defaultRouteDomain = 0
        self.f5_pools = []
        self.f5_monitors = []
        self.f5_virtuals = []
        self.f5_apps = []
        self.f5_profiles = []
        self.f5_policies = []
    def __repr__(self):
        virtualString= "[ "
        for virtual in self.f5_virtuals:
            virtualString += f"\n\t\t{virtual}"
        virtualString += "]"
        poolString = "[ "
        for pool in self.f5_pools:
            poolString += f"\n\t\t{pool}"
        poolString += "]"
        return f"avi_tenant(name='{self.name}', defaultRouteDomain='{self.defaultRouteDomain}' description='{self.description}', \n\tf5_pools='{poolString}', \n\tf5_virtuals='{virtualString}')"


def usage ():
    print("Usage:")
    print("%s --avi-json <AviConfig.json> ")

def log_error(logmessage):
    logmessage = str("ERROR: " + logmessage)
    print(logmessage, file=sys.stderr)
    if args.logToFile:
        logging.error(logmessage)

def log_warning(logmessage):
    logmessage = str("WARNING: " + logmessage)
    print(logmessage, file=sys.stderr)
    if args.logToFile:
        logging.warning(logmessage)

def log_debug(logmessage):
    if args.debug:
        logmessage = str("DEBUG: " + logmessage)
        print(logmessage, file=sys.stderr)
        if args.logToFile:
            logging.debug(logmessage)

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
    objTenant = f5_objects.f5_sanitize(getRefTenant(ref))
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
            log_error("getObjByRef: Don't know how to handle object type: " + objType)
            raise Exception("getObjByRef: Don't know how to handle object type: " + objType)
            
    for testObj in testList:
        if f5_objects.f5_sanitize(testObj.name) == objName \
        and f5_objects.f5_sanitize(getRefName(testObj.tenant_ref)) == objTenant:
            return testObj

def generateCertKeyFile(name, obj, type):
    filename = f"{args.sslFileDir}{name}.{type}"
    try:
        f = open(filename , "w")
    except Exception as e:
        raise Exception("ERROR: problem opening file for writing. " + str(e))
    if type == "certificate":
        f.write(obj.certificate)
    if type == "key":
        f.write(obj.key)

def addObjToTenant(obj):
    objType = obj.__class__.__name__
    tenantNameForAdd = obj.partition
    log_debug(f"Attempting Adding Object: {obj.name} of type {objType} to tenant {tenantNameForAdd}")
    addedToTenant = 0
    for tenant in avi_tenants:
        tenantName = f5_objects.f5_sanitize(tenant.name)
        if tenantName == "admin":
            tenantName = "Common"
        if tenantName == tenantNameForAdd:
            match objType:
                case "pool":
                    addToList = tenant.f5_pools
                case "monitor":
                    addToList = tenant.f5_monitors
                case "virtual":
                    addToList = tenant.f5_virtuals
                case "ltmPolicy":
                    addToList = tenant.f5_policies
                case "iRule":
                    addToList = tenant.f5_rules
                case _:
                    log_error(f"Adding Object: {obj.name} not added to any tenant, no tenant found of type {objType} in tenant: {tenantNameForAdd}.")
            log_debug(f"Adding Object: FOUND TENANT {tenantName} for {obj.name} tenant contains {len(addToList)} .")
            for testObj in addToList:
                log_debug(f"Adding Object: {obj.name} testing against {objType} before adding to tenant {tenantName}.")
                if testObj.name == obj.name:
                    log_debug(f"Adding Object: {obj.name} of type {objType} already exists in tenant: {tenantName}'s.")
                    addedToTenant = 1
            if addedToTenant == 0:
                log_debug(f"Adding Object: {obj.name} appending to {objType} in tenant: {tenantName}.")
                addToList.append(obj)
                addedToTenant = 1
                break
    if addedToTenant == 0:
        log_error(f"Adding Object: {obj.name} not added to any tenant, no tenant found of type {str(addToList)} in tenant: {tenantName}.")
        return 0
    return 1

def createRedirectVirtual(f5_virtual, ip, rd):
    log_debug(f"Creating Redirect Virtual for {f5_virtual.name} to {ip}%{rd}")
    f5_redirect_virtual = copy.deepcopy(f5_virtual)
    f5_redirect_virtual.name = f5_redirect_virtual.name + "__redirect"
    f5_redirect_virtual.destination = f"{ip}%{rd}:80"
    f5_redirect_virtual.irules.append("/Common/_sys_https_redirect")
    f5_redirect_virtual.profilesAll.clear()
    f5_redirect_virtual.profilesClientSide.clear()
    f5_redirect_virtual.profilesServerSide.clear()
    f5_redirect_virtual.profilesAll.append(f"/Common/f5-tcp-progressive")
    f5_redirect_virtual.profilesAll.append(f"/Common/http")
    return f5_redirect_virtual

def createSNIRoutingLTMPolicy(name, partition, sniMapping):
    ltmPolicy = f5_objects.ltmPolicy(name)
    ltmPolicy.partition = partition
    ltmPolicy.controls = ['forwarding']
    ltmPolicy.requires = ['http', 'client-ssl']
    rules = dict()
    for i, (key, value) in enumerate(sniMapping.items()):
        ruleName = f"{key}_sni_rule"
        rules[ruleName] = f"""            conditions {{
                0 {{
                    ssl-extension
                    ssl-client-hello
                    server-name
                    values {{ {key} }}
                }}
            }}
            actions {{
                0 {{
                    forward
                    select
                    pool {value}
                }}
            }}
            ordinal {i}
"""
    ltmPolicy.rules = rules
    return ltmPolicy

def avi2bigip_http_profile(aviApplicationProfile):

    tenantName =  f5_objects.f5_sanitize(getRefName(aviApplicationProfile.tenant_ref))

    f5_profile = f5_objects.httpProfile(aviApplicationProfile.name) 
    f5_profile.partition = tenantName

    if hasattr(aviApplicationProfile, 'http_profile'):
        if aviApplicationProfile.http_profile.connection_multiplexing_enabled is False:
            f5_profile.oneconnectTransformations = "enabled"
        # Only set max header if it's above F5 Default of 64
        if aviApplicationProfile.http_profile.max_header_count > 64:
            f5_profile.maxHeaderCount = aviApplicationProfile.http_profile.max_header_count

        # Avi has a lot of XFF options we don't have... so we'll likely need LTM Policies or iRules to fully implement some of this.
        if aviApplicationProfile.http_profile.xff_enabled is True:
            f5_profile.insertXForwardedFor = "enabled"

        # Rewrite redirects from http to https:
        if aviApplicationProfile.http_profile.server_side_redirect_to_https is True:
            f5_profile.redirectRewrite = "all"

        #For all but "ADD_NEW_XFF_HEADER" we'll need LTM Policies or iRules to fully implement.
        match aviApplicationProfile.http_profile.xff_update:
            case "ADD_NEW_XFF_HEADER":
                f5_profile.insertXForwardedFor = "enabled"
            case "APPEND_TO_THE_XFF_HEADER":
                f5_profile.insertXForwardedFor = "enabled"
                log_warning("HTTP Profile: " + aviApplicationProfile.name + " Don't know how to handle xff_update = APPEND_TO_THE_XFF_HEADER.")
            case "REPLACE_XFF_HEADERS":
                f5_profile.insertXForwardedFor = "enabled"
                log_warning("HTTP Profile: " + aviApplicationProfile.name + " Don't know how to handle xff_update = REPLACE_XFF_HEADERS.")
        if aviApplicationProfile.http_profile.xff_alternate_name != "X-Forwarded-For":
            log_warning("HTTP Profile: " + aviApplicationProfile.name + " Don't know how to handle xff_alternative_name.")
        if aviApplicationProfile.http_profile.ssl_client_certificate_mode != "SSL_CLIENT_CERTIFICATE_NONE":
            log_warning("HTTP Profile: " + aviApplicationProfile.name + " Don't know how to handle Client Cert Auth.")

    if tenantName == "admin":
        f5_profile.partition = "Common"
    return f5_profile

def avi2bigip_cipherMapping(aviCipherString):
    f5Ciphers = []
    aviCipherList = aviCipherString.split(":")
    if len(aviCipherList) == 0:
        f5Ciphers.append("DEFAULT")
    for cipher in aviCipherList:
        replaced = 0
        for cipherMap in migration_config.cipherStringMapping:
            log_debug(f"Checking Cipher: {cipher.lower()} against {cipherMap.aviCipher.lower()}")
            if cipherMap.aviCipher.lower() == cipher.lower():
                log_debug(f"Replacing Cipher: {cipher.lower()} with {cipherMap.f5Cipher.lower()}")
                f5Ciphers.append(f"{cipherMap.f5Cipher.lower()}")
                replaced = 1
        if replaced == 0:
            log_debug(f"Appending Cipher: {cipher.lower()} to list.")
            f5Ciphers.append(f"{cipher.lower()}")
    return f5Ciphers
    

def avi2bigip_serverssl_profile(aviSSLProfile):

    tenantName =  f5_objects.f5_sanitize(getRefName(aviSSLProfile.tenant_ref))

    f5_profile = f5_objects.ServerSSLProfile(aviSSLProfile.name) 
    f5_profile.partition = tenantName

    # Sort out allowed TLS/SSL Versions... yes, this is ugly.
    tls1_0 = "disabled"
    tls1_1 = "disabled"
    tls1_2 = "disabled"
    tls1_3 = "disabled"
    ssl3   = "disabled"

    for version in aviSSLProfile.accepted_versions:
        if version.type == "SSL_VERSION_TLS1":
            tls1_0 = "enabled"
        if version.type == "SSL_VERSION_TLS1_1":
            tls1_1 = "enabled"
        if version.type == "SSL_VERSION_TLS1_2":
            tls1_2 = "enabled"
        if version.type == "SSL_VERSION_TLS1_3":
            tls1_3 = "enabled"
        if version.type == "SSL_VERSION_SSLV3":
            ssl3 = "enabled"
    ssl_options = [ "dont-insert-empty-fragments" ]
    if ssl3 == "disabled":
        ssl_options.append("no-sslv3")
    if tls1_0 == "disabled":
        ssl_options.append("no-tlsv1")
    if tls1_1 == "disabled":
        ssl_options.append("no-tlsv1_1")
    if tls1_2 == "disabled":    
        ssl_options.append("no-tlsv1_2")
    if tls1_3 == "disabled":
        ssl_options.append("no-tlsv1_3")

    try:
        f5_profile.ciphers = avi2bigip_cipherMapping(aviSSLProfile.accepted_ciphers)
    except Exception as e:
        log_error("avi2bigip_cipherMapping: " + aviSSLProfile.name + " not able to be converted cipher string " + str(e))
        
    if tenantName == "admin":
        f5_profile.partition = "Common"
    return f5_profile

def avi2bigip_clientssl_profile(aviSSLProfile, aviSSLKeyAndCertificate):

    tenantName =  f5_objects.f5_sanitize(getRefName(aviSSLProfile.tenant_ref))

    f5_profile = f5_objects.ClientSSLProfile(aviSSLKeyAndCertificate.name) 
    f5_profile.partition = tenantName

    # Sort out allowed TLS/SSL Versions... yes, this is ugly.
    tls1_0 = "disabled"
    tls1_1 = "disabled"
    tls1_2 = "disabled"
    tls1_3 = "disabled"
    ssl3   = "disabled"

    for version in aviSSLProfile.accepted_versions:
        if version.type == "SSL_VERSION_TLS1":
            tls1_0 = "enabled"
        if version.type == "SSL_VERSION_TLS1_1":
            tls1_1 = "enabled"
        if version.type == "SSL_VERSION_TLS1_2":
            tls1_2 = "enabled"
        if version.type == "SSL_VERSION_TLS1_3":
            tls1_3 = "enabled"
        if version.type == "SSL_VERSION_SSLV3":
            ssl3 = "enabled"
    ssl_options = [ "dont-insert-empty-fragments" ]
    if ssl3 == "disabled":
        ssl_options.append("no-sslv3")
    if tls1_0 == "disabled":
        ssl_options.append("no-tlsv1")
    if tls1_1 == "disabled":
        ssl_options.append("no-tlsv1_1")
    if tls1_2 == "disabled":    
        ssl_options.append("no-tlsv1_2")
    if tls1_3 == "disabled":
        ssl_options.append("no-tlsv1_3")

    try:
        f5_profile.ciphers = avi2bigip_cipherMapping(aviSSLProfile.accepted_ciphers)
    except Exception as e:
        log_error("avi2bigip_cipherMapping: " + aviSSLProfile.name + " not able to be converted cipher string " + str(e))

    cert = aviSSLKeyAndCertificate.certificate.certificate
    #log_debug(f"Cert: {cert}")
    key = aviSSLKeyAndCertificate.key
    #log_debug(f"Key: {key}")

    f5_profile.certFileName = f"{f5_profile.name}.crt"
    f5_profile.certFile = cert
    f5_profile.keyFileName = f"{f5_profile.name}.key"
    f5_profile.keyFile = key

    if hasattr(aviSSLKeyAndCertificate, 'ca_certs'):
        chain = ""
        for ca in aviSSLKeyAndCertificate.ca_certs:
            if not hasattr(ca, 'ca_ref'):
                log_warning("ClientSSL Profile: " + aviSSLProfile.name + " Don't know how to handle ca_certs without ca_ref.")
                continue
            caName = f5_objects.f5_sanitize(getRefName(ca.ca_ref))
            caTenant = f5_objects.f5_sanitize(getRefTenant(ca.ca_ref))
            for cert in avi_config.SSLKeyAndCertificate:
                certName = f5_objects.f5_sanitize(cert.name)
                certTenant = f5_objects.f5_sanitize(getRefName(cert.tenant_ref))
                #log_debug(f"TESTING {caName} == {certName} and certTenant {caTenant} == {certTenant}")
                if certName == caName and certTenant == caTenant:
                    chain = chain + "\n" + cert.certificate.certificate
        f5_profile.chainFileName = f"{f5_objects.f5_sanitize(aviSSLKeyAndCertificate.ca_certs[0].name)}.crt"
        f5_profile.chainFile = chain
        log_debug(f"ChainFileName: {f5_profile.chainFileName} Chain: {f5_profile.chainFile}") 

    if tenantName == "admin":
        f5_profile.partition = "Common"
    return f5_profile

def avi2bigip_network_profile(aviNetworkProfile):
    tenantName =  f5_objects.f5_sanitize(getRefName(aviNetworkProfile.tenant_ref))
    snat = "enabled"
    match aviNetworkProfile.profile.type:
        case "PROTOCOL_TYPE_UDP_FAST_PATH":
            timeout = int(aviNetworkProfile.profile.udp_fast_path_profile.session_idle_timeout)
            if aviNetworkProfile.profile.udp_fast_path_profile.per_pkt_loadbalance:
                type = "udp"
            else:
                type = "fastl4"
            if aviNetworkProfile.profile.udp_fast_path_profile.snat == False:
                snat = "disabled"
        case "PROTOCOL_TYPE_TCP_FAST_PATH":
            type = "fastl4"
            timeout = int(aviNetworkProfile.profile.tcp_fast_path_profile.session_idle_timeout)
        case "PROTOCOL_TYPE_TCP_PROXY":
            type = "tcp"
            timeout = int(aviNetworkProfile.profile.tcp_proxy_profile.idle_connection_timeout)
        case "PROTOCOL_TYPE_UDP_PROXY":
            type = "udp"
            timeout = int(aviNetworkProfile.profile.udp_proxy_profile.idle_connection_timeout)
        case "PROTOCOL_TYPE_SCTP_PROXY":
            type = "sctp"
            timeout = int(aviNetworkProfile.profile.sctp_proxy_profile.idle_timeout)
        case _:
            log_warning("Network Profile: " + aviNetworkProfile.name + " Don't know how to handle type: " + aviNetworkProfile.profile.type)

    f5_profile = f5_objects.networkProfile(aviNetworkProfile.name, type) 
    f5_profile.timeout = timeout
    f5_profile.partition = tenantName
    if aviNetworkProfile.profile.type == "PROTOCOL_TYPE_UDP_FAST_PATH" and type == "fastl4":
        f5_profile.datagramLoadBalancing = "enabled"
        # snat's don't exist in F5 profiles.... but oneoff handling.
        if snat == "disabled":
            f5_profile.snat = "disabled"
    if tenantName == "admin":
        f5_profile.partition = "Common"
    return f5_profile


def avi2bigip_monitor(monitor):
    tenantName =  f5_objects.f5_sanitize(getRefName(monitor.tenant_ref))

    match monitor.type:
        case "HEALTH_MONITOR_HTTP":
            type = "http"
        case "HEALTH_MONITOR_HTTPS":
            type = "https"
        case "HEALTH_MONITOR_TCP":
            type = "tcp"
        case "HEALTH_MONITOR_UDP":
            type = "udp"
        case "HEALTH_MONITOR_DNS":
            type = "dns"
        case "HEALTH_MONITOR_PING":
            type = "gateway_icmp"
        case "HEALTH_MONITOR_EXTERNAL":
            log_error("Monitor: " + monitor.name + " Don't know how to handle monitor: " + monitor.type)
            type = "tcp"
        case _:
            log_error("Monitor: " + monitor.name + " Don't know how to handle monitor: " + monitor.type)
            raise Exception("Monitor: " + monitor.name + " Don't know how to handle monitor: " + monitor.type)

    f5_monitor = f5_objects.monitor(monitor.name, type)
    if monitor.type == "HEALTH_MONITOR_EXTERNAL":
        f5_monitor.name = f"{monitor.name}_FIXME_EXTERNAL_MONITOR_NOT_CONVERTED"

    if type == "dns":
        f5_monitor.qname = monitor.dns_monitor.query_name
        if monitor.dns_monitor.record_type == "DNS_RECORD_A":
            f5_monitor.qtype = "a"
        else:  
            f5_monitor.qtype = "aaaa"

    if tenantName != "admin":
        f5_monitor.partition = tenantName

    if hasattr(monitor, 'send_interval') and monitor.send_interval > 5:
        f5_monitor.interval = monitor.send_interval
        f5_monitor.timeout = monitor.send_interval * 3

    if hasattr(monitor, 'monitor_port'):
        f5_monitor.destination = "*:" + str(monitor.monitor_port)

    if hasattr(monitor, 'http_monitor'):
        monitor_attrs = monitor.http_monitor
    if hasattr(monitor, 'https_monitor'):
        monitor_attrs = monitor.https_monitor
    if 'monitor_attrs' in locals():
        # Send strings can be all over the place... so let's try to clean them up.
        send_str, num_subs = re.subn( "\\r\\n", r"\\r\\n", monitor_attrs.http_request.strip())
        if num_subs == 0:
            send_str, num_subs = re.subn( "\\n", r"\\r\\n", monitor_attrs.http_request.strip())
        if not send_str.endswith("\\r\\n"):
            send_str = send_str + "\\r\\n\\r\\n"
        recv_code = ""
        for code in monitor_attrs.http_response_code:
            if code == "HTTP_1XX":
                recv_code += "1"
            if code == "HTTP_2XX":
                recv_code += "2"
            if code == "HTTP_3XX":
                recv_code += "3"
            if code == "HTTP_4XX":
                recv_code += "4"
            if code == "HTTP_5XX":
                recv_code += "5"
            if code == "HTTP_ANY":
                recv_code = "0-9"
        recv_str = "HTTP/1.[01] [" + recv_code + "][0-9][0-9] .*"
        if hasattr(monitor_attrs,'http_response'):
            recv_str += monitor_attrs.http_response.strip()
        f5_monitor.send = send_str
        f5_monitor.recv = recv_str 
        del monitor_attrs, send_str, type, recv_code, recv_str, num_subs
    return f5_monitor

def avi2bigip_poolGroup(poolGroup):
    poolGroupName = f"{f5_objects.f5_sanitize(poolGroup.name)}_poolGroup"
    poolGroupTenantName =  f5_objects.f5_sanitize(getRefName(poolGroup.tenant_ref))

    f5_members = []
    vrfName = ""
    serverSideSSLProfileRef = ""
    serviceDownAction = ""
    monitorList = ""
    for subPoolIndex, subPool in enumerate(poolGroup.members):
        if hasattr(subPool, 'priority_label'): 
            priority = subPool.priority_label
        else:
            priority = 0
        subPoolName =  getRefName(subPool.pool_ref)
        subPoolTenant =  f5_objects.f5_sanitize(getRefTenant(subPool.pool_ref))
        for pool in avi_config.Pool:
            poolName =  f5_objects.f5_sanitize(pool.name)
            tenantName =  f5_objects.f5_sanitize(getRefName(pool.tenant_ref))
            routeDomainID = 0
            
            if subPoolName == poolName and subPoolTenant == tenantName:
                if hasattr(pool, 'use_service_port'): 
                    if pool.use_service_port:
                        log_warning("Pool: " + pool.name + " Don't know how to handle use_service_port: True")
                if hasattr(pool, 'ssl_key_and_certificate_ref'): 
                    log_error("Pool: " + pool.name + "Don't know how to handle ssl_key_and_certificate_ref for mTLS on server-side")
                if hasattr(pool, 'fail_action'): 
                    match pool.fail_action.type:
                        case "FAIL_ACTION_CLOSE_CONN":
                            serviceDownAction = "reset"
                        case _:
                            log_warning("Pool: " + pool.name + " Don't know how to handle fail_action: " + pool.fail_action.type)
                
                if hasattr(pool, 'health_monitor_refs'): 
                    for monitor_ref in pool.health_monitor_refs:
                        subPoolMonitorList = ""
                        try:
                            f5_monitor = avi2bigip_monitor(getObjByRef(monitor_ref))
                        except Exception as e:
                            log_error("Monitor: " + monitor_ref + " not able to be converted to bigip object " + str(e))
                            continue
                        addObjToTenant(f5_monitor)
                        monitorName = f"/{f5_monitor.partition}/{f5_monitor.name}"
                        if subPoolMonitorList == "":
                            subPoolMonitorList = monitorName
                        else:
                            if monitorName not in subPoolMonitorList:
                                subPoolMonitorList = f"{subPoolMonitorList} and {monitorName}"
                        if subPoolIndex == 0:
                            monitorList = subPoolMonitorList
                        else:
                            if monitorName not in monitorList:
                                log_error(f"Error Creating Pool Group: {poolGroupName}: subPool: {pool.name} contains different monitors than previous subPool")
                    
                if hasattr(pool, 'ssl_profile_ref'): 
                    if serverSideSSLProfileRef == "":
                        serverSideSSLProfileRef = pool.ssl_profile_ref
                        log_debug(f"Pool Group: {poolGroupName} Found SSL Profile: {serverSideSSLProfileRef} inside {pool.name}.")
                    elif serverSideSSLProfileRef != pool.ssl_profile_ref:
                        log_warning(f"Pool Group: {poolGroupName} Don't know how to handle multiple SSL Profiles in Pool Group, using: {serverSideSSLProfileRef} Found: {pool.ssl_profile_ref} inside {pool.name}.")
                        
                vrfName    =  getRefName(pool.vrf_ref)
                for vrf in migration_config.routeDomainMapping:
                    if vrfName == vrf.vrfName:
                        routeDomainID = vrf.rdID
                if hasattr(pool, 'servers'): 
                    for member in pool.servers:
                        if member.resolve_server_by_dns == True:
                            member.ip.addr = member.hostname
                        if hasattr(member, 'port'):
                            f5_member = f5_objects.pool_member(member.ip.addr, member.port)
                            f5_member.routeDomain = routeDomainID
                            f5_member.partition = tenantName
                        else:
                            f5_member = f5_objects.pool_member(member.ip.addr, pool.default_server_port)
                            f5_member.routeDomain = routeDomainID
                            f5_member.partition = tenantName
                        if member.ratio != 1:
                            f5_member.ratio = member.ratio
                        if member.enabled != "true":
                            f5_member.enabled = "no"
                        member.priority = priority
                        f5_members.append(f5_member)

    if tenantName == "admin":
        tenantName = "Common"

    f5_pool = f5_objects.pool(poolGroupName, f5_members )
    f5_pool.partition = poolGroupTenantName
    f5_pool.routeDomain = vrfName
    f5_pool.minActiveMembers = poolGroup.min_servers
    f5_pool.monitors = monitorList
    
    return f5_pool, serverSideSSLProfileRef


def avi2bigip_pool(pool):
    tenantName =  f5_objects.f5_sanitize(getRefName(pool.tenant_ref))
    vrfName    =  getRefName(pool.vrf_ref)
    routeDomainID = 0
    for vrf in migration_config.routeDomainMapping:
        if vrfName == vrf.vrfName:
            routeDomainID = vrf.rdID
    cloudName = getRefName(pool.cloud_ref)
    if pool.pool_type != "POOL_TYPE_GENERIC_APP":
        log_error("Pool: " + pool.name + " Don't know how to handle pool_type: " + pool.pool_type )
    if pool.append_port != "NEVER":
        log_warning("Pool: " + pool.name + " Don't know how to handle append_port: " + pool.append_port)

    f5_members = []
    if hasattr(pool, 'servers'): 
        for member in pool.servers:
            if member.resolve_server_by_dns == True:
                member.ip.addr = member.hostname
            if hasattr(member, 'port'): 
                f5_member = f5_objects.pool_member(member.ip.addr, member.port)
                f5_member.routeDomain = routeDomainID
                f5_member.partition = tenantName
            else:
                f5_member = f5_objects.pool_member(member.ip.addr, pool.default_server_port)
                f5_member.routeDomain = routeDomainID
                f5_member.partition = tenantName
            if member.ratio != 1:
                f5_member.ratio = member.ratio
            if member.enabled != "true":
                f5_member.enabled = "no"
            f5_members.append(f5_member)

    f5_pool = f5_objects.pool(pool.name, f5_members )
    f5_pool.routeDomain = vrfName

    if pool.enabled is False:
        f5_pool.enabled = False
    
    if hasattr(pool, 'use_service_port'): 
        if pool.use_service_port:
            log_warning("Pool: " + pool.name + " Don't know how to handle use_service_port: True")
    if hasattr(pool, 'ssl_key_and_certificate_ref'): 
        log_error("Pool: " + pool.name + "Don't know how to handle ssl_key_and_certificate_ref for mTLS on server-side")
    if hasattr(pool, 'fail_action'): 
        match pool.fail_action.type:
            case "FAIL_ACTION_CLOSE_CONN":
                f5_pool.serviceDownAction = "reset"
            case _:
                log_warning("Pool: " + pool.name + " Don't know how to handle fail_action: " + pool.fail_action.type)
    
    if hasattr(pool, 'health_monitor_refs'): 
        for index, monitor_ref in enumerate(pool.health_monitor_refs):
            try:
                f5_monitor = avi2bigip_monitor(getObjByRef(monitor_ref))
            except Exception as e:
                log_error("Monitor: " + monitor_ref + " not able to be converted to bigip object " + str(e))
                continue
            addObjToTenant(f5_monitor)
            if index == 0:
                f5_pool.monitors = f"/{f5_monitor.partition}/{f5_monitor.name}"
            else:
                f5_pool.monitors = f5_pool.monitors + " and " + f"/{f5_monitor.partition}/{f5_monitor.name}"

    match pool.lb_algorithm:
        case "LB_ALGORITHM_ROUND_ROBIN":
            f5_pool.loadBalancingMode = "round-robin"
        case "LB_ALGORITHM_LEAST_CONNECTIONS":
            f5_pool.loadBalancingMode = "least-connections-member"
        case "LB_ALGORITHM_FASTEST_RESPONSE":
            f5_pool.loadBalancingMode = "fastest-app-response"
        case "LB_ALGORITHM_LEAST_LOAD":
            f5_pool.loadBalancingMode = "fastest-app-response"
        case "LB_ALGORITHM_CONSISTENT_HASH":
            log_warning("Pool: " + pool.name + " Don't know how to handle lb_algorithm: " + pool.lb_algorithm)
        case "LB_ALGORITHM_CORE_AFFINITY":
            log_warning("Pool: " + pool.name + " Don't know how to handle lb_algorithm: " + pool.lb_algorithm)
        case _:
            log_warning("Pool: " + pool.name + " Don't know how to handle lb_algorithm: " + pool.lb_algorithm)
    
    if tenantName != "admin":
        f5_pool.partition = tenantName

    return f5_pool

def avi2bigip_virtual(virtual):

    tenantName =  f5_objects.f5_sanitize(getRefName(virtual.tenant_ref))
    # List of F5 virtuals, this allows us to handle splitting
    virtuals = []
    profiles = []
    policies = []
    rules = []

    redirectVipFound = 0
    sniParent = False
    sniChild = False


    match virtual.type:
        case "VS_TYPE_NORMAL":
            sniParent = False
        case "VS_TYPE_VH_PARENT":
            # If we have a parent vip, go find all the children vips and put them into a list.
            sniParent = True
            parentUUID = virtual.uuid
            childrenUUIDs = virtual.extension.vh_child_vs_uuid
            childrenVirtuals = []
            for testVirtual in avi_config.VirtualService:
                if testVirtual.uuid in childrenUUIDs:
                    childrenVirtuals.append(testVirtual)
        case "VS_TYPE_VH_CHILD":
            sniChild = True
        case _:
            log_error("Virtual: " + virtual.name + " Don't know how to handle type: " + virtual.type )
            raise Exception("Virtual: " + virtual.name + " Don't know how to handle type: " + virtual.type )


    destPortList = []
    destIpList = []
    if not hasattr(virtual, 'services') and not sniChild:
        #log_warning("Virtual: " + virtual.name + " Don't know how to handle no services on VirtualService object." )
        raise Exception("Virtual: " + virtual.name + " Don't know how to handle no services on VirtualService object." )
    if hasattr(virtual, 'services'):
        if virtual.services[0].port != virtual.services[0].port_range_end:
            log_error("Virtual: " + virtual.name + " Don't know how to handle port range." )
        if virtual.services[0].enable_http2 == "true":
            log_warning("Virtual: " + virtual.name + " Don't know how to handle http/2." )
        if virtual.services[0].is_active_ftp_data_port == "true":
            log_warning("Virtual: " + virtual.name + " Don't know how to handle is_active_ftp_data_port." )
        if virtual.services[0].horizon_internal_ports == "true":
            log_warning("Virtual: " + virtual.name + " Don't know how to handle horizon_internal_ports." )
        if virtual.use_bridge_ip_as_vip == "true":
            log_warning("Virtual: " + virtual.name + " Don't know how to handle use_bridge_ip_as_vip." )
        if virtual.use_vip_as_snat == "true":
            log_warning("Virtual: " + virtual.name + " Don't know how to handle use_vip_as_snat." )
    
        for service in virtual.services:
            destPortList.append(service.port)
    
        vsVip = getObjByRef(virtual.vsvip_ref)
        vrfName =  getRefName(vsVip.vrf_context_ref)
        for vip in vsVip.vip:
            ip = vip.ip_address.addr
            mask = vip.prefix_length 
            routeDomainID = 0
            if mask != 32:
                log_warning(f"VsVip: {virtual.vsvip_ref} Don't know how to handle VIP with non /32 bit mask." )
            for vrf in migration_config.routeDomainMapping:
                if vrfName == vrf.vrfName:
                    routeDomainID = vrf.rdID
            # if RD is zero let it pickup default route domain from the partition.
            if routeDomainID == 0:
                destIpList.append(f"{ip}")
            else:
                destIpList.append(f"{ip}%{routeDomainID}")
            
        # Temp Destination, will get modified if needed for multiple ip & port handling:
        destination = f"{destIpList[0]}:{str(destPortList[0])}"
    if sniChild:
        destination = f"255.255.255.255%0:123"
        destIpList.append("255.255.255.255%0")
        destPortList.append(123)
        vrfName = 0


    # Use this to handle ServerSSL Config, based on Avi Pool
    serverSideSSLProfileRef = ""
    # Figure out pool:
    default_pool = "none"
    if hasattr(virtual, 'pool_ref'):
        pool = getObjByRef(virtual.pool_ref)
        if hasattr(pool, 'ssl_profile_ref'):
            serverSideSSLProfileRef = pool.ssl_profile_ref
        try:
            f5_pool = avi2bigip_pool(getObjByRef(virtual.pool_ref))
        except Exception as e:
            if args.debug:
                log_error("Pool: " + virtual.pool_ref + " not able to be converted to bigip object " + str(e) + " full stack: " + str(traceback.format_exc()))
            else:
                log_error("Pool: " + virtual.pool_ref + " not able to be converted to bigip object " + str(e))
        addObjToTenant(f5_pool)
        # Add Pool to Virtual Config:
        default_pool =  f"/{f5_pool.partition}/{f5_pool.name}"
        
    if hasattr(virtual, 'pool_group_ref'):
        try:
            f5_pool, serverSideSSLProfileRef = avi2bigip_poolGroup(getObjByRef(virtual.pool_group_ref))
        except Exception as e:
            if args.debug:
                log_error("Pool: " + virtual.pool_group_ref + " not able to be converted to bigip object " + str(e) + " full stack: " + str(traceback.format_exc()))
            else:
                log_error("Pool: " + virtual.pool_group_ref + " not able to be converted to bigip object " + str(e))
        addObjToTenant(f5_pool)
        # Add Pool to Virtual Config:
        default_pool =  f"/{f5_pool.partition}/{f5_pool.name}"

    f5_virtual = f5_objects.virtual(virtual.name, destination, default_pool)
    f5_virtual.routeDomain = vrfName
    if tenantName != "admin":
        f5_virtual.partition = tenantName

    # Network Profile first...
    try:
        f5_network_profile = avi2bigip_network_profile(getObjByRef(virtual.network_profile_ref))
    except Exception as e:
        log_error("Network Profile: " + virtual.network_profile_ref + " not able to be converted to bigip object " + str(e))
    
    profiles.append(f5_network_profile)
    f5_virtual.profilesAll.append(f"/{f5_network_profile.partition}/{f5_network_profile.name}")

    # Now Application Profile, if it has one.
    createRedirectVips = False
    if hasattr(virtual, 'application_profile_ref'):
        try:
            aviApplicationProfile = getObjByRef(virtual.application_profile_ref)
        except Exception as e:
            log_error("ApplicationProfile : " + virtual.application_profile_ref + " not found " + str(e))
        match aviApplicationProfile.type:
            case "APPLICATION_PROFILE_TYPE_HTTP":
                try:
                    http_profile = avi2bigip_http_profile(aviApplicationProfile)
                except Exception as e:
                    if args.debug:
                        log_error("Application Profile: " + aviApplicationProfile.name + " not able to be converted to bigip object " + str(e) + " full stack: " + str(traceback.format_exc()))
                    else:
                        log_error("Application Profile: " + aviApplicationProfile.name + " not able to be converted to bigip object " + str(e))

                if hasattr(aviApplicationProfile, 'http_profile.compression_profile'):
                    if aviApplicationProfile.http_profile.compression_profile.compression is True:
                        log_warning("Application Profile: " + aviApplicationProfile.name + " Don't know how to handle compression." )

                if aviApplicationProfile.http_profile.http_to_https is True:
                    log_debug("Application Profile: " + aviApplicationProfile.name + " Redirecting HTTP to HTTPS.")
                    createRedirectVips = True
    
                if aviApplicationProfile.http_profile.use_true_client_ip is True:
                    f5_virtual.snat = False
                    f5_virtual.snat_type = "none"
                else:
                    f5_virtual.snat = True
                    f5_virtual.snat_type = "automap"
                
                profiles.append(http_profile)
                f5_virtual.profilesAll.append(f"/{http_profile.partition}/{http_profile.name}")
            case "APPLICATION_PROFILE_TYPE_L4":
                if aviApplicationProfile.preserve_client_ip is True:
                    f5_virtual.snat = False
                    f5_virtual.snat_type = "none"
                else:
                    f5_virtual.snat = True
                    f5_virtual.snat_type = "automap"
            case "APPLICATION_PROFILE_TYPE_SSL":
                if aviApplicationProfile.preserve_client_ip is True:
                    f5_virtual.snat = False
                    f5_virtual.snat_type = "none"
                else:
                    f5_virtual.snat = True
                    f5_virtual.snat_type = "automap"
            case _:
                log_warning("Application Profile: " + aviApplicationProfile.name + " Don't know how to handle type: " + aviApplicationProfile.type)
    
    if hasattr(virtual, 'http_policies'):
        foundPolicyRules = 0
        for httpPolicy in virtual.http_policies:
            try:
                httpPolicy = getObjByRef(httpPolicy.http_policy_set_ref)
            except Exception as e:
                if args.debug:
                    log_error("HTTP Policy: Can't find policy: " + httpPolicy.http_policy_set_ref + str(e) + " full stack: " + str(traceback.format_exc()))
                else:
                    log_error("HTTP Policy: Can't find policy: " + httpPolicy.http_policy_set_ref + str(e))
            if hasattr(httpPolicy, 'http_request_policy'):
                for rule in httpPolicy.http_request_policy.rules:
                    foundPolicyRules += 1
                    log_debug(f"Virtual: {virtual.name} has httpPolicySet with http_request_policy rule: {rule}" )
            if hasattr(httpPolicy, 'http_response_policy'):
                for rule in httpPolicy.http_response_policy.rules:
                    foundPolicyRules += 1
                    log_debug(f"Virtual: {virtual.name} has httpPolicySet with http_request_policy rule: {rule}" )
        if foundPolicyRules == 0:
            log_debug("Virtual: " + virtual.name + " has http_policies but policy has no rules, ignoring." )
        else:
            log_error("Virtual: " + virtual.name + " Don't know how to handle http_policies with http policy rules on VirtualService object." )
    

    # Now Client SSL Profile, if it has one.
    if hasattr(virtual, 'ssl_profile_ref') and not sniParent:
        if len(virtual.ssl_key_and_certificate_refs) > 1:
            log_warning("Virtual: " + virtual.name + " Don't know how to handle multiple ssl_key_and_certificate_refs." )
        try:
            f5_clientssl_profile = avi2bigip_clientssl_profile(getObjByRef(virtual.ssl_profile_ref), getObjByRef(virtual.ssl_key_and_certificate_refs[0]))
        except Exception as e:
            if args.debug:
                log_error("ERROR: clientssl profile: " + virtual.ssl_profile_ref + " " + virtual.ssl_key_and_certificate_refs[0] + " not able to be converted to bigip object " + str(e) + " full stack: " + str(traceback.format_exc()))
            else:
                log_error("ERROR: clientssl profile: " + virtual.ssl_profile_ref + " " + virtual.ssl_key_and_certificate_refs[0] + " not able to be converted to bigip object " + str(e))
        
        f5_virtual.profilesClientSide.append(f"/{f5_clientssl_profile.partition}/{f5_clientssl_profile.name}")
        profiles.append(f5_clientssl_profile)

    # Now ServerSSL Profile, if it has one.
    if serverSideSSLProfileRef != "":
        log_debug(f"Virtual: {virtual.name} has serverSideSSLProfileRef: {serverSideSSLProfileRef}")
        try:
            f5_serverssl_profile = avi2bigip_serverssl_profile(getObjByRef(serverSideSSLProfileRef))
        except Exception as e:
            if args.debug:
                log_error("ERROR: serverssl profile: " + serverSideSSLProfileRef + " not able to be converted to bigip object " + str(e) + " full stack: " + str(traceback.format_exc()))
            else:
                log_error("ERROR: serverssl profile: " + serverSideSSLProfileRef + " not able to be converted to bigip object " + str(e))
        
        f5_virtual.profilesServerSide.append(f"/{f5_serverssl_profile.partition}/{f5_serverssl_profile.name}")
        profiles.append(f5_serverssl_profile)
    
    # Now Handle SNI Parent Virtual and all children virtuals, SSL Profiles, and Content Switching
    if sniParent:
        log_debug(f"Virtual: {virtual.name} is a SNI Parent Virtual, building Child SSL profiles and content switching.")
        try:
            f5_clientssl_parent_profile = avi2bigip_clientssl_profile(getObjByRef(virtual.ssl_profile_ref), getObjByRef(virtual.ssl_key_and_certificate_refs[0]))
        except Exception as e:
            if args.debug:
                log_error("ERROR: clientssl profile: " + virtual.ssl_profile_ref + " " + virtual.ssl_key_and_certificate_refs[0] + " not able to be converted to bigip object " + str(e) + " full stack: " + str(traceback.format_exc()))
            else:
                log_error("ERROR: clientssl profile: " + virtual.ssl_profile_ref + " " + virtual.ssl_key_and_certificate_refs[0] + " not able to be converted to bigip object " + str(e))
        # Do not append the parent profile to the Virtual Server, as it's just a parent for the child profiles, but do append it to the profiles list.
        parentClientSSLProfileName = f"/{f5_clientssl_parent_profile.partition}/{f5_clientssl_parent_profile.name}"
        profiles.append(f5_clientssl_parent_profile)
        defaultClientSSLProfile = f5_objects.ClientSSLProfile( f"{virtual.name}_sni_default_clientssl" )
        defaultClientSSLProfile.parent = parentClientSSLProfileName
        defaultClientSSLProfile.partition = f5_clientssl_parent_profile.partition
        # empty out ciphers, and options, these get picked up from the parent profile.
        defaultClientSSLProfile.options = []
        defaultClientSSLProfile.ciphers = []
        defaultClientSSLProfile.sniDefault = True
        profiles.append(defaultClientSSLProfile)
        f5_virtual.profilesClientSide.append(f"/{defaultClientSSLProfile.partition}/{defaultClientSSLProfile.name}")
        # Now we need to create a default SNI ClientSSL profiel that does get appended to the Virtual.
        sniPoolMap = { }
        for childVirtual in childrenVirtuals:
            try:
                f5_clientssl_child_profile = avi2bigip_clientssl_profile(getObjByRef(childVirtual.ssl_profile_ref), getObjByRef(childVirtual.ssl_key_and_certificate_refs[0]))
            except Exception as e:
                if args.debug:
                    log_error("ERROR: clientssl profile: " + childVirtual.ssl_profile_ref + " " + childVirtual.ssl_key_and_certificate_refs[0] + " not able to be converted to bigip object " + str(e) + " full stack: " + str(traceback.format_exc()))
                else:
                    log_error("ERROR: clientssl profile: " + childVirtual.ssl_profile_ref + " " + childVirtual.ssl_key_and_certificate_refs[0] + " not able to be converted to bigip object " + str(e))
            f5_clientssl_child_profile.parent = parentClientSSLProfileName
            f5_clientssl_child_profile.partition = f5_clientssl_parent_profile.partition
            f5_clientssl_child_profile.sniDefault = False
            f5_clientssl_child_profile.sniRequired = True
            profiles.append(f5_clientssl_child_profile)
            if f"/{f5_clientssl_child_profile.partition}/{f5_clientssl_child_profile.name}" not in f5_virtual.profilesClientSide:
                f5_virtual.profilesClientSide.append(f"/{f5_clientssl_child_profile.partition}/{f5_clientssl_child_profile.name}")
                
            try:
                f5_child_virtuals, f5_child_profiles = avi2bigip_virtual(childVirtual)
            except TypeError as e:
                log_warning("virtual: subvirtual" + virtual.name + " not able to be converted to bigip object " + str(e) + " full stack: " + str(traceback.format_exc()))
                continue
            
            if len(f5_child_virtuals) == 0:
                log_error(f"virtual: subvirtual {childVirtual.name} returned no virtuals, don't know how to handle this.")
            if len(f5_child_virtuals) > 1:
                log_warning(f"virtual: subvirtual {childVirtual.name} returned {len(f5_child_virtuals)} virtuals, don't know how to handle this.")
           
            # First we need to add this and any other virtual host domains to a SNI Mapping of hostname => pool_ref
            for hostname in childVirtual.vh_domain_name:
                sniPoolMap[hostname] = f5_child_virtuals[0].default_pool
                # Add to our VIP handled counter:
                global f5VipCount
                f5VipCount += 1

            
        # Create LTM Policy to reference Pools in Pool List... plus make sure those pools get added to the config
        ltmPolicyName = f"{f5_virtual.name}__ltm_policy"
        ltmPolicy = createSNIRoutingLTMPolicy(ltmPolicyName, f5_virtual.partition, sniPoolMap)
        addObjToTenant(ltmPolicy)

    # If we have multiple destinations and/or multiple ports, copy our vip to multiple virtuals one per destination port combo.
    for ip in destIpList:
        rd = ip.split("%")[1]
        ip = ip.split("%")[0]
        for port in destPortList:
            if len(destPortList) > 1 and len(destIpList) > 1:
                newDestVirtual = copy.deepcopy(f5_virtual)
                log_debug(f"VsVip: {virtual.vsvip_ref} MULTIPLE DESTINATIONS MULTIPLE PORTS building VIP for: {ip}:{port}" )
                newDestVirtual.name = f"{f5_virtual.name}__{ip}:{port}"
                newDestVirtual.destination = f"{ip}%{rd}:{port}"
                virtuals.append(newDestVirtual)
            elif len(destPortList) == 1 and len(destIpList) > 1:
                newDestVirtual = copy.deepcopy(f5_virtual)
                log_debug(f"VsVip: {virtual.vsvip_ref} MULTIPLE DESTINATIONS SINGLE PORT building VIP for: {ip}:{port}" )
                newDestVirtual.name = f"{f5_virtual.name}__{ip}"
                newDestVirtual.destination = f"{ip}%{rd}:{port}"
                virtuals.append(newDestVirtual)
            elif len(destPortList) > 1 and len(destIpList) == 1:
                newDestVirtual = copy.deepcopy(f5_virtual)
                log_debug(f"VsVip: {virtual.vsvip_ref} SINGLE DESTINATION MULTIPLE PORT building VIP for: {ip}:{port}" )
                newDestVirtual.name = f"{f5_virtual.name}__{port}"
                newDestVirtual.destination = f"{ip}%{rd}:{port}"
                virtuals.append(newDestVirtual)
            else:
                log_debug(f"VsVip: {virtual.name} SINGLE DESTINATION SINGLE PORT building VIP for: {ip}:{port}" )
                virtuals.append(f5_virtual)
        if createRedirectVips:
            # Check to see if we already have a VIP on port 80 first..
            if "80" in destPortList or 80 in destPortList:
                log_error(f"Virtual: {f5_virtual.name} has multiple destinations and port 80 already exists, can't create redirect VIP.")
            else:
                f5_redirect_virtual = createRedirectVirtual(f5_virtual, ip, rd)
                log_debug(f"Virtual: {f5_virtual.name} appending redirect to virtuals list current list contains: {len(virtuals)}.")
                redirectVipFound += 1
                virtuals.append(f5_redirect_virtual)
        
    return virtuals, profiles


def loadJsonFile(filename) -> SimpleNamespace:
    file = open(filename, "r")
    jsonObj = json.loads(file.read(), object_hook=lambda d: SimpleNamespace(**d))
    file.close()
    return jsonObj


def writeBigIpConfig():
    try:
        f = open(args.bigipConfigFile, "w")
    except Exception as e:
        log_error("ERROR: problem opening file for writing. " + e)
        raise Exception("ERROR: problem opening file for writing. " + str(e))

    f.write(f"################################################################################\n")
    f.write(f"### \t RouteDomain Config \t###\n")
    f.write(f"################################################################################\n")
    for routeDomain in f5_routeDomains:
        f.write(routeDomain.tmos_obj() + "\n")
    for tenant in avi_tenants:
        if tenant.name == "admin":
            tenant.name = "Common"
        f.write(f"################################################################################\n")
        f.write(f"### Tenant: {tenant.name}\t###\n")
        f.write(f"################################################################################\n")
        if tenant.name != "Common":
            if len(tenant.f5_virtuals) < 1:
                log_warning(f"Tenant: {tenant.name} has no Virtual Servers.")
                f.write(f"# Tenant: {tenant.name} has no Virtual Servers skipping all objects.\n")
                continue
        if tenant.name != "Common":
            for partition in f5_partitions:
                if partition.name == tenant.name:
                    f.write(partition.tmos_obj() + "\n")
        f.write(f"### Tenant: {tenant.name}\tMonitors ###\n")
        for monitor in tenant.f5_monitors:
            f.write(monitor.tmos_obj() + "\n")
        f.write(f"### Tenant: {tenant.name}\tPools ###\n")
        for pool in tenant.f5_pools:
            f.write(pool.tmos_obj() + "\n")
        f.write(f"### Tenant: {tenant.name}\tProfiles ###\n")
        for profile in tenant.f5_profiles:
            f.write(profile.tmos_obj() + "\n")
        f.write(f"### Tenant: {tenant.name}\tLTM Policies###\n")
        for policy in tenant.f5_policies:
            f.write(policy.tmos_obj() + "\n")
        f.write(f"### Tenant: {tenant.name}\tVirtual Servers ###\n")
        for virtual in tenant.f5_virtuals:
            f.write(virtual.tmos_obj() + "\n")
    f.close()

    return

def writeSslFiles():
    if args.sslFileDir == "":
        args.sslFileDir = os.getcwd() + "/sslFiles/"
    try:
        os.makedirs(args.sslFileDir, exist_ok=True)
    except Exception as e:
        log_error(f"ERROR: problem creating SSL File Directory: {args.sslFileDir} " + e)
        raise Exception(f"ERROR: problem creating SSL File Directory: {args.sslFileDir} " + str(e))

    # string of import commands to append tmsh commands to...    
    importCommands = ""
    partitionList = []
    
    # Write out SSL Files:
    for tenant in avi_tenants:
        if tenant.name == "admin":
            tenant.name = "Common"
        for profile in tenant.f5_profiles:
            if profile.type == "client-ssl":
                if profile.partition not in partitionList:
                    partitionList.append(profile.partition)
                if profile.certFileName != "" and "default.crt" not in profile.certFileName:
                    try:
                        f = open(f"{args.sslFileDir}/{profile.partition}___{profile.certFileName}", "w")
                    except Exception as e:
                        log_error("ERROR: problem opening file for writing. " + e)
                        raise Exception("ERROR: problem opening file for writing. " + str(e))
                    f.write(profile.certFile)
                    #importScriptFile.write(f"tmsh install sys crypto cert /{profile.partition}/{profile.certFileName} {{ from-local-file /var/tmp/sslFiles/{profile.partition}___{profile.certFileName} }}\n")
                    importCommands += f"tmsh install sys crypto cert /{profile.partition}/{profile.certFileName} {{ from-local-file /var/tmp/sslFiles/{profile.partition}___{profile.certFileName} }}\n"
                    f.close()
                if profile.keyFileName != "" and "default.key" not in profile.keyFileName:
                    try:
                        f = open(f"{args.sslFileDir}/{profile.partition}___{profile.keyFileName}", "w")
                    except Exception as e:
                        log_error("ERROR: problem opening file for writing. " + e)
                        raise Exception("ERROR: problem opening file for writing. " + str(e))
                    f.write(profile.keyFile)
                    #importScriptFile.write(f"tmsh install sys crypto key /{profile.partition}/{profile.keyFileName} {{ from-local-file /var/tmp/sslFiles/{profile.partition}___{profile.keyFileName} }}\n")
                    importCommands += f"tmsh install sys crypto key /{profile.partition}/{profile.keyFileName} {{ from-local-file /var/tmp/sslFiles/{profile.partition}___{profile.keyFileName} }}\n"
                    f.close()
                if profile.chainFileName != "":
                    try:
                        f = open(f"{args.sslFileDir}/{profile.partition}___{profile.chainFileName}", "w")
                    except Exception as e:
                        log_error("ERROR: problem opening file for writing. " + e)
                        raise Exception("ERROR: problem opening file for writing. " + str(e))
                    f.write(profile.chainFile)
                    #importScriptFile.write(f"tmsh install sys crypto cert /{profile.partition}/{profile.chainFileName} {{ from-local-file /var/tmp/sslFiles/{profile.partition}___{profile.chainFileName} }}\n")
                    importCommands += f"tmsh install sys crypto cert /{profile.partition}/{profile.chainFileName} {{ from-local-file /var/tmp/sslFiles/{profile.partition}___{profile.chainFileName} }}\n"
                    f.close()

    # Open file for writing import commands to:
    try:
        importScriptFile = open(f"{args.sslFileDir}/avi2bigip_ssl_file_import.sh", "w")
    except Exception as e:
        log_error("ERROR: problem opening file for writing. " + e)
        raise Exception("ERROR: problem opening file for writing. " + str(e))

    for partition in partitionList:
        importScriptFile.write(f"tmsh create auth partition {partition}\n")

    importScriptFile.write(f"{importCommands}\n")
    importScriptFile.close()
    return

def main() -> int:

    global avi_config
    try:
        avi_config = loadJsonFile(args.aviJsonFile)
    except Exception as e:
        log_error("ERROR: problem loading Avi JSON Configuration. " + str(e))
        return 1

    global migration_config
    try:
        migration_config = loadJsonFile(args.migrationConfigFile)
    except Exception as e:
        log_error("ERROR: problem loading Migration Config JSON File. " + str(e))
        return 1

    if args.debug:
        print("DEBUGGING ENAABLED")
        if args.logToFile:
            logging.basicConfig(
                filename=args.logFile, 
                level=logging.DEBUG,
                format='%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
    else:
        if args.logToFile:
            logging.basicConfig(
                filename=args.logFile, 
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )

    global aviVipCount
    aviVipCount = 0
    
    global f5VipCount
    f5VipCount = 0

    global avi_tenants
    avi_tenants = []

    global f5_partitions
    f5_partitions = []
    
    global f5_routeDomains
    f5_routeDomains = []

    for tenant in avi_config.Tenant:
        f5_partition = f5_objects.partition(tenant.name)
        avi_tenant_obj   = avi_tenant(tenant.name)
        if tenant.name == "admin":
            avi_tenant_obj.name = "Common"
        if hasattr(tenant, 'description'): 
            f5_partition.description = tenant.description
            avi_tenant_obj.description = tenant.description
        for partition in migration_config.partitionDefaultRoutDomain:
            if tenant.name == partition.partitionName:
                avi_tenant_obj.defaultRouteDomain = partition.rdID
                f5_partition.defaultRouteDomain = partition.rdID
        f5_partitions.append(f5_partition)
        avi_tenants.append(avi_tenant_obj)
    
    for vrf in migration_config.routeDomainMapping:
        f5_routeDomain = f5_objects.routeDomain(vrf.vrfName, vrf.rdID)
        if hasattr(vrf, 'description'): 
            f5_routeDomain.description = vrf.description
        f5_routeDomains.append(f5_routeDomain)
    
    for virtual in avi_config.VirtualService:
        tenantName =  f5_objects.f5_sanitize(getRefName(virtual.tenant_ref))
        if tenantName == "admin":
            tenantName = "Common"
        cloudName = getRefName(virtual.cloud_ref)
        if cloudName != args.aviCloud:
            continue
        if args.aviTenant != "all" and tenantName != args.aviTenant:
            continue
        aviVipCount += 1
        try:
            virtuals, profiles = avi2bigip_virtual(virtual)
        except TypeError as e:
            log_debug("virtual: " + virtual.name + " not able to be converted to bigip object " + str(e) + " full stack: " + str(traceback.format_exc()))
            continue
        except Exception as e:
            if args.debug:
                log_error("virtual: " + virtual.name + " not able to be converted to bigip object " + str(e) + " full stack: " + str(traceback.format_exc()))
            else:
                log_error("virtual: " + virtual.name + " not able to be converted to bigip object " + str(e) )
            continue
        addedToTenant = 0
       
        # Because we create a F5 virtual for every destination/port add to the avi count
        # for each additional virtual we get back beyond the 1 expected. 
        if len(virtuals) > 1:
            aviVipCount += len(virtuals) - 1

        # we get one vip back, and we know what partition it goes in, so simply add it...
        for tenant in avi_tenants:
            if tenant.name == tenantName:
                for f5_virtual in virtuals:
                    # Skip if it's a child virtual with dummy address:
                    if "255.255.255.255%0" in f5_virtual.destination:
                        continue
                    f5VipCount += 1
                    tenant.f5_virtuals.append(f5_virtual)
                    addedToTenant += 1

        # we get multiple profiles back, and need to add them to the correct tenant/partition.
        for profile in profiles:
            #log_debug(f"TESTING Profile: {profile.name} with Partition: {profile.partition} against tenant: {tenant.name}")
            profileAddedToTenant = 0
            for tenant in avi_tenants:
                if tenant.name == "admin":
                    tenant.name = "Common"
                if tenant.name == profile.partition:
                    log_debug(f"Adding Profile: {profile.name} {profile.type} to tenant: {tenant.name}")
                    profileExists = 0
                    # Check if the profile alread exists in the tenant...
                    for testProfile in tenant.f5_profiles:
                        if testProfile.name == profile.name:
                            profileExists = 1
                            profileAddedToTenant += 1
                    # if not add it...
                    if profileExists == 0:
                        tenant.f5_profiles.append(profile)
                        profileAddedToTenant += 1
            if profileAddedToTenant == 0:
                log_error("Profile: " + profile.name + " not added to any tenant, no tenant found for: " + profile.partition)
                profileAddedToTenant = 0

        if addedToTenant == 0:
            log_error("Virtual: " + virtual.name + " not added to any tenant, no tenant found for: " + tenant.name)
            addedToTenant = 0
    
        #cleanup vars:
        del tenantName, addedToTenant, virtuals, profiles
    
    #print("Avi Tenants:")
    #pprintpp.pprint(avi_tenants)

    try: 
        writeBigIpConfig()
    except Exception as e:
        log_error("ERROR: problem writing BigIP Config." + str(e))
        return 1

    try: 
        writeSslFiles()
    except Exception as e:
        log_error("ERROR: problem writing SSL Files." + str(e))
        return 1

    print("###############")
    print("### SUMMARY ###")
    print("###############")
    print(f"Found Avi Vip Count: {aviVipCount}")
    print(f"Created F5 Vip Count: {f5VipCount}")

    return 0




# Main
if __name__ == '__main__':
    # ArgeParse stuff:
    parser = argparse.ArgumentParser(description="Convert Avi JSON Configuration to BIG-IP Configuration")
    parser.add_argument("aviJsonFile", action="store", help="Avi JSON Configuration File")
    parser.add_argument("-c", "--avi-cloud", action="store", dest="aviCloud", default="VM-Default-Cloud", help="Avi Cloud to convert, by default it converts only the VM-Default-Cloud")
    parser.add_argument("-t", "--avi-tenant", action="store", dest="aviTenant", default="all", help="Avi Tenant to convert, by default it converts all tenants")
    parser.add_argument("-b", "--bigip-conf", action="store", dest="bigipConfigFile", default="avi_bigip_for_merge.conf", help="BIG-IP Configuration File destination, avi_bigip_for_merge.conf by default")
    parser.add_argument("-m", "--migration-conf", action="store", dest="migrationConfigFile", default="config.json", help="Configuration File for Migration, config.json by default")
    parser.add_argument("-s", "--ssl-file-dir", action="store", dest="sslFileDir", default="", help="File Directory to dump SSL certs/keys into, by default it uses the current directory.")
    parser.add_argument("-f", "--log-file", action="store", dest="logFile", default="avi_bigip_for_merge.log", help="Log Path/Filename, avi_bigip_for_merge.log by default")
    parser.add_argument("-l", "--log", action=argparse.BooleanOptionalAction, dest="logToFile", default=False, help="Log to file in addition to stderr")
    parser.add_argument("-d", "--debug", action=argparse.BooleanOptionalAction, dest="debug", default=False, help="debug logging")
    global args
    args = parser.parse_args()

    # Call main function: 
    sys.exit(main())  