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
from types import SimpleNamespace
import f5_objects
from urllib.parse import urlparse, parse_qs
import pprintpp
import re
import argparse


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
    def __repr__(self):
        virtualString= "[ "
        for virtual in self.f5_virtuals:
            virtualString += f"\n\t\t{virtual}"
        virtualString += "]"
        poolString = "[ "
        for pool in self.f5_pools:
            poolString += f"\n\t\t{pool}"
        poolString += "]"
        return f"avi_tenant(name='{self.name}', defaultRouteDomain='{self.defaultRouteDomain}' description='{self.description}', \n\tpools='{poolString}', \n\tvirtuals='{virtualString}')"


def usage ():
    print("Usage:")
    print("%s --avi-json <AviConfig.json> ")


def log_error(logmessage):
    logmessage = str("ERROR: " + logmessage)
    print(logmessage, file=sys.stderr)

def log_warning(logmessage):
    logmessage = str("WARNING: " + logmessage)
    print(logmessage, file=sys.stderr)

def getRefName(url):
    ref_querystring = parse_qs(urlparse(url).query)
    name =  ref_querystring["name"][0]
    #name = name.replace(" ", "_")
    #name = name.replace("%20", "_")
    #name = name.replace("%2A", "wildcard")
    return name
def getRefTenant(url):
    ref_querystring = parse_qs(urlparse(url).query)
    name =  ref_querystring["tenant"][0]
    #name = name.replace(" ", "_")
    #name = name.replace("%20", "_")
    #name = name.replace("%2A", "wildcard")
    return name
def getRefCloud(url):
    ref_querystring = parse_qs(urlparse(url).query)
    name =  ref_querystring["cloud"][0]
    #name = name.replace(" ", "_")
    #name = name.replace("%20", "_")
    #name = name.replace("%2A", "wildcard")
    return name

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

    f5_profile.ciphers = aviSSLProfile.accepted_ciphers

    cert = aviSSLKeyAndCertificate.certificate.certificate
    #print(f"DEBUG: Cert: {cert}")
    key = aviSSLKeyAndCertificate.key
    #print(f"DEBUG: Key: {key}")

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
                #print(f"DEBUG: TESTING {caName} == {certName} and certTenant {caTenant} == {certTenant}")
                if certName == caName and certTenant == caTenant:
                    chain = chain + "\n" + cert.certificate.certificate
        f5_profile.chainFileName = f"{f5_objects.f5_sanitize(aviSSLKeyAndCertificate.ca_certs[0].name)}.crt"
        f5_profile.chainFile = chain
        #print(f"DEBUG: ChainFileName: {f5_profile.chainFileName} Chain: {f5_profile.chainFile}") 



    #if aviNetworkProfile.profile.type == "PROTOCOL_TYPE_UDP_FAST_PATH" and type == "fastl4":
    #    f5_profile.datagramLoadBalancing = "enabled"
    #    # snat's don't exist in F5 profiles.... but oneoff handling.
    #    if snat == "disabled":
    #        f5_profile.snat = "disabled"
    #if tenantName == "admin":
    #    f5_profile.partition = "Common"
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
            #log_error("Monitor: " + monitor.name + " Don't know how to handle monitor: " + monitor.type)
            raise Exception("Monitor: " + monitor.name + " Don't know how to handle monitor: " + monitor.type)
        case _:
            #log_error("Monitor: " + monitor.name + " Don't know how to handle monitor: " + monitor.type)
            raise Exception("Monitor: " + monitor.name + " Don't know how to handle monitor: " + monitor.type)

    f5_monitor = f5_objects.monitor(monitor.name, type)

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

def avi2bigip_pool(pool):
    tenantName =  f5_objects.f5_sanitize(getRefName(pool.tenant_ref))
    vrfName    =  getRefName(pool.vrf_ref)
    cloudName = getRefName(pool.cloud_ref)
    if pool.pool_type != "POOL_TYPE_GENERIC_APP":
        log_error("Pool: " + pool.name + " Don't know how to handle pool_type: " + pool.pool_type )
    if pool.append_port != "NEVER":
        log_error("Pool: " + pool.name + " Don't know how to handle append_port: " + pool.append_port)

    f5_members = []
    if hasattr(pool, 'servers'): 
        for member in pool.servers:
            if member.resolve_server_by_dns == True:
                member.ip.addr = member.hostname
            if hasattr(member, 'port'): 
                f5_member = f5_objects.pool_member(member.ip.addr, member.port)
            else:
                f5_member = f5_objects.pool_member(member.ip.addr, pool.default_server_port)
            if member.ratio != 1:
                f5_member.ratio = member.ratio
            if member.enabled != "true":
                f5_member.enabled = "no"
            f5_members.append(f5_member)

    f5_pool = f5_objects.pool(pool.name, f5_members )
    f5_pool.routeDomain = vrfName

    if pool.enabled is False:
        f5_pool.enabled = False
    
    if hasattr(pool, 'fail_action'): 
        match pool.fail_action.type:
            case "FAIL_ACTION_CLOSE_CONN":
                f5_pool.serviceDownAction = "reset"
            case _:
                log_warning("Pool: " + pool.name + " Don't know how to handle fail_action: " + pool.fail_action.type)

    if hasattr(pool, 'health_monitor_refs'): 
        if len(pool.health_monitor_refs) > 1:
            for index, monitor_ref in enumerate(pool.health_monitor_refs):
                monitorName =  f5_objects.f5_sanitize(getRefName(monitor_ref))
                monitorTenantName = f5_objects.f5_sanitize(getRefTenant(monitor_ref))
                monitorPartition =  "Common"
                if monitorTenantName != "admin":
                    monitorPartition = monitorTenantName
                if index == 0:
                    f5_pool.monitors = f"/{monitorPartition}/{monitorName}"
                else:
                    f5_pool.monitors = f5_pool.monitors + " and " + f"/{monitorPartition}/{monitorName}"
        else:
            monitorName =  f5_objects.f5_sanitize(getRefName(pool.health_monitor_refs[0]))
            monitorTenantName =  f5_objects.f5_sanitize(getRefTenant(pool.health_monitor_refs[0]))
            monitorPartition =  "Common"
            if monitorTenantName != "admin":
                monitorPartition = monitorTenantName
            f5_pool.monitors = f"/{monitorPartition}/{monitorName}"

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
    if virtual.type != "VS_TYPE_NORMAL":
        #log_error("Virtual: " + virtual.name + " Don't know how to handle type: " + virtual.type )
        raise Exception("Virtual: " + virtual.name + " Don't know how to handle type: " + virtual.type )
    tenantName =  f5_objects.f5_sanitize(getRefName(virtual.tenant_ref))
    #if pool.append_port != "NEVER":
    #    log_warning("Virtual: " + pool.name + " Don't know how to handle append_port: " + pool.append_port)

    if not hasattr(virtual, 'services'):
        #log_warning("Virtual: " + virtual.name + " Don't know how to handle no services on VirtualService object." )
        raise Exception("Virtual: " + virtual.name + " Don't know how to handle no services on VirtualService object." )
    if len(virtual.services) > 1:
        log_error("Virtual: " + virtual.name + " Don't know how to handle multiple services on VirtualService object." )
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

    # lookup VsVip Reference and find destination IP
    vsVipName =  getRefName(virtual.vsvip_ref)
    for vsvip in avi_config.VsVip:
        if vsvip.name == vsVipName:
            if len(vsvip.vip) > 1:
                log_warning("VsVip: " + vsVipName + " Don't know how to handle multiple vip objects in VsVip object." )
            ip = vsvip.vip[0].ip_address.addr
            mask = vsvip.vip[0].prefix_length 
            vrfName =  getRefName(vsvip.vrf_context_ref)
    destination = ip + ":" + str(virtual.services[0].port)
    if mask != 32:
        log_warning("VsVip: " + vsVipName + " Don't know how to handle VIP with non /32 bit mask." )

    # Figure out pool:
    default_pool = "none"
    if hasattr(virtual, 'pool_ref'):
        # lookup pool Reference and pool name
        default_pool =  f"/{f5_objects.f5_sanitize(getRefTenant(virtual.pool_ref))}/{f5_objects.f5_sanitize(getRefName(virtual.pool_ref))}"
        #default_pool =  f5_objects.f5_sanitize(getRefName(virtual.pool_ref))
    if hasattr(virtual, 'pool_group_ref'):
        log_warning("Virtual: " + virtual.name + " Don't know how to handle pool_group_ref." )

    #poolMatchCount = 0
    #for pool in f5_pools:
    #   if default_pool == pool.name:
    #       poolMatchCount = poolMatchCount+1
    #if poolMatchCount != 1 and default_pool != "none":
    #    log_warning("Virtual: " + virtual.name + " uses pool: " + default_pool + " but there's more than one object with the same name count: " + str(poolMatchCount) + "." )

    # Figure out Profiles:
    # Network Profile first...
    networkProfileName = getRefName(virtual.network_profile_ref)
    networkProfileTenant = f5_objects.f5_sanitize(getRefTenant(virtual.network_profile_ref))

    networkProfileFound = 0
    for networkProfile in avi_config.NetworkProfile:
        if networkProfile.name == networkProfileName and f5_objects.f5_sanitize(getRefName(networkProfile.tenant_ref)) == networkProfileTenant:
            try:
                f5_network_profile = avi2bigip_network_profile(networkProfile)
            except Exception as e:
                log_error("Network Profile: " + networkProfile.name + " not able to be converted to bigip object " + str(e))
            networkProfileFound += 1
    
    if networkProfileFound == 0:
        #print(f"ERROR: networkProfile: {networkProfileName} not found in networkProfileTenant {networkProfileTenant}.")
        raise Exception(f"ERROR: networkProfile: {networkProfileName} not found in networkProfileTenant {networkProfileTenant}.")
    if networkProfileFound > 1:
        #print(f"ERROR: Multiple network profiles found networkProfile: {networkProfileName} networkProfileTenant {networkProfileTenant}.")
        raise Exception(f"ERROR: Multiple network profiles found networkProfile: {networkProfileName} networkProfileTenant {networkProfileTenant}.")

    f5_virtual = f5_objects.virtual(virtual.name, destination, default_pool)
    f5_virtual.routeDomain = vrfName
    profiles = []
    
    profiles.append(f5_network_profile)
    f5_virtual.profilesAll.append(f"/{f5_network_profile.partition}/{f5_network_profile.name}")

    if tenantName != "admin":
        f5_virtual.partition = tenantName


    # Now SSL Profile, if it has one.
    if hasattr(virtual, 'ssl_profile_ref'):
        sslProfileName = getRefName(virtual.ssl_profile_ref)
        sslProfileTenant = f5_objects.f5_sanitize(getRefTenant(virtual.ssl_profile_ref))

        if len(virtual.ssl_key_and_certificate_refs) > 1:
            log_warning("Virtual: " + virtual.name + " Don't know how to handle multiple ssl_key_and_certificate_refs." )
        sslCertProfileName = getRefName(virtual.ssl_key_and_certificate_refs[0])
        sslCertProfileTenant = f5_objects.f5_sanitize(getRefTenant(virtual.ssl_key_and_certificate_refs[0]))
    
        sslProfileFound = 0
        for sslProfile in avi_config.SSLProfile:
            if sslProfile.name == sslProfileName and f5_objects.f5_sanitize(getRefName(sslProfile.tenant_ref)) == sslProfileTenant:
                #print(f"DEBUG: found matching sslProfile: {sslProfileName} sslProfileTenant {sslProfileTenant}")
                for sslCertProfile in avi_config.SSLKeyAndCertificate:
                    if sslCertProfile.name == sslCertProfileName and f5_objects.f5_sanitize(getRefName(sslCertProfile.tenant_ref)) == sslCertProfileTenant:
                        #print(f"DEBUG: found matching sslProfileCertAndKey: {sslCertProfile.name} sslProfileTenant {sslCertProfile.tenant_ref}")
                        try:
                            f5_clientssl_profile = avi2bigip_clientssl_profile(sslProfile, sslCertProfile)
                        except Exception as e:
                            log_error("ERROR: clientssl profile: " + sslProfileName + " " + sslCertProfileName + " not able to be converted to bigip object " + str(e))
                            print(e)
                        sslProfileFound += 1

        if sslProfileFound == 0:
            #log_error(f"ERROR: sslProfile: {sslProfileName} not found in sslProfileTenant {sslProfileTenant}.")
            raise Exception(f"ERROR: sslProfile: {sslProfileName} not found in sslProfileTenant {sslProfileTenant}.")
        if sslProfileFound > 1:
            #log_error(f"ERROR: Multiple ssl profiles found sslProfile: {sslProfileName} sslProfileTenant {sslProfileTenant}.")
            raise Exception(f"ERROR: Multiple ssl profiles found sslProfile: {sslProfileName} sslProfileTenant {sslProfileTenant}.")
    
        f5_virtual.profilesClientSide.append(f"/{f5_clientssl_profile.partition}/{f5_clientssl_profile.name}")
        profiles.append(f5_clientssl_profile)


    return f5_virtual, profiles


def loadAviConfigFile(filename) -> SimpleNamespace:
    avi_config_file = open(filename, "r")
    avi_config = json.loads(avi_config_file.read(), object_hook=lambda d: SimpleNamespace(**d))
    avi_config_file.close()
    return avi_config


def writeBigIpConfig():
    try:
        f = open(args.bigipConfigFile, "w")
    except Exception as e:
        #log_error("ERROR: problem opening file for writing. " + e)
        raise Exception("ERROR: problem opening file for writing. " + str(e))

    for tenant in avi_tenants:
        if tenant.name == "admin":
            tenant.name = "Common"
        f.write(f"################################################################################\n")
        f.write(f"### Tenant: {tenant.name}\t###\n")
        f.write(f"################################################################################\n")
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
        #log_error(f"ERROR: problem creating SSL File Directory: {args.sslFileDir} " + e)
        raise Exception(f"ERROR: problem creating SSL File Directory: {args.sslFileDir} " + str(e))

    # Open file for writing import commands to:
    try:
        importScriptFile = open(f"{args.sslFileDir}/avi2bigip_ssl_file_import.sh", "w")
    except Exception as e:
        #log_error("ERROR: problem opening file for writing. " + e)
        raise Exception("ERROR: problem opening file for writing. " + str(e))
    
    # Write out SSL Files:
    for tenant in avi_tenants:
        if tenant.name == "admin":
            tenant.name = "Common"
        for profile in tenant.f5_profiles:
            if profile.type == "client-ssl":
                if profile.certFileName != "":
                    try:
                        f = open(f"{args.sslFileDir}/{profile.partition}___{profile.certFileName}", "w")
                    except Exception as e:
                        #log_error("ERROR: problem opening file for writing. " + e)
                        raise Exception("ERROR: problem opening file for writing. " + str(e))
                    f.write(profile.certFile)
                    importScriptFile.write(f"tmsh install sys crypto cert /{profile.partition}/{profile.certFileName} {{ from-local-file /var/tmp/sslFiles/{profile.partition}___{profile.certFileName} }}\n")
                    f.close()
                if profile.keyFileName != "":
                    try:
                        f = open(f"{args.sslFileDir}/{profile.partition}___{profile.keyFileName}", "w")
                    except Exception as e:
                        #log_error("ERROR: problem opening file for writing. " + e)
                        raise Exception("ERROR: problem opening file for writing. " + str(e))
                    f.write(profile.keyFile)
                    importScriptFile.write(f"tmsh install sys crypto key /{profile.partition}/{profile.keyFileName} {{ from-local-file /var/tmp/sslFiles/{profile.partition}___{profile.keyFileName} }}\n")
                    f.close()
                if profile.chainFileName != "":
                    try:
                        f = open(f"{args.sslFileDir}/{profile.partition}___{profile.chainFileName}", "w")
                    except Exception as e:
                        #log_error("ERROR: problem opening file for writing. " + e)
                        raise Exception("ERROR: problem opening file for writing. " + str(e))
                    f.write(profile.chainFile)
                    importScriptFile.write(f"tmsh install sys crypto cert /{profile.partition}/{profile.chainFileName} {{ from-local-file /var/tmp/sslFiles/{profile.partition}___{profile.chainFileName} }}\n")
                    f.close()
    importScriptFile.close()
    return

def main() -> int:

    global avi_config
    try:
        avi_config = loadAviConfigFile(args.aviJsonFile)
    except Exception as e:
        log_error("ERROR: problem loading Avi JSON Configuration. " + str(e))
        return 1

    global avi_tenants
    avi_tenants = []

    global f5_partitions
    f5_partitions = []

    f5_routeDomains = []
    routeDomainCount = 10
    
    for tenant in avi_config.Tenant:
        f5_partition = f5_objects.partition(tenant.name)
        avi_tenant_obj   = avi_tenant(tenant.name)
        if tenant.name == "admin":
            avi_tenant_obj.name = "Common"
        if hasattr(tenant, 'description'): 
            f5_partition.description = tenant.description
            avi_tenant_obj.description = tenant.description
        f5_partitions.append(f5_partition)
        avi_tenants.append(avi_tenant_obj)
    
    for vrf in avi_config.VrfContext:
        cloud = getRefName(vrf.cloud_ref)
        if cloud != args.aviCloud:
            continue
        vrfTenantName =  getRefName(vrf.tenant_ref)
        f5_routeDomain = f5_objects.routeDomain(vrf.name, routeDomainCount)
        routeDomainCount = routeDomainCount + 10
        if hasattr(vrf, 'description'): 
            f5_routeDomain.description = vrf.description
        for tenant in avi_tenants:
            if tenant.name == vrf.name:
                tenant.defaultRouteDomain = f5_routeDomain.id
        f5_routeDomains.append(f5_routeDomain)
    
    #pprintpp.pprint(avi_vrfs)
    #pprintpp.pprint(avi_tenants)
    
    for monitor in avi_config.HealthMonitor:
        tenantName =  f5_objects.f5_sanitize(getRefName(monitor.tenant_ref))
        if tenantName == "admin":
            tenantName = "Common"
    
        try:
            f5_monitor = avi2bigip_monitor(monitor)
        except Exception as e:
            log_error("Monitor: " + monitor.name + " not able to be converted to bigip object " + str(e))
            continue
    
        addedToTenant = 0
        for tenant in avi_tenants:
            if tenant.name == tenantName:
                tenant.f5_monitors.append(f5_monitor)
                addedToTenant = 1
        if addedToTenant == 0:
            log_error("Monitor: " + monitor.name + " not added to any tenant, no tenant found for: " + tenant.name)
            addedToTenant = 0
        
        #cleanup vars:
        del addedToTenant, f5_monitor, tenantName
    
    
    for pool in avi_config.Pool:
        tenantName =  f5_objects.f5_sanitize(getRefName(pool.tenant_ref))
        if tenantName == "admin":
            tenantName = "Common"
        vrfName    =  getRefName(pool.vrf_ref)
        cloudName = getRefName(pool.cloud_ref)
        if cloudName != args.aviCloud:
            continue
        try:
            f5_pool = avi2bigip_pool(pool)
        except Exception as e:
            log_error("Pool: " + pool.name + " not able to be converted to bigip object " + str(e))
            continue
        addedToTenant = 0
        for tenant in avi_tenants:
            if tenant.name == tenantName:
                tenant.f5_pools.append(f5_pool)
                addedToTenant = 1
        if addedToTenant == 0:
            log_error("Pool: " + pool.name + " not added to any tenant, no tenant found for: " + tenant.name)
            addedToTenant = 0
    
        #cleanup vars:
        del tenantName, addedToTenant, f5_pool, vrfName, cloudName
    
    for virtual in avi_config.VirtualService:
        tenantName =  f5_objects.f5_sanitize(getRefName(virtual.tenant_ref))
        if tenantName == "admin":
            tenantName = "Common"
        cloudName = getRefName(virtual.cloud_ref)
        if cloudName != args.aviCloud:
            continue
        try:
            f5_virtual, profiles = avi2bigip_virtual(virtual)
        except Exception as e:
            log_error("virtual: " + virtual.name + " not able to be converted to bigip object " + str(e))
            continue
        addedToTenant = 0
        for tenant in avi_tenants:
            if tenant.name == tenantName:
                tenant.f5_virtuals.append(f5_virtual)
                addedToTenant = 1
            for profile in profiles:
                #print(f"DEBUG: TESTING Profile: {profile.name} with Partition: {profile.partition} against tenant: {tenant.name}")
                if tenant.name == profile.partition:
                    #print(f"DEBUG: Adding Profile: {profile.name} to tenant: {tenant.name}")
                    profileExists = 0
                    for profile in tenant.f5_profiles:
                        if profile.name == profile.name:
                            profileExists = 1
                    if profileExists == 0:
                        tenant.f5_profiles.append(profile)
        if addedToTenant == 0:
            log_error("Virtual: " + virtual.name + " not added to any tenant, no tenant found for: " + tenant.name)
            addedToTenant = 0
    
        #cleanup vars:
        del tenantName, addedToTenant, f5_virtual
    
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

    return 0




# Main
if __name__ == '__main__':
    # ArgeParse stuff:
    parser = argparse.ArgumentParser(description="Convert Avi JSON Configuration to BIG-IP Configuration")
    parser.add_argument("aviJsonFile", action="store", help="Avi JSON Configuration File")
    parser.add_argument("-c", "--avi-cloud", action="store", dest="aviCloud", default="VM-Default-Cloud")
    parser.add_argument("-t", "--avi-tenant", action="store", dest="aviTenant", default="all")
    parser.add_argument("-b", "--bigip-conf", action="store", dest="bigipConfigFile", default="avi_bigip_for_merge.conf")
    parser.add_argument("-d", "--ssl-file-dir", action="store", dest="sslFileDir", default="")
    global args
    args = parser.parse_args()

    # Call main function: 
    sys.exit(main())  