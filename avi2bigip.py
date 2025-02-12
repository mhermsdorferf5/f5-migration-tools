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
        self.f5_profile = []
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
    return name
def getRefTenant(url):
    ref_querystring = parse_qs(urlparse(url).query)
    name =  ref_querystring["tenant"][0]
    return name
def getRefCloud(url):
    ref_querystring = parse_qs(urlparse(url).query)
    name =  ref_querystring["cloud"][0]
    return name

parser = argparse.ArgumentParser(description="Convert Avi JSON Configuration to BIG-IP Configuration")
parser.add_argument("aviJsonFile", action="store", help="Avi JSON Configuration File")
parser.add_argument("-c", "--avi-cloud", action="store", dest="aviCloud", default="VM-Default-Cloud")
parser.add_argument("-t", "--avi-tenant", action="store", dest="aviTenant", default="all")
parser.add_argument("-b", "--bigip-conf", action="store", dest="bigipConfigFile", default="avi_bigip_for_merge.conf")
args = parser.parse_args()

avi_config_file = open(args.aviJsonFile, "r")
avi_config = json.loads(avi_config_file.read(), object_hook=lambda d: SimpleNamespace(**d))
avi_config_file.close()

avi_tenants = []
f5_partitions = []
f5_routeDomains = []
routeDomainCount = 10

for tenant in avi_config.Tenant:
    f5_partition = f5_objects.partition(tenant.name)
    avi_tenant_obj   = avi_tenant(tenant.name)
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
            log_warning("Monitor: " + monitor.name + " Don't know how to handle lb_algorithm: " + monitor.type)
        case _:
            log_warning("Monitor: " + monitor.name + " Don't know how to handle lb_algorithm: " + monitor.type)

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

    addedToTenant = 0
    for tenant in avi_tenants:
        if tenant.name == tenantName:
            tenant.f5_monitors.append(f5_monitor)
            addedToTenant = 1
    if addedToTenant == 0:
        log_error("Monitor: " + monitor.name + " not added to any tenant, no tenant found for: " + tenant.name)
        addedToTenant = 0
    
    #cleanup vars:
    del tenantName, addedToTenant, f5_monitor


for pool in avi_config.Pool:
    tenantName =  f5_objects.f5_sanitize(getRefName(pool.tenant_ref))
    vrfName    =  getRefName(pool.vrf_ref)
    cloudName = getRefName(pool.cloud_ref)
    if cloudName != args.aviCloud:
        continue
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

    addedToTenant = 0
    for tenant in avi_tenants:
        if tenant.name == tenantName:
            tenant.f5_pools.append(f5_pool)
            addedToTenant = 1
    if addedToTenant == 0:
        log_error("Pool: " + pool.name + " not added to any tenant, no tenant found for: " + tenant.name)
        addedToTenant = 0

    #cleanup vars:
    del tenantName, addedToTenant, f5_pool, f5_members, vrfName

for virtual in avi_config.VirtualService:
    cloudName = getRefName(pool.cloud_ref)
    if cloudName != args.aviCloud:
        continue

    if virtual.type != "VS_TYPE_NORMAL":
        log_error("Virtual: " + virtual.name + " Don't know how to handle type: " + virtual.type )
        continue
    tenantName =  f5_objects.f5_sanitize(getRefName(virtual.tenant_ref))
    #if pool.append_port != "NEVER":
    #    log_warning("Virtual: " + pool.name + " Don't know how to handle append_port: " + pool.append_port)

    if not hasattr(virtual, 'services'):
        log_warning("Virtual: " + virtual.name + " Don't know how to handle no services on VirtualService object." )
        continue
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

    f5_virtual = f5_objects.virtual(virtual.name, destination, default_pool)
    f5_virtual.routeDomain = vrfName

    if tenantName != "admin":
        f5_virtual.partition = tenantName

    addedToTenant = 0
    for tenant in avi_tenants:
        if tenant.name == tenantName:
            tenant.f5_virtuals.append(f5_virtual)
            addedToTenant = 1
    if addedToTenant == 0:
        log_error("Virtual: " + virtual.name + " not added to any tenant, no tenant found for: " + tenant.name)
        addedToTenant = 0

    #cleanup vars:
    del tenantName, addedToTenant, vrfName, destination, default_pool, f5_virtual, vsVipName, ip, mask, vsvip

print("Avi Tenants:")
pprintpp.pprint(avi_tenants)

f = open(args.bigipConfigFile, "w")
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
    f.write(f"### Tenant: {tenant.name}\tVirtual Servers ###\n")
    for virtual in tenant.f5_virtuals:
        f.write(virtual.tmos_obj() + "\n")
f.close()




