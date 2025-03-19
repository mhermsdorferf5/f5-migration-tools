# F5 Migration Tools

This repo is intended to contain migraiton scripts for various system to BIG-IP.  Currently the only tool is to convert Avi to BIG-IP.

## Contents

-[Installation](#installation)
-[Avi Migration Tool](#avi-migration-tool)
-[Miscellaneous Tools](#miscellaneous-tools)

## Installation

Most of these tools are written in python and have dependencies on packages often not included in the system python.  You can either install these as system packages, or you can create a python virtual environment and use pip to install them within the virtual environment.

Python Virtual Environment Instructions:

```bash
# Create Python virtual environment in ./python-venv
python3 -m venv ./.python-venv
# Move shell into the venv:
source ./.python-venv/bin/activate
# install/upgrade pip:
python3 -m pip install --upgrade pip
# Install required packages/libs:
python3 -m pip install argparse logging requests
# You're now ready to run tools using:
python3 avi2bigip.py
```

## Avi Migration Tool

This was built with configruation exported from a version 22.1.6 controller.  Note that you do need to export the Avi config with un-encrypted TLS keys, this can only be done via CLI on the Avi Controller.

### Migration Exceptions & Traffic Handling Differences

* Virtual Services:
  * VS_TYPE_NORMAL is currently supported
  * VS_TYPE_PARENT & VS_TYPE_CHILD is supported for SNI parent/child handling only.
  * Only HTTP and L4 type VIPs currently supported.
  * Network Security Policies are not supported
  * Analytics Profiles are not supported.
  * HTTP Policies are not supported (no content switching)
* HTTP Profiles:
  * Content Rewrite rules/Policies are not supported.
  * Compression Policies are not supported.
  * xff_update: not fully supported, F5 by default always appends a new XFF header to the request.
    * If XFF replacement is required, we'll need an LTM Policy or iRule to get that functionality.
  * xff_alternate_name: not fully supported, F5's HTTP Profiles only handle inserting xff headers with the industry standard name: X-Forwarded-For.
    * If custom XFF header names are required, that can be done via iRule or LTM Policies.
  * HTTP MultiPlexing: OneConnect needs to be added to support this.
* Client mTLS isn't currently supported.
* Pools:
  * Pool Groups with differing server-side TLS are not supported.
  * Server mTLS isn't currently supported.
  * Don't handle append_port property, this script doesn't generate configuration that will append ports to the host header ever.
    * If host header rewriting is required, that can be done via iRule, LTM Policies, or Rewrite Profiles.
* Health Monitors:
  * HEALTH_MONITOR_EXTERNAL is not supported
  * HEALTH_MONITOR_SCTP is not supported
* No support for Avi WAF Engine.
* No support for Avi DNS.

### Program Options

| Short Option | Long Option | Description |
| -h | --help | Prints application help seen below |
| -c \<aviCloud> | --avi-cloud \<aviCloud> | Limits the conversion to the cloud specified, by default this is "VM-Default-Cloud" |
| -t \<aviTenant> | --avi-tenant \<aviTenant> | Limits the conversion the tenant specified, by default it converts all tenants |
| -v \<aviVirtualService> | --avi-vip \<aviVirtualServiceName> | Limits the conversion to that specific Virtual Service |
| -b \<output-config> | --bigip-conf \<output-config> | Filename to save the generated BIG-IP configuration to, by default avi_bigip_for_merge.conf |
| -m \<migration-config> | --migration-conf \<migration-config> | Filename to read migration configuration from, required for Route Domain Mapping |
| -s \<ssl-directory> | --ssl-file-dir \<ssl-directory> | Directory where we should dump the SSL certs/keys and import script, by default it's the current workign directory |
| -f \<log-filename> | --log-file \<log-filename> | Filename to save logs to, by default avi_bigip_for_merge.log |
| -l | --log | Enable writing a log file in addition to writing logs to standard error/standard out. |
| -d | --debug | Enable debug logging |

```bash
$ python3 avi2bigip.py --help
usage: avi2bigip.py [-h] [-c AVICLOUD] [-t AVITENANT] [-v AVIVIRTUAL] [-b BIGIPCONFIGFILE] [-m MIGRATIONCONFIGFILE] [-s SSLFILEDIR] [-f LOGFILE]
                    [-l | --log | --no-log] [-d | --debug | --no-debug]
                    aviJsonFile

Convert Avi JSON Configuration to BIG-IP Configuration

positional arguments:
  aviJsonFile           Avi JSON Configuration File

options:
  -h, --help            show this help message and exit
  -c AVICLOUD, --avi-cloud AVICLOUD
                        Avi Cloud to convert, by default it converts only the VM-Default-Cloud
  -t AVITENANT, --avi-tenant AVITENANT
                        Avi Tenant to convert, by default it converts all tenants
  -v AVIVIRTUAL, --avi-virtual AVIVIRTUAL
                        Avi Virtual Service to convert, by default it converts all Virtual Services
  -b BIGIPCONFIGFILE, --bigip-conf BIGIPCONFIGFILE
                        BIG-IP Configuration File destination, avi_bigip_for_merge.conf by default
  -m MIGRATIONCONFIGFILE, --migration-conf MIGRATIONCONFIGFILE
                        Configuration File for Migration, config.json by default
  -s SSLFILEDIR, --ssl-file-dir SSLFILEDIR
                        File Directory to dump SSL certs/keys into, by default it uses the current directory.
  -f LOGFILE, --log-file LOGFILE
                        Log Path/Filename, avi_bigip_for_merge.log by default
  -l, --log, --no-log   Log to file in addition to stderr
  -d, --debug, --no-debug
                        debug logging
```

### Configuration File

A configuration file is required to map Avi VRFs to F5 Route Domain IDs, additionally it's very helpful for mapping default route domain IDs to F5 partitions created from Avi Tenants.  Additionally, while many TLS Cipher strings are teh came between Avi and F5, not all are.  This config can be used mapping Avi TLS cipher strings to a cipher string name supported by BIG-IP.

```json
{
  "routeDomainMapping": [
    {
      "vrfName": "FOO",
      "rdID": 20
    },
    {
      "vrfName": "BAR",
      "rdID": 10
    },
    {
      "vrfName": "FOOBAR",
      "rdID": 11
    }
  ],
  "partitionDefaultRoutDomain": [
    {
      "partitionName": "FOO",
      "rdID": 20
    },
    {
      "partitionName": "BAR",
      "rdID": 10
    },
    {
      "partitionName": "FOOBAR",
      "rdID": 11
    },
    {
      "partitionName": "INTERNET",
      "rdID": 100
    }
  ],
  "cipherStringMapping": [
    {
      "aviCipher": "ecdhe-rsa-aes256-sha",
      "f5Cipher": "ECDHE-RSA-AES256-SHA384"
    },
    {
      "aviCipher": "ecdhe-rsa-aes128-sha",
      "f5Cipher": "ECDHE-RSA-AES128-SHA256"
    }
  ]
}

```

### Usage Example

```bash
$ python3 avi2bigip.py -l avi-config-unencrypted.json 2>&1 2>&1
###############
### SUMMARY ###
###############
Found Avi Vip Count: 459
Created F5 Vip Count: 458
$ ll
total 2.2M
-rwxrwxrwx 1 mhermsdorfer mhermsdorfer  45K Mar 14 14:27  avi_bigip_for_merge.log
-rwxrwxrwx 1 mhermsdorfer mhermsdorfer 891K Mar 14 14:27  avi_bigip_for_merge.conf
drwxrwxrwx 1 mhermsdorfer mhermsdorfer  512 Mar 14 14:27  .
drwxrwxrwx 1 mhermsdorfer mhermsdorfer  512 Mar 14 14:27  sslFiles
$ scp -r sslFiles avi_bigip_for_merge.conf bigip:/var/tmp/
avi2bigip_ssl_file_import.sh                                                                    100%   11KB 110.9KB/s   00:00
Common___example.crt                                                                            100% 2844    22.0KB/s   00:00
Common___example.key                                                                            100% 1704    14.5KB/s   00:00  
avi_bigip_for_merge.conf                                                                        100%  890KB   1.1MB/s   00:00   
$ ssh bigip
[root@localhost:Active:Standalone] config # bash /var/tmp/sslFiles/avi2bigip_ssl_file_import.sh
01020037:3: The requested partition (Common) already exists.
[root@localhost:Active:Standalone] config # tmsh load sys config merge file /var/tmp/avi_bigip_for_merge.conf
Loading configuration...
  /var/tmp/avi_bigip_for_merge.conf
[root@localhost:Active:Standalone] config #
```

## Miscellaneous Tools

### json-breakdown.sh

This will take in a large json file and break it down into smaller files based on the top level 'list' of objects.  Particularly useful for Avi Configs.

### create-dummy-crypto.py

This will read in all of the files ending with .crt or .key in a directory, and then re-generate the keys and certs with the same filename & x509 subject but with freshly generated dummy key material.  Note that of course these are now self-signed certs.  While we do copy the subject over, other extensions such as SNI are ignored.
