import re;
from enum import Enum;

bannedObjNames = [
    "apm-forwarding-client-tcp",
    "apm-forwarding-server-tcp",
    "f5-tcp-lan",
    "f5-tcp-mobile",
    "f5-tcp-progressive",
    "f5-tcp-wan",
    "mptcp-mobile-optimized",
    "splitsession-default-tcp",
    "tcp",
    "tcp-lan-optimized",
    "tcp-legacy",
    "tcp-mobile-optimized",
    "tcp-wan-optimized",
    "wom-tcp-lan-optimized",
    "wom-tcp-wan-optimized",
    "udp",
    "udp_decrement_ttl",
    "udp_gtm_dns",
    "udp_preserve_ttl",
    "apm-forwarding-fastL4",
    "fastL4",
    "full-acceleration",
    "security-fastL4",
    "http",
    "http-explicit",
    "http-transparent",
]

def f5_sanitize(name):
    clean_name = name.replace("%20", "_")
    clean_name = clean_name.replace("%2A", "wildcard")
    clean_name = clean_name.replace(" ", "_")
    #clean_name = clean_name.replace("-", "_")
    if clean_name in bannedObjNames:
        return "object_" + clean_name
    if re.match(r'^[a-zA-Z/]', clean_name):
        #return clean_name.lower()
        return clean_name
    else:
        #return "a_" + clean_name.lower()
        return "object_" + clean_name

class bigip_obj:
    description = "Generic BIG-IP Object"

    def __init__(self, name):
        self.name = name

    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, value):
        self._name = f5_sanitize(value)

    def __repr__(self):
        return f"bigip_obj(name='{self.name}', description='{self.description}')"
    
class ltmPolicy(bigip_obj):
    description = "LTM Policy"

    def __init__(self, name):
        self.name = f5_sanitize(name)
        self.controls = [ "none" ]
        self.requires = [ "none" ]
        self.strategy = "first-match"
        self.status = "published"
        self.rules = dict()

    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, value):
        self._name = f5_sanitize(value)
        
    @property
    def controls(self):
        return self._controls
    @controls.setter
    def controls(self, value):
        _valid_controls = [ "none", "forwarding", "caching", "compression", "acceleration", "asm", "avr", "l7dos", "classification", "request-adaptation", "response-adaptation", "server-ssl", "websocket" ]
        if isinstance(value, list):
            self._controls = [ "none" ]
            valid = True
            for i in value:
                if i not in _valid_controls:
                    valid = False
            if valid:
                self._controls = value
        else:
            self._controls = [ "none" ]
            
    @property
    def requires(self):
        return self._requires
    @requires.setter
    def requires(self, value):
        _valid_requires = [ "none", "http", "tcp", "client-ssl", "ssl-persist", "classification" ]
        if isinstance(value, list):
            self._requires = [ "none" ]
            valid = True
            for i in value:
                if i not in _valid_requires:
                    valid = False
            if valid:
                self._requires = value
        else:
            self._requires = [ "none" ]

    def __str__(self):
        return f"bigip_ltm_policy(name={self.name})"
    def __repr__(self):
        return f"bigip_ltm_policy(name={self.name})"

    def tmos_obj(self):
        controlsStr = "{ "
        for control in self.controls:
            controlsStr += f"{control} "
        controlsStr += "}"
        requiresStr = "{ "
        for requires in self.requires:
            requiresStr += f"{requires} "
        requiresStr += "}"
        rulesStr = "{"
        for i, (key, value) in enumerate(self.rules.items()):
            rulesStr += f"\n\t\t{key} {{ \n{value}\t\t}}"
        rulesStr += "\n\t}"
        return f"""ltm policy /{self.partition}/{self.name} {{
    controls {controlsStr}
    requires {requiresStr}
    rules {rulesStr}
    status {self.status}
    strategy {self.strategy}
}}"""

class oneconnectProfile(bigip_obj):
    description = "LTM OneConnect Profile"

    def __init__(self, name):
        self.name = f5_sanitize(name)
        self.type = "oneconnect"
        self.partition = "Common"
        self.maxAge = 86400
        self.maxReuse = 1000
        self.maxSize = 10000
        self.sourceMask = "any"

    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, value):
        self._name = f5_sanitize(value)

    def __str__(self):
        return f"bigip_oneconnectProfile(name={self.name}"
    def __repr__(self):
        return f"bigip_oneconnectpProfile(name={self.name}"
    def tmos_obj(self):
        return f"""ltm profile one-connect /{self.partition}/{self.name} {{
    defaults-from oneconnect
    idle-timeout-override disabled
    max-age {self.maxAge}
    max-reuse {self.maxReuse}
    max-size {self.maxSize} 
    source-mask {self.sourceMask}
}}"""

class httpProfile(bigip_obj):
    description = "LTM HTTP Profile"

    def __init__(self, name):
        self.name = f5_sanitize(name)
        self.type = "http"
        self.partition = "Common"
        self.maxHeaderCount = 64
        self.maxHeaderSize = 32768
        self.insertXFF = "enabled"
        self.acceptXFF = "disabled"
        self.xffAlternativeNames = "none"
        self.oneconnectTransformations = "enabled"
        self.redirectRewrite = "none"

    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, value):
        self._name = f5_sanitize(value)

    def __str__(self):
        return f"bigip_httpProfile(name={self.name}"
    def __repr__(self):
        return f"bigip_httpProfile(name={self.name}"
    def tmos_obj(self):
        return f"""ltm profile http /{self.partition}/{self.name} {{
    defaults-from http
    proxy-type reverse
    enforcement {{
        max-header-count {str(self.maxHeaderCount)}
        max-header-size {str(self.maxHeaderSize)}
        pipeline allow
        unknown-method allow
    }}
    oneconnect-status-reuse "200 206"
    oneconnect-transformations {self.oneconnectTransformations}
    request-chunking sustain
    response-chunking sustain
    server-agent-name BigIP
    insert-xforwarded-for {self.insertXFF}
    accept-xff {self.acceptXFF}
    xff-alternative-names {self.xffAlternativeNames}
    redirect-rewrite {self.redirectRewrite}
}}"""

class persistenceProfile(bigip_obj):
    description = "LTM Persistence Profile"

    def __init__(self, name, type):
        self.name = f5_sanitize(name)
        self.type = type 
        self.timeout = "3600"
        self.matchAcrossPools = "disabled"
        self.matchAcrossServices = "disabled"
        self.matchAcrossVirtuals = "disabled"
        self.mask = "none"
        self.mirror = "disabled"
        self.hashAlgorithm = "default"
        self.method = "insert"
        self.cookieEncryption = "required"
        self.cookieEncryptionPassphrase = "Avi_Migration_Cookie_Passphrase_FIXME_FIXME_FIXME_FIXME"
        self.encryptCookiePoolname = "enabled"
        self.expiration = "0"
        self.httpOnly = "enabled"
        self.secure = "enabled"

    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, value):
        self._name = f5_sanitize(value)

    @property
    def type(self):
        return self._type
    @type.setter
    def type(self, value):
        _valid_types = [ "cookie", "dest-addr", "source-addr", "hash" ]
        if value in _valid_types:
            self._type = value
        else:
            self._type = "source-addr"

    def __str__(self):
        return f"bigip_persistenceProfile(name={self.name}, type={self.type}"
    def __repr__(self):
        return f"bigip_persistenceProfile(name={self.name}, type={self.type}"
    def tmos_obj(self):
        if self.type == "source-addr" or self.type == "dest-addr":
            return f"""ltm persistence {self.type} /{self.partition}/{self.name} {{
    timeout {self.timeout}
    mask {self.mask}
    hash-algorithm  {self.hashAlgorithm}
    match-across-pools {self.matchAcrossPools}
    match-across-services {self.matchAcrossServices}
    match-across-virtuals {self.matchAcrossVirtuals}
    mirror {self.mirror}
}}"""
        if self.type == "cookie":
            return f"""ltm persistence {self.type} /{self.partition}/{self.name} {{
    defaults-from cookie
    timeout {self.timeout}
    method {self.method}
    cookie-encryption {self.cookieEncryption}
    cookie-encryption-passphrase "{self.cookieEncryptionPassphrase}"
    encrypt-cookie-poolname {self.encryptCookiePoolname}
    expiration {self.expiration}
    httpOnly {self.httpOnly}
    secure {self.secure}
}}"""

class ServerSSLProfile(bigip_obj):
    description = "LTM ServerSSL Profile"

    def __init__(self, name):
        self.name = f5_sanitize(name)
        self.type = "server-ssl"
        self.partition = "Common"
        self.options = [ "dont-insert-empty-fragments", "no-ssl", "no-dtls", "no-tlsv1.3", "no-tlsv1"]
        self.ciphers = [ "DEFAULT" ]
        self.certFileName = ""
        self.certFile = ""
        self.keyFileName = ""
        self.keyFile = ""
        self.chainFileName = ""
        self.chainFile = ""
        self.caFileName = ""
        self.caFile = ""

    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, value):
        self._name = f5_sanitize(value)

    def __str__(self):
        return f"bigip_serverssl(name={self.name}"
    def __repr__(self):
        return f"bigip_serverssl(name={self.name}"
    def tmos_obj(self):
        optionsStr = ""
        certKeyChainStr = ""
        certKeyChainName = re.sub('.crt', '', self.certFileName)
        if certKeyChainName != "":
            certKeyChainStr = f"""    cert-key-chain {{
        {certKeyChainName} {{
            cert {self.certFileName}
            key {self.keyFileName}
            chain {self.chainFileName}
        }}"""
        for option in self.options:
            optionsStr += f"{option} "
        certKeyChainName = re.sub('.crt', '', self.certFileName)
        cipherString = ""
        for i in range(len(self.ciphers)):
            if i == 0:
                cipherString += f"{self.ciphers[i]}"
            else:
                cipherString += f":{self.ciphers[i]}"
        return f"""ltm profile server-ssl /{self.partition}/{self.name} {{
    defaults-from serverssl
    {certKeyChainStr}
    options {{ {optionsStr} }}
    ciphers {cipherString}
}}"""

class ClientSSLProfile(bigip_obj):
    description = "LTM ClientSSL Profile"

    def __init__(self, name):
        self.name = f5_sanitize(name)
        self.type = "client-ssl"
        self.parent = "clientssl"
        self.partition = "Common"
        self.options = [ "dont-insert-empty-fragments", "no-ssl", "no-dtls", "no-tlsv1.3", "no-tlsv1"]
        self.ciphers = [ "DEFAULT" ]
        self.certFileName = "default.crt"
        self.certFile = ""
        self.keyFileName = "default.key"
        self.keyFile = ""
        self.chainFileName = "none"
        self.chainFile = ""
        self.caFileName = ""
        self.caFile = ""
        self.sniDefault = False
        self.sniRequire = False

    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, value):
        self._name = f5_sanitize(value)

    def __str__(self):
        return f"bigip_clientssl(name={self.name}"
    def __repr__(self):
        return f"bigip_clientssl(name={self.name}"
    def tmos_obj(self):
        if len(self.options) > 0:
            optionsStr = "\n options { "
            for option in self.options:
                optionsStr += f"{option} "
            optionsStr += " }"
        else:
            optionsStr = ""
        certKeyChainName = re.sub('.crt', '', self.certFileName)
        if self.chainFileName == "none":
            chainObjName = "none"
        else:
            chainObjName = f"/{self.partition}/{self.chainFileName}"
        if self.certFileName == "default.crt":
            certObjName = "/Common/default.crt"
        else:
            certObjName = f"/{self.partition}/{self.certFileName}"
        if self.keyFileName == "default.key":
            keyObjName = "/Common/default.key"
        else:
            keyObjName = f"/{self.partition}/{self.keyFileName}"
        if len(self.ciphers) > 0:
            cipherString = "\nciphers "
            for i in range(len(self.ciphers)):
                if i == 0:
                    cipherString += f"{self.ciphers[i]}"
                else:
                    cipherString += f":{self.ciphers[i]}"
        else:
            cipherString = ""
        if self.sniDefault:
            sniDefaultStr = "\nsni-default true"
        else:
            sniDefaultStr = ""
        if self.sniRequire:
            sniRequireStr = "\nsni-require true"
        else:
            sniRequireStr = ""
        return f"""ltm profile client-ssl /{self.partition}/{self.name} {{
    defaults-from {self.parent}
    cert-key-chain {{
        {certKeyChainName} {{
            cert {certObjName}
            key {keyObjName}
            chain {chainObjName}
        }}
    }}{cipherString}{optionsStr}{sniDefaultStr}{sniRequireStr}
}}"""

class networkProfile(bigip_obj):
    description = "LTM Network Profile"

    def __init__(self, name, type):
        self.name = f5_sanitize(name)
        self.type = type 
        self.timeout = 300
        self.partition = "Common"
        self.datagramLoadLalancing = "disabled"
        self.snat = "enabled"

    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, value):
        self._name = f5_sanitize(value)

    @property
    def type(self):
        return self._type
    @type.setter
    def type(self, value):
        _valid_types = ["tcp", "udp", "fastl4"]
        if value in _valid_types:
            self._type = value
        else:
            self._type = "tcp"

    @property
    def timeout(self):
        return self._timeout
    @timeout.setter
    def timeout(self, value):
        if value >= 1 and value <= 86400:
            self._timeout = value
        else:
            self._timeout = 300

    def __str__(self):
        return f"bigip_networkProfile(name={self.name}, type={self.type}"
    def __repr__(self):
        return f"bigip_networkProfile(name={self.name}, type={self.type}"
    def tmos_obj(self):
        match self.type:
            case "tcp":
                return f"""ltm profile {self.type} /{self.partition}/{self.name} {{
    defaults-from f5-tcp-progressive
    idle-timeout {str(self.timeout)}
}}"""
            case "udp": 
                return f"""ltm profile {self.type} /{self.partition}/{self.name} {{
    defaults-from udp
    idle-timeout {str(self.timeout)}
    datagram-load-balancing {self.datagramLoadLalancing}
}}"""
            case "fastl4": 
                return f"""ltm profile {self.type} /{self.partition}/{self.name} {{
    defaults-from fastL4
    idle-timeout {str(self.timeout)}
}}"""

class monitor(bigip_obj):
    description = "LTM Monitor"

    def __init__(self, name, type):
        self.name = f5_sanitize(name)
        self.type = type 
        self.interval = "5"
        self.timeout = "15"
        self.send = ""
        self.recv = ""
        self.destination = "*:*"
        self.partition = "Common"
        self.qname = "example.com"
        self.qtype = "a"

    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, value):
        self._name = f5_sanitize(value)

    @property
    def type(self):
        return self._type
    @type.setter
    def type(self, value):
        _valid_types = ["tcp", "http", "https", "udp", "dns"]
        if value in _valid_types:
            self._type = value
        else:
            self._type = "tcp"

    def __str__(self):
        return f"bigip_monitor(name={self.name}, type={self.type}"
    def __repr__(self):
        return f"bigip_monitor(name={self.name}, type={self.type}"
    def tmos_obj(self):
        if self.type == "tcp" or self.type == "udp" or self.type == "http" or self.type == "https":
            return f"""ltm monitor {self.type} /{self.partition}/{self.name} {{
    interval {self.interval}
    timeout {self.timeout}
    send "{self.send}"
    recv "{self.recv}"
    destination {self.destination}
}}"""
        if self.type == "dns":
            return f"""ltm monitor {self.type} /{self.partition}/{self.name} {{
    interval {self.interval}
    timeout {self.timeout}
    destination {self.destination}
    qname {self.qname}
    qtype {self.qtype}
}}"""

class partition(bigip_obj):
    def __init__(self, name):
        self.name = f5_sanitize(name)
        self.description = "BIG-IP Partition"
        self.defaultRouteDomain = 0

    def __str__(self):
        return f"bigip_partition(name='{self.name}', defaultRouteDomain='{self.defaultRouteDomain}')"
    def __repr__(self):
        return f"bigip_partition(name='{self.name}', defaultRouteDomain='{self.defaultRouteDomain}')"

    def tmos_obj(self):
        return f"""auth partition {self.name} {{
    default-route-domain {self.defaultRouteDomain}
    description "{self.description}"
}}"""

class routeDomain(bigip_obj):
    def __init__(self, name, id):
        self.name = f5_sanitize(name)
        self.description = "BIG-IP RouteDomain"
        self.id = id

    def __str__(self):
        return f"bigip_routeDomain(name='{self.name}', id='{self.id}')"
    def __repr__(self):
        return f"bigip_routeDomain(name='{self.name}', id='{self.id}')"

    def tmos_obj(self):
        return f"""net route-domain {self.name} {{
    id {self.id}
    description "{self.description}"
}}"""

class pool_member:
    description = "LTM Pool Member"

    def __init__(self, dest, port ):
        self.name = dest
        self.dest = dest
        self.port = port
        self.enabled = True
        self.ratio = 1
        self.priority = 0
        self.partition = "Common"
        self.routeDomain = 0

    def __str__(self):
        return f"bigip_pool_member(name='{self.name}', dest='{self.dest}', port='{self.port}')"
    def __repr__(self):
        return f"bigip_pool_member(name='{self.name}', dest='{self.dest}', port='{self.port}')"

    def tmos_obj(self):
        if re.match(r'\d+\.\d+\.\d+\.\d+', self.dest):
            return f"""        /{self.partition}/{self.name}%{self.routeDomain}:{self.port} {{
            address {self.dest}%{self.routeDomain}
            ratio {self.ratio}
            priority-group {self.priority}
        }}"""
        else:
            return f"""        /{self.partition}/{self.name}:{self.port} {{
            fqdn {{ name {self.dest} }}
            ratio {self.ratio}
            priority-group {self.priority}
        }}"""


class pool(bigip_obj):
    description = "LTM Pool"

    def __init__(self, name, members):
        self.name = f5_sanitize(name)
        self.members = members 
        self.allowSNAT = "yes"
        self.allowNAT = "yes"
        self.loadBalancingMode = "round-robin"
        self.enabled = "enabled"
        self.serviceDownAction = "none"
        self.routeDomain = "0"
        self.partition = "Common"
        self.monitors = "none"
        self.minActiveMembers = 0

    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, value):
        self._name = f5_sanitize(value)

    @property
    def loadBalancingMode(self):
        return self._loadBalancingMode
    @loadBalancingMode.setter
    def loadBalancingMode(self, value):
        _valid_modes = ["dynamic-ratio-member", "dynamic-ratio-node", "fastest-app-response", "fastest-node", "least-connections-member", "least-connections-node", "least-sessions", "observed-member", "observed-node", "predictive-member", "predictive-node", "ratio-least-connections-member", "ratio-least-connections-node", "ratio-member", "ratio-node", "ratio-session", "round-robin", "weighted-least-connections-member", "weighted-least-connections-node"]
        if value in _valid_modes:
            self._loadBalancingMode = value
        else:
            self._loadBalancingMode= "round-robin"

    def __str__(self):
        memberString = "[ "
        for member in self.members:
            memberString += f"\n\t\t\t{member}"
        memberString += "]"
        return f"bigip_pool(name={self.name}, \n\t\tmembers={memberString}"
    def __repr__(self):
        memberString = "[ "
        for member in self.members:
            memberString += f"\n\t\t\t{member}"
        memberString += "]"
        return f"bigip_pool(name={self.name}, \n\t\tmembers={memberString}"

    def tmos_obj(self):
        members_objs = "\n"
        for member in self.members:
            members_objs += f"{member.tmos_obj()}\n"
        if len(self.members) == 0:
            return f"""ltm pool /{self.partition}/{self.name} {{
    allow-snat {self.allowSNAT}
    allow-nat {self.allowNAT}
    load-balancing-mode {self.loadBalancingMode}
    service-down-action {self.serviceDownAction}
    monitor {self.monitors}
    min-active-members {self.minActiveMembers}
}}"""
        return f"""ltm pool /{self.partition}/{self.name} {{
    allow-snat {self.allowSNAT}
    allow-nat {self.allowNAT}
    load-balancing-mode {self.loadBalancingMode}
    service-down-action {self.serviceDownAction}
    members {{ {members_objs}    }}
    monitor {self.monitors}
    min-active-members {self.minActiveMembers}
}}"""



class virtual(bigip_obj):
    description = "LTM Virtual Server"

    def __init__(self, name, destination, default_pool):
        self.name = f5_sanitize(name)
        self.destination = destination
        self.default_pool = f5_sanitize(default_pool)
        self.rotueDomain = "0"
        self.profilesAll = [ ]
        self.profilesClientSide = [ ]
        self.profilesServerSide = [ ]
        self.persistenceProfile = [ ]
        self.partition = "Common"
        self.mask = "255.255.255.255"
        self.snat = True
        self.snatType = "automap"
        self.snatPoolName = ""
        self.irules = []


    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, value):
        self._name = f5_sanitize(value)

    @property
    def default_pool(self):
        return self._default_pool
    @default_pool.setter
    def default_pool(self, value):
        self._default_pool = f5_sanitize(value)

    def __str__(self):
        return f"bigip_virtual(name={self.name}, default_pool={self.default_pool}"
    def __repr__(self):
        return f"bigip_virtual(name={self.name}, default_pool={self.default_pool}"

    def tmos_obj(self):
        profiles = "\n"
        for profile in self.profilesAll:
            profiles += f"        {profile} {{context all}}\n"
        for profile in self.profilesClientSide:
            profiles += f"        {profile} {{context clientside}}\n"
        for profile in self.profilesServerSide:
            profiles += f"        {profile} {{context serverside}}\n"
        snatConfig = ""
        if self.snat:
            if self.snatType == "automap":
                snatConfig = f"""
    source-address-translation {{
        type automap
    }}"""
        if len(self.irules) == 0:
            rulesStr = "none"
        else:
            rulesStr = "{ "
            for rule in self.irules:
                rulesStr += f"{rule} "
            rulesStr += "}"
        if len(self.persistenceProfile) == 0:
            persistStr = "none"
        else:
            persistStr = "{ "
            for i, persist in enumerate(self.persistenceProfile):
                if i == 0:
                    persistStr += f"{persist} {{ default yes }} "
                else:
                    persistStr += f"{persist} {{ default no }} "
            persistStr += "}"
        return f"""ltm virtual /{self.partition}/{self.name} {{
    destination {self.destination}
    pool {self.default_pool}
    profiles {{ {profiles}    }} {snatConfig}
    rules {rulesStr}
    persist {persistStr}
}}"""