import re;
from enum import Enum;

def f5_sanitize(name):
    clean_name = name.replace("%20", "_")
    clean_name = clean_name.replace("%2A", "wildcard")
    clean_name = clean_name.replace(" ", "_")
    clean_name = clean_name.replace("-", "_")
    if re.match(r'^[a-zA-Z/]', clean_name):
        return clean_name.lower()
    else:
        return "a_" + clean_name.lower()

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

class ClientSSLProfile:
    description = "LTM ClientSSL Profile"

    def __init__(self, name):
        self.name = f5_sanitize(name)
        self.type = "client-ssl"
        self.partition = "Common"
        self.options = [ "dont-insert-empty-fragments", "no-ssl", "no-dtls", "no-tlsv1.3", "no-tlsv1"]
        self.ciphers = "DEFAULT"
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
        return f"bigip_clientssl(name={self.name}"
    def __repr__(self):
        return f"bigip_clientssl(name={self.name}"
    def tmos_obj(self):
        optionsStr = ""
        for option in self.options:
            optionsStr += f"{option} "
        certKeyChainName = re.sub('.crt', '', self.certFileName)
        return f"""ltm profile client-ssl /{self.partition}/{self.name} {{
    defaults-from clientssl
    cert-key-chain {{
        {certKeyChainName} {{
            cert {self.certFileName}
            key {self.keyFileName}
            chain {self.chainFileName}
        }}
    }}
    ciphers {self.ciphers}
    options {{ {optionsStr} }}
}}"""

class networkProfile:
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
        return f"bigip_monitor(name={self.name}, type={self.type}"
    def __repr__(self):
        return f"bigip_monitor(name={self.name}, type={self.type}"
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

class monitor:
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
    id {self.defaultRouteDomain}
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

    def __str__(self):
        return f"bigip_pool_member(name='{self.name}', dest='{self.dest}', port='{self.port}')"
    def __repr__(self):
        return f"bigip_pool_member(name='{self.name}', dest='{self.dest}', port='{self.port}')"

    def tmos_obj(self):
        if re.match(r'\d+\.\d+\.\d+\.\d+', self.dest):
            return f"""        /Common/{self.name}:{self.port} {{
            address {self.dest}
        }}"""
        else:
            return f"""        /Common/{self.name}:{self.port} {{
            fqdn {{ name {self.dest} }}
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
}}"""
        return f"""ltm pool /{self.partition}/{self.name} {{
    allow-snat {self.allowSNAT}
    allow-nat {self.allowNAT}
    load-balancing-mode {self.loadBalancingMode}
    service-down-action {self.serviceDownAction}
    members {{ {members_objs}    }}
    monitor {self.monitors}
}}"""



class virtual(bigip_obj):
    description = "LTM Virtual Server"

    def __init__(self, name, destination, default_pool):
        self.name = f5_sanitize(name)
        self.destination = destination
        self.default_pool = f5_sanitize(default_pool)
        self.rotueDomain = "0"
        self.profilesAll = ["/Common/f5-tcp-progressive"]
        self.profilesClientSide = [ ]
        self.profilesServerSide = [ ]
        self.partition = "Common"
        self.mask = "255.255.255.255"

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
        return f"""ltm virtual /{self.partition}/{self.name} {{
    destination {self.destination}
    pool {self.default_pool}
    profiles {{ {profiles}    }}
}}"""