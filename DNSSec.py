#Query domain using parent IP for DS records
    #- Get back IP of it's NS and DS Hash Key
#Query domain with it's IP for DNSKey records
    #- Get DNSKeys (RRset) , SHA, RRsig
    #- Validate
       #- Validation of DS record with hash of KSK
       #- Validation of RRSig of RRset

import sys
import dns.message
import dns.query
import dns.rdatatype
import dns.dnssec
import validators.domain
from mydig import dnsResolver
from datetime import datetime
from time import time

#Get root servers
def getRootServers(cfg_file):
    servers = []
    with open(cfg_file) as f:
        for line in f:
            root_server_name, root_server_ip = line.strip().split(":")
            servers.append(root_server_ip)
    return servers

#Get the DS record
def parseforDSRecord(tcp_response):
    ds_records = []
    #if len(tcp_response.authority) > 0:
    for auth in tcp_response.authority:
        if auth.rdtype == dns.rdatatype.DS:
            ds_records.append(auth[0])
                #return auth[0]
    return ds_records
    #return None

#Get Hash function
def getHashFunction(ds_record):
    if ds_record is None:
        return None
    hash_fn = []
    for record in ds_record:
        if record.digest_type == 2:
            hash_fn.append("SHA256")
        elif record.digest_type == 1:
            hash_fn.append("SHA1")
    return hash_fn

#Get IP from additional section
def parseAdditionalSection(tcp_response):
    servers = []
    if len(tcp_response.additional) > 0:
        for add_server in tcp_response.additional:
            servers.append(add_server.to_text().split(" ")[-1])
        return servers
    return None

#get the DS Record and Hash function
def getDSRecord(tcp_response):
    ds_record, hash_fn = None, None
    if len(tcp_response.authority) > 0:
        ds_record = parseforDSRecord(tcp_response)
        hash_fn = getHashFunction(ds_record)
    return ds_record, hash_fn

#Get TCP response and validate it
def getResponse(domain,servers):
    for server in servers:
        try:
            query = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
            response = dns.query.tcp(query, server, timeout=5)
            if response is None:
                continue
            elif response.rcode() != 0:
                continue
            else:
                ds_record, hash_fn = getDSRecord(response)
                if (ds_record is not None and hash_fn is not None) or (len(ds_record) > 0 and len(hash_fn) > 0):
                    return ds_record, hash_fn, response
        except dns.exception.Timeout:
            continue
    return None,None,None

#Get Next level servers
def getNextDNSServer(tcp_response,servers):
    next_level_dns_servers = []
    if len(tcp_response.answer) > 0:
        next_level_dns_servers = servers
    elif len(tcp_response.additional) > 0:
        for add_server in tcp_response.additional:
            if add_server.rdtype == dns.rdatatype.AAAA:
                continue
            else:
                next_level_dns_servers.append(add_server.to_text().split(" ")[-1])
    else:
        if tcp_response.authority[0].rdtype == dns.rdatatype.SOA:
            return servers
        elif tcp_response.authority[0].rdtype == dns.rdatatype.NS:
            dns_resolve = dnsResolver(tcp_response.authority[0][0].to_text()[:-1],"A")
            x = dns_resolve.resolveDomainHeirarchy()
            next_level_dns_servers = x

    return next_level_dns_servers

#Getting RRSig and KSK
def getRRsig(domain,next_level_servers):
    if next_level_servers is not None:
        for server in next_level_servers:
            ksk = None
            signature_of_rr = None
            set_rr = None
            query = dns.message.make_query(domain,dns.rdatatype.DNSKEY,want_dnssec=True)
            response = dns.query.tcp(query,server)
            if response is not None:
                if len(response.answer) > 0:
                    for ans in response.answer:
                        if ans.rdtype == dns.rdatatype.RRSIG:
                            signature_of_rr = ans
                        elif ans.rdtype == dns.rdatatype.DNSKEY:
                            for key in ans:
                                if key.flags != 256:
                                    ksk = key
                                    set_rr = ans

            if ksk is not None and set_rr is not None and signature_of_rr is not None:
                return ksk, signature_of_rr, set_rr
    return None,None,None

#Validation 2 times
def validate(hash_ksk, signature_rr, rrset, ds_record, sub_domain):
    flag = 0
    #Validate KSK hash against DS hash
    for record in [ds_record]:
        if record != hash_ksk:
            continue
        else:
            flag = 1
            break

    if flag == 0:
        return False

    domain_rrset = {}
    domain_rrset[sub_domain] = rrset
    #Validate the RRSet of DNSKEY
    try:
        dns.dnssec.validate(rrset, signature_rr,domain_rrset)
        flag = 1
    except Exception as e:
        flag = 0

    if flag == 1:
        return True
    return False

#Main resolution function
def resolveHeirarchy(domain):
    servers = getRootServers(cfg_file)

    if domain in hot_list and domain not in cold_list:
        domain = "www." + domain

    domain_heirarchy = domain.strip().split(".")

    sub_domain = domain_heirarchy[-1] + "."
    ds_record, hash_fn, response = getResponse(sub_domain, servers)
    if response is not None:
        servers = getNextDNSServer(response, servers)
    else:
        return None

    for i in range(len(domain_heirarchy)-2,-1,-1):
        ksk, signature_rr, rrset = getRRsig(sub_domain,servers)
        if ksk is None:
            return None
        if hash_fn is None:
            return None
        if rrset is None:
            return None
        if signature_rr is None:
            return None
        flag = 0
        for j in range(len(hash_fn)):
            hash_ksk = dns.dnssec.make_ds(sub_domain,ksk,hash_fn[j])
            if ds_record is None or len(ds_record) == 0:
                print("DNS not supported")
                return None
            if validate(hash_ksk,signature_rr,rrset,ds_record[j],dns.name.from_text(sub_domain)) is True:
                flag = 1
                break
        if flag == 0:
            print("DNS Verification Failed")
            return None
        sub_domain = domain_heirarchy[i] + "." + sub_domain
        ds_record, hash_fn, response = getResponse(sub_domain, servers)
        if response is None or hash_fn is None or ds_record is None or len(ds_record) == 0 or len(hash_fn) == 0:
            print("DNS not supported")
            return None
        servers = getNextDNSServer(response, servers)
    return servers


#check domain
def checkDomain(domain):
    if validators.domain(domain):
        return True
    else:
        print("ERROR: Domain %s not valid" % (domain))
        return False

domain_name = None
if len(sys.argv) != 2:
    print("ERROR: Invalid arguments!!")
    exit(-1)

#Program starts from here
domain_name = sys.argv[1]
if not checkDomain(domain_name):
    exit(-1)

cfg_file = "RootServer.cfg"
servers = getRootServers(cfg_file)
start_time = time()
hot_list = "dnssec-failed.org"
cold_list = "www"
nameservers = resolveHeirarchy(domain_name)
end_time = time()

#Print Output
if nameservers is not None:
    r = None
    for i in range(len(nameservers)):
        q = dns.message.make_query(domain_name, dns.rdatatype.from_text("A"))
        r = dns.query.tcp(q, nameservers[i])
        if r is None:
            continue
        else:
            break

    if r is None:
        exit(-1)

    output = "QUESTION SECTION:\n" + str(domain_name) + "\n\n\nANSWER SECTION:\n"
    for ans in r.answer:
        output += ans.to_text()

    output += "\nQuery Time: " + str(end_time - start_time) + " sec\n"
    currentDT = datetime.now()
    output += currentDT.strftime("%a %b %d %H:%M:%S %Y\n")
    output += "MSG SIZE rcvd: " + str(sys.getsizeof(r))
    print(output)




