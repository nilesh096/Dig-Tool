#!/usr/bin/env python
import dns.rdatatype
import dns.query
import dns.name
import dns.rcode
from time import time
import validators.domain
from datetime import datetime
from ipaddress import ip_address, IPv4Address
import sys


class dnsResolver:
    def __init__(self, domain_name = None, record_type = None):
        self.domain_name = domain_name
        self.record_type = record_type
        self.answer = None
        self.servers = []
        self.is_soa = False
        self.ans = False
        self.prev_sub_domain = ""
        self.is_cname = False
        self.is_ns = False
        self.cfg_file = "RootServer.cfg"

    #Get list of root servers
    def getRootServers(self, cfg_file = None):
        servers = []
        with open(self.cfg_file) as f:
            for line in f:
                root_server_name, root_server_ip = line.strip().split(":")
                servers.append(root_server_ip)
        return servers

    #Get Response
    def getResponse(self, domain):
        if self.servers is None:
            return None
        for server in self.servers:
            try:
                if type(ip_address(server)) != IPv4Address:
                    continue
                query = dns.message.make_query(domain, self.record_type)
                #print("Using server %s" %(server))
                #print(server,domain)
                udp_response = dns.query.udp(query, server, ignore_trailing=True, timeout=1)
                is_valid = self.IsValid(udp_response, udp_response.rcode(), domain)
                #print("Server used is %s" % server)
                if is_valid in [-2, -3, -4]:
                    #print("ERROR:Got error")
                    continue
                elif is_valid == -1:
                    #print("ERROR: Domain %s is not valid" % domain)
                    return None
                else:
                    return udp_response
            except dns.exception.Timeout:
                continue
        return None

    #Validate response
    def IsValid(self, udp_response, response_code, domain):
        if response_code != 0:
            if response_code == dns.rcode.NXDOMAIN:
                #print("ERROR: Domain %s doesn't exist" % (domain))
                return -1
            elif response_code == dns.rcode.SERVFAIL:
                #print("ERROR: Server failed to complete the request, trying another server if any")
                return -2
            elif response_code == dns.rcode.REFUSED:
                #print("ERROR: Server refused, trying another server if any")
                return -3
            return -4
        return 1

    def resolveDomainHeirarchy(self, domain_name = None):
        if domain_name is None:
            domain_name = self.domain_name

        self.servers = self.getRootServers()

        heirarchy = domain_name.strip().split(".")

        domain = ""
        is_error = False

        i = len(heirarchy)-1

        while i >= 0:
            domain = heirarchy[i] + "." + domain
            if heirarchy[i] == "www":
                i -= 1
                continue
            self.prev_sub_domain = domain
            response = self.getResponse(domain)
            if response is None:
                is_error = True
                break
            else:
                self.servers = self.getNextLevelDNSServer(response)
            i -= 1

        if is_error:
           return None

        response = self.getResponse(domain)
        if (self.is_soa or self.is_ns) and response == None:
            return self.servers
        elif response == None:
            return None
        else:
            return self.getNextLevelDNSServer(response)

    #Get authority namseserver IPs
    def getAuthorityServerIPs(self, additional):
        servers = []
        for add_server in additional:
            servers.append(add_server.to_text().split(" ")[-1])
        return servers

    #Get Next level server
    def getNextLevelDNSServer(self, udp_response):
        if len(udp_response.answer) > 0:
            if self.is_cname is False:
                self.answer = udp_response
            return [udp_response.answer[0].to_text().split(" ")[-1]]
        elif len(udp_response.additional) > 0:
            return self.getAuthorityServerIPs(udp_response.additional)
        elif len(udp_response.authority) > 0:
            if udp_response.authority[0].rdtype == dns.rdatatype.SOA:
                self.is_soa = True
                return self.servers
            elif udp_response.authority[0].rdtype == dns.rdatatype.NS:
                self.is_ns = True
                nameserver = udp_response.authority[0][0].to_text()[:-1]
                #prev_sub_domain = self.prev_sub_domain
                self.servers = self.resolveDomainHeirarchy(nameserver)
                return self.servers

    #Generate Output
    def generateOutput(self,total_time):
        if self.answer is None:
            output = "QUESTION SECTION:\n" + self.domain_name + " IN " + dns.rdatatype.to_text(self.record_type) + "\n\n"
            output += "\n" + "Query Time: " + str(total_time) + " sec\n"
            print(output)
            exit(-1)

        question = "QUESTION SECTION:\n" + self.answer.question[0].to_text() + "\n\n"
        answer = "ANSWER SECTION:\n"
        output = question + answer

        for ans in self.answer.answer:
            if ans.rdtype == dns.rdatatype.CNAME:
                self.is_cname = True
                cname = ans.to_text().split(" ")[-1][:-1]
                servers = self.resolveDomainHeirarchy(cname)
                #output += str(servers)
            output += ans.to_text() + "\n"
        output += "\n" + "Query Time: " + str(total_time) + " sec\n"
        output += datetime.now().strftime("%a %b %d %H:%M:%S %Y\n")
        output += "MSG SIZE rcvd: " + str(sys.getsizeof(self.answer))
        return output
        #print(output)

    #Validate domain
    def checkDomain(self):
        if validators.domain(self.domain_name):
            pass
        else:
            print("ERROR: Domain %s not valid" % (domain_name))
            exit(-1)

    #Validate record type
    def checkRecordType(self):
        try:
            if self.record_type not in ["A","NS","MX"]:
                print("ERROR: Invalid Record type")
                exit(-1)
            self.record_type = dns.rdatatype.from_text(self.record_type)
            #print(self.record_type)
        except Exception as e:
            print("ERROR: Invalid Record type")
            exit(-1)

#Main function
if __name__ == '__main__':
    record_type = None
    domain_name = None

    if len(sys.argv) != 3:
        print("ERROR: Invalid arguments!!")
        exit(-1)


    domain_name, record_type = sys.argv[1], sys.argv[2]
    resolver = dnsResolver(domain_name, record_type)
    cfg_file = "RootServer.cfg"

    resolver.checkDomain()
    resolver.checkRecordType()

    start_time = time()
    ans = resolver.resolveDomainHeirarchy()
    total_time = time() - start_time
    print(resolver.generateOutput(total_time))


