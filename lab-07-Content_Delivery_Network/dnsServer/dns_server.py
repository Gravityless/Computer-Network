'''DNS Server for Content Delivery Network (CDN)
'''
import random
import sys
from ipaddress import IPv4Network
from socketserver import UDPServer, BaseRequestHandler
from utils.dns_utils import DNS_Request, DNS_Rcode
from utils.ip_utils import IP_Utils
from datetime import datetime
from math import radians, cos, sin, asin, sqrt
import math

import re
from collections import namedtuple


__all__ = ["DNSServer", "DNSHandler"]


class DNSServer(UDPServer):
    def __init__(self, server_address, dns_file, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=True)
        self._dns_table = []
        self.parse_dns_file(dns_file)
        
    def parse_dns_file(self, dns_file):
        # ---------------------------------------------------
        # TODO: your codes here. Parse the dns_table.txt file
        # and load the data into self._dns_table.
        # --------------------------------------------------
        with open(dns_file, 'r') as f:
            lines = f.readlines()
        for line in lines:
            domainName = line.strip().split()[0]
            recordType = line.strip().split()[1]
            recordValues = line.strip().split()[2:]
            if domainName[len(domainName) - 1] != '.':
                domainName = domainName + '.'
            record = [domainName, recordType, recordValues]
            self._dns_table.append(record)

    @property
    def table(self):
        return self._dns_table


class DNSHandler(BaseRequestHandler):
    """
    This class receives clients' udp packet with socket handler and request data. 
    ----------------------------------------------------------------------------
    There are several objects you need to mention:
    - udp_data : the payload of udp protocol.
    - socket: connection handler to send or receive message with the client.
    - client_ip: the client's ip (ip source address).
    - client_port: the client's udp port (udp source port).
    - DNS_Request: a dns protocl tool class.
    We have written the skeleton of the dns server, all you need to do is to select
    the best response ip based on user's infomation (i.e., location).

    NOTE: This module is a very simple version of dns server, called global load ba-
          lance dns server. We suppose that this server knows all the ip addresses of 
          cache servers for any given domain_name (or cname).
    """
    
    def __init__(self, request, client_address, server):
        self.table = server.table
        super().__init__(request, client_address, server)

    def match_record(self, record_domain, request_domain):
        record_len = len(record_domain)
        request_len = len(request_domain)
        if request_domain[request_len - 1] != '.':
            request_domain = request_domain + '.'
            request_len += 1
        if record_len > request_len:
            return False
        for i in range(request_len):
            if record_len < i + 1:
                return False
            if request_domain[request_len - 1 - i] == record_domain[record_len - 1 - i]:
                continue
            if record_domain[record_len - 1 - i] == '*':
                break
            else:
                return False

        return True

    def get_best_value(self, client_ip, recordValues):
        random_select = False
        min_distance = -1
        best_server_ip = None

        client_locate = IP_Utils.getIpLocation(client_ip)
        if client_locate is None:
            random_select = True

        if not random_select:
            for ipaddr in recordValues:
                server_locate = IP_Utils.getIpLocation(ipaddr)
                if server_locate is None:
                    random_select = True
                    break
                else:
                    if min_distance < 0 or self.calc_distance(server_locate, client_locate) < min_distance:
                        min_distance = self.calc_distance(server_locate, client_locate)
                        best_server_ip = ipaddr

        if random_select:
           best_server_ip = recordValues[random.randint(0, len(recordValues))]

        return best_server_ip

    def calc_distance(self, pointA, pointB):
        ''' TODO: calculate distance between two points '''
        lat1, lng1 = pointA
        lat2, lng2 = pointB
        # distance = sqrt((lat1 - lat2)**2 + (lng1 - lng2)**2)
        lng1, lat1, lng2, lat2 = map(radians, [float(lng1), float(lat1), float(lng2), float(lat2)])  # 经纬度转换成弧度
        dlon = lng2 - lng1
        dlat = lat2 - lat1
        a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
        distance = 2 * asin(sqrt(a)) * 6371 * 1000  # 地球平均半径，6371km
        distance = round(distance / 1000, 3)
        return distance

    def get_response(self, request_domain_name):
        response_type, response_val = (None, None)
        # ------------------------------------------------
        # TODO: your codes here.
        # Determine an IP to response according to the client's IP address.
        #       set "response_ip" to "the best IP address".
        client_ip, _ = self.client_address
        for line in self.table:
            if self.match_record(line[0], request_domain_name):
                if len(line[2]) == 1:
                    response_type, response_val = (line[1], line[2][0])
                else:
                    response_type, response_val = (line[1], self.get_best_value(client_ip, line[2]))
                break

        # -------------------------------------------------
        return (response_type, response_val)

    def handle(self):
        """
        This function is called once there is a dns request.
        """
        ## init udp data and socket.
        udp_data, socket = self.request

        ## read client-side ip address and udp port.
        client_ip, client_port = self.client_address

        ## check dns format.
        valid = DNS_Request.check_valid_format(udp_data)
        if valid:
            ## decode request into dns object and read domain_name property.
            dns_request = DNS_Request(udp_data)
            request_domain_name = str(dns_request.domain_name)
            self.log_info(f"Receving DNS request from '{client_ip}' asking for "
                          f"'{request_domain_name}'")

            # get caching server address
            response = self.get_response(request_domain_name)

            # response to client with response_ip
            if None not in response:
                dns_response = dns_request.generate_response(response)
            else:
                dns_response = DNS_Request.generate_error_response(
                                             error_code=DNS_Rcode.NXDomain)
        else:
            self.log_error(f"Receiving invalid dns request from "
                           f"'{client_ip}:{client_port}'")
            dns_response = DNS_Request.generate_error_response(
                                         error_code=DNS_Rcode.FormErr)

        socket.sendto(dns_response.raw_data, self.client_address)

    def log_info(self, msg):
        self._logMsg("Info", msg)

    def log_error(self, msg):
        self._logMsg("Error", msg)

    def log_warning(self, msg):
        self._logMsg("Warning", msg)

    def _logMsg(self, info, msg):
        ''' Log an arbitrary message.
        Used by log_info, log_warning, log_error.
        '''
        info = f"[{info}]"
        now = datetime.now().strftime("%Y/%m/%d-%H:%M:%S")
        sys.stdout.write(f"{now}| {info} {msg}\n")
