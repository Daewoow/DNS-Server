from parse_utils import Parser
from type_to_constant import dict_of_records

import os
import pickle
import random
import struct
import socket
import time


class Utils:
    @staticmethod
    def encode_soa_record(request_data):
        transaction_id = request_data[:2]

        header = (
                transaction_id +
                b'\x81\x83' +
                b'\x00\x01' +
                b'\x00\x00' +
                b'\x00\x01' +
                b'\x00\x00'
        )
        question_name, question_type_offset = Parser.read_name(request_data, 12)
        question_section = request_data[12:question_type_offset + 4]

        soa_name = b'\x03ns1\x06domain\x03com\x00'

        soa_record = (
                soa_name +
                b'\x00\x06' +
                b'\x00\x01' +
                b'\x00\x00\x00\x1E' +
                b'\x00\x1C' +
                b'\x03ns1\x06domain\x03com\x00' +
                b'\x06domain\x03com\x00' +
                struct.pack(">I", 2023112400) +
                struct.pack(">I", 3600) +
                struct.pack(">I", 600) +
                struct.pack(">I", 86400) +
                struct.pack(">I", 3600)
        )

        response = header + question_section + soa_record
        return response

    @staticmethod
    def encode_dns_name(data, answers):
        flags = b'\x81\x80'
        qdcount = b'\x00\x01'
        question_rd = data[:2]
        ancount = struct.pack('!H', len(answers))
        nscount = b'\x00\x00'
        arcount = b'\x00\x00'

        question = data[12:]

        response = question_rd + flags + qdcount + ancount + nscount + arcount + question

        for answer in answers:
            name = b'\xc0\x0c'
            this_type = b'\x00\x01'
            where = b'\x00\x01'
            ttl = struct.pack('!I', 60)
            rdlength = b'\x00\x04'
            rdata = socket.inet_aton(answer)

            response += name + this_type + where + ttl + rdlength + rdata

        return response

    @staticmethod
    def get_root_servers():
        return ["198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",  "192.203.230.10", "192.5.5.241",
                "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
                "202.12.27.33"]

    @staticmethod
    def make_question_for_dns(domain_name, r_type):
        transaction_id = random.randint(0, 65535)
        flags = 0x0100
        qdcount = 1
        ancount = nscount = arcount = 0

        header = struct.pack('>HHHHHH', transaction_id, flags, qdcount, ancount, nscount, arcount)

        query = b''
        for part in domain_name.split('.'):
            query += struct.pack('B', len(part)) + part.encode('utf-8')
        query += b'\x00'
        question = struct.pack('>HH', dict_of_records[r_type], 1)

        dns_query = header + query + question
        return dns_query

    @staticmethod
    def parse_dns_records(response, current_server, domain_name) -> dict:
        records = {
            "Answer": [],
            "Authority": [],
            "Additional": []
        }

        unpacked = struct.unpack('>HHHHHH', response[:12])

        qdcount, ancount, nscount, arcount = (
            unpacked[2],
            unpacked[3],
            unpacked[4],
            unpacked[5]
        )

        records, ttl = Parser.fill_records(records, response, qdcount, ancount, nscount, arcount)
        Utils.fill_in_cache(current_server, ttl, records, domain_name)

        return records

    @staticmethod
    def fill_in_cache(current_server, ttl, records, domain_name):
        if os.path.getsize("simple_cache.pkl") > 0:
            with open("simple_cache.pkl", "rb") as f:
                data = pickle.load(f)
                data[current_server] = {domain_name: (records, time.time(), ttl)}
                with open("simple_cache.pkl", "wb") as file:
                    pickle.dump(data, file)
        else:
            with open("simple_cache.pkl", "wb") as file:
                pickle.dump({
                    current_server: {
                        domain_name: (records, time.time(), ttl)
                    }
                }, file)
