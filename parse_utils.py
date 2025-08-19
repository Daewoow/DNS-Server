import os
import pickle
import re
import time
import struct


class Parser:
    @staticmethod
    def get_domains():
        return ["com", "net", "org", "ru"]

    @staticmethod
    def records_to_dict(response, offset):
        name, offset = Parser.read_name(response, offset)
        if response[offset:offset + 2].decode() in Parser.get_domains():
            offset += 3

        rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', response[offset:offset + 10])
        offset += 10

        rdata = response[offset:offset + rdlength]
        offset += rdlength

        if rtype == 1:
            ip_address = '.'.join(map(str, rdata))
            rdata = {"IP Address": ip_address}
        elif rtype == 28:
            ipv6_address = ':'.join(f"{rdata[i]:02x}{rdata[i + 1]:02x}" for i in range(0, len(rdata), 2))
            rdata = {"IPv6 Address": ipv6_address}
        elif rtype == 5:
            cname, _ = Parser.read_name(response, offset - rdlength)
            rdata = {"CNAME": cname}
        elif rtype == 15:
            preference = struct.unpack('>H', rdata[:2])[0]
            exchange, _ = Parser.read_name(response, offset - rdlength + 2)
            rdata = {"Preference": preference, "Exchange": exchange}
        elif rtype == 2:
            ns, _ = Parser.read_name(response, offset - rdlength)
            rdata = {"NS": ns}
        elif rtype == 16:
            txt_length = rdata[0]
            txt_data = rdata[1:1 + txt_length].decode()
            rdata = {"TXT": txt_data}
        elif rtype == 12:
            ptr, _ = Parser.read_name(response, offset - rdlength)
            rdata = {"PTR": ptr}
        elif rtype == 6:
            mname, offset_mname = Parser.read_name(response, offset - rdlength)
            rname, offset_rname = Parser.read_name(response, offset_mname)
            serial, refresh, retry, expire, minimum = struct.unpack('>IIIII', response[offset_rname:offset_rname + 20])
            rdata = {
                "MName": mname,
                "RName": rname,
                "Serial": serial,
                "Refresh": refresh,
                "Retry": retry,
                "Expire": expire,
                "Minimum": minimum
            }
        elif rtype == 33:
            priority, weight, port = struct.unpack('>HHH', rdata[:6])
            target, _ = Parser.read_name(response, offset - rdlength + 6)
            rdata = {"Priority": priority, "Weight": weight, "Port": port, "Target": target}
        else:
            rdata = {"Data": rdata}

        return name, rtype, rclass, ttl, rdata, offset

    @staticmethod
    def fill_records(records, response, qdcount, ancount, nscount, arcount):
        offset = 12
        current_ttl = 0

        for _ in range(qdcount):
            while response[offset] != 0:
                offset += response[offset] + 1
            offset += 5

        for _ in range(ancount):
            name, rtype, rclass, ttl, rdata, offset = Parser.records_to_dict(response, offset)
            records["Answer"].append({"Name": name, "Data": rdata})

        for _ in range(nscount):
            name, rtype, rclass, ttl, rdata, offset = Parser.records_to_dict(response, offset)
            records["Authority"].append({"Name": name, "Data": rdata})

        for _ in range(arcount):
            name, rtype, rclass, ttl, rdata, offset = Parser.records_to_dict(response, offset)
            current_ttl = ttl
            records["Additional"].append({"Name": name, "Data": rdata})

        return records, current_ttl

    @staticmethod
    def parse_answers(answers):
        result = []
        for section in answers.keys():
            for answer in answers[section]:
                if "IP Address" in answer["Data"]:
                    if re.match("[0-9a-z]+:[0-9a-z]+:*[0-9a-z]*::[0-9a-z]+", answer["Data"]["IP Address"]):
                        result.append(("AAAA", answer["Data"]["IP Address"]))
                    else:
                        result.append(("A", answer["Data"]["IP Address"]))
                if "NS" in answer["Data"]:
                    result.append(("NS", answer["Data"]["NS"]))
                if "CNAME" in answer["Data"]:
                    result.append(("CNAME", answer["Data"]["CNAME"]))

        return result

    @staticmethod
    def read_name(response, offset):
        labels = []
        while True:
            length = response[offset]
            if (length & 0xC0) == 0xC0:
                pointer = struct.unpack('>H', response[offset:offset + 2])[0] & 0x3FFF
                offset += 2
                labels.append(Parser.read_name(response, pointer)[0])
                break
            elif length == 0:
                offset += 1
                break
            else:
                offset += 1
                labels.append(response[offset:offset + length].decode())
                if response[offset:offset + length].decode() in Parser.get_domains():
                    break
                offset += length

        return '.'.join(labels), offset

    @staticmethod
    def response_parse(response, current_server, domain_name):
        header = struct.unpack(">HHHHHH", response[:12])
        answer_rrs = header[3]
        authority_rrs = header[4]
        additional_rrs = header[5]

        offset = 12
        while response[offset] != 0:
            offset += 1
        offset += 5

        answers, offset, ttl = Parser.parse_records(response, answer_rrs, offset)
        authority, offset, _ = Parser.parse_records(response, authority_rrs, offset)
        additional, offset, _ = Parser.parse_records(response, additional_rrs, offset)

        records = answers + authority + additional

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

        return answers, authority, additional

    @staticmethod
    def parse_records(response, count, offset):
        records = []
        ttl = 0
        for _ in range(count):
            name, offset = Parser.read_name(response, offset)
            if response[offset:offset + 2].decode() in Parser.get_domains():
                offset += 3
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", response[offset:offset + 10])
            offset += 10
            rdata = response[offset:offset + rdlength]
            offset += rdlength

            if rtype == 1:
                ip = ".".join(map(str, rdata))
                records.append((name, rtype, ip))
            elif rtype == 2:
                ns_name, _ = Parser.read_name(response, offset - rdlength)
                records.append((name, rtype, ns_name))
            elif rtype == 5:
                cname, _ = Parser.read_name(response, offset - rdlength)
                records.append((name, rtype, cname))
            elif rtype == 28:
                ipv6 = ":".join(f"{rdata[i]:02x}{rdata[i + 1]:02x}" for i in range(0, rdlength, 2))
                records.append((name, rtype, ipv6))
            else:
                records.append((name, rtype, rdata))

        return records, offset, ttl
