import logging
import os
import pickle
import re
import socket
import time

from parse_utils import Parser
from utils import Utils

logging.basicConfig(level=logging.INFO)


def get_an_iterative_approach(domain_name):
    next_servers = Utils.get_root_servers()
    dns_query = Utils.make_question_for_dns(domain_name, "A")

    if not os.path.exists("simple_cache.pkl"):
        f = open("simple_cache.pkl", "wb")
        f.close()

    result = []

    for _ in range(13):
        for server in next_servers:
            cached = False
            try:
                if os.path.getsize("simple_cache.pkl") > 0:
                    with open("simple_cache.pkl", "rb") as f:
                        cache = pickle.load(f)

                        if server in cache.keys() and domain_name in cache[server].keys():
                            if time.time() - cache[server][domain_name][1] < cache[server][domain_name][2]:
                                res = []
                                ipv4 = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
                                for ans in cache[server][domain_name][0]:
                                    if ans[2] != b'':
                                        if ipv4.match(ans[2]):
                                            res.append(ans[2])
                                return res
                            else:
                                logging.warning(f"The time limit was exceeded by {server}")
                                del cache[server][domain_name]
                                with open("simple_cache.pkl", "wb") as file:
                                    pickle.dump(cache, file)
                if not cached:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.settimeout(2.0)
                        sock.sendto(dns_query, (server, 53))
                        response, _ = sock.recvfrom(512)
                        answers, authority, additional = Parser.response_parse(response, server, domain_name)

                        for answer in answers:
                            if answer[1] == 1 or answer[1] == 28:
                                result.append(answer[2])

                        if result:
                            return result
                        next_servers = []
                        for record in authority:
                            if record[1] == 2:
                                ns_name = record[2]
                                ip_for_ns = None

                                for add_record in additional:
                                    if add_record[1] == 1 and add_record[0] == ns_name:
                                        ip_for_ns = add_record[2]

                                if ip_for_ns:
                                    next_servers.append(ip_for_ns)
                                else:
                                    ip_for_ns = get_an_iterative_approach(ns_name)
                                    if ip_for_ns:
                                        next_servers.extend(ip_for_ns)

                        if not next_servers:
                            return "SOA"
            except Exception as e:
                logging.warning(e)
                continue

    return result if result else "SOA"


def run_dns_server(host='127.0.0.1', port=53):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((host, port))
        logging.info(f"Server listening on {host}:{port}")
        while True:
            data, client_address = s.recvfrom(512)
            decoded_data = Parser.read_name(data, 12)[0]
            if decoded_data == "1.0.0.127.in-addr.arpa":
                continue

            answers = get_an_iterative_approach(decoded_data)

            if answers == "SOA":
                soa_response = Utils.encode_soa_record(data)
                s.sendto(soa_response, client_address)
            else:
                s.sendto(Utils.encode_dns_name(data, answers), client_address)


if __name__ == "__main__":
    run_dns_server()
