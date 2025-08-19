import logging
import socket


logging.basicConfig(format='%(asctime)s \n%(message)s', level=logging.INFO)


def run_client():
    while True:
        print("Write your question at format: dig DOMAIN.NAME @local_server")
        print("Write END to close connection")
        server_address = ('127.0.0.7', 53)
        try:
            input_question = input()
            input_question_splited = input_question.split()

            if input_question == "END":
                break

            if (len(input_question_splited)
                    != 3 or input_question_splited[0] != "dig" or '.' not in input_question_splited[1]):
                raise IndexError

            logging.info("Sending DNS-query...")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(input_question.encode(), server_address)
                response, _ = sock.recvfrom(512)
            print(response.decode())
        except IndexError:
            logging.error("Incorrect format of question")
            continue


if __name__ == "__main__":
    run_client()


# ['77.88.55.242', '5.255.255.242', '77.88.44.242']