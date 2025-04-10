import socket
import random
import warnings
import os
from datetime import datetime
from configs import CFG, Config
config = Config.from_json(CFG)

# global variables
used_ports = []

def set_socket(port: int) -> socket.socket:
    '''
    This function creates a new UDP socket

    :param port: port number
    :return: A socket object with an unused port number
    '''
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((config.constants.TRACKER_ADDR[1], port))
    used_ports.append(port)

    return sock

def generate_random_port() -> int:
    '''
    This function generates a new(unused) random port number

    :return: a random integer in range of [1, 65535]
    '''
    available_ports = config.constants.AVAILABLE_PORTS_RANGE
    rand_port = random.randint(available_ports[0], available_ports[1])
    while rand_port in used_ports:
        rand_port = random.randint(available_ports[0], available_ports[1])
    used_ports.append(rand_port)
    return rand_port

