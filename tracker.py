import socket
from threading import Thread
from datetime import datetime
import time
import threading
import bencodepy
import hashlib
import json
import os
from configs import CFG, Config
config = Config.from_json(CFG)
from utils import *

class Tracker:
    def __init__(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 1))
        self.host = s.getsockname()[0]
        self.port = 22236
        self.announce_url = f"http://{self.host}:22236/announce"
        self.peers = {}  # {"filename": [(peer_ip, peer_port)]}
        self.history = []  # List of past commands for 'show history'
        self.metainfo_dir = "metainfo"  # Directory to store .torrent files
        if not os.path.exists(self.metainfo_dir):
            os.makedirs(self.metainfo_dir)

    # listening to clients------------------------------------------------------------
    def handle_client(self, conn, addr):
        peer_host = conn.recv(config.constants.BUFFER_SIZE).decode()
        peer_port = conn.recv(config.constants.BUFFER_SIZE).decode()
        time.sleep(1)
        print(f"Connected with peer: {peer_host} : {peer_port}")
        while True:
            try:
                data = conn.recv(config.constants.BUFFER_SIZE).decode()
                time.sleep(0.1)
                self.history.append(data)
                data_list = data.split(" ")
                # print(f"this is the decoded data: {data}") # for debug purposes
                command = data_list[0]
                if command == "send":
                    filename = data_list[1]
                    conn.send("Enter send mode.\n".encode())

                    data_from_announce = conn.recv(config.constants.BUFFER_SIZE).decode()
                    message = json.loads(data_from_announce)

                    info_hash = message.get("info_hash")
                    peer_info = {
                        "ip": message.get("ip"),
                        "port": message.get("port"),
                        "peer_id": message.get("peer_id")
                    }

                    if info_hash:
                        if info_hash not in self.peers:
                            self.peers[info_hash] = []

                        # Avoid duplicates
                        if peer_info not in self.peers[info_hash]:
                            self.peers[info_hash].append(peer_info)
                            print(f"[TRACKER] Registered peer: {peer_info} for hash: {info_hash}")

                        # Send back the list of known peers for that file
                        conn.send(json.dumps(self.peers[info_hash]).encode())
                    else:
                        print("invalid file recieved")
                        conn.send("Invalid file.\n".encode())

                elif command == "download":
                    try:
                        filename = data_list[1]
                        info_hash = data_list[2]
                        info_hash = info_hash.strip()
                        #print(data_from_announce)
                        #conn.send("Enter download mode \n".encode())
                        #data_from_announce = conn.recv(config.constants.BUFFER_SIZE).decode()
                        print(f"this is the data from announce: {info_hash}")
                        #info_hash = json.loads(data_from_announce)
                        #print(f"info_hash: {info_hash}")
                        peer_list = self.peers.get(info_hash, [])
                        
                        print(f"[Tracker] Peers list cho {info_hash}: {peer_list}")
                        conn.send(json.dumps(peer_list).encode())
                    except Exception as e:
                        print(f"[Peer] Failed to getting peers list from tracker: {e}")

                elif command == "exit":
                    break

                else:
                    conn.send("Invalid commands.\n".encode())
            except Exception as e:
                print(f"Error handling client {addr}: {e}")
                break
    # ===============================end======================================

    @staticmethod
    def lishis(self):
        time.sleep(1)
        print("Welcome to the Tracker.\n")
        print("------List of commands-----\n")
        print("show_peer: Show peers connected to the tracker.\n")
        print("show_history: Show history of activities in the tracker.\n")
        while True:
            command = input("Enter command:")
            if command == "show_peer":
                response = json.dumps(self.peers, indent=2)
                print(response)
            elif command == "show_history":
                response = json.dumps(self.history, indent=2)
                print(response)
            elif command == "exit":
                print("You have exited the tracker.")
                print("Exiting...")
                exit(0)
            else:
                print("Invalid Command")

    def run_tracker(self):
        # tracker server----------------------------------------------
        server_socket = set_socket(self.port)
        server_socket.listen(10)
        print(f"Tracker running on {self.host}:{self.port}")
        # =================================================================

        while True:
            con, addr = server_socket.accept()
            print(f"New connection from {addr}")
            t = Thread(target=self.handle_client, args=(con, addr))
            t.start()

if __name__ == "__main__":
    tracker = Tracker()

    th = Thread(target=tracker.run_tracker,args=[] , daemon=True)
    th.start()

    tracker.lishis(tracker)


