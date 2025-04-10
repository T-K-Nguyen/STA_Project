from utils import *
import socket
import random
from threading import Thread
import time
import os
import json
import bencodepy
import hashlib
import uuid
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from configs import CFG, Config, get_host_default_interface_ip
config = Config.from_json(CFG)

PIECE_SIZE = config.constants.CHUNK_PIECES_SIZE  # 512KB per piece

#flag = 0


class Peer:
    def __init__(self, host, port, tracker_host, tracker_post):
        self.host = host
        self.port = port
        self.peer_id = f"{host}:{port}"  # Unique identifier for the peer
        self.tracker_host = tracker_host
        self.tracker_port = tracker_post
        self.peers = []  # List of peers for downloading
        self.listen_port = []
        self.flag = 0
        self.running = True
        self.threads = []
#----------------------------------FOLDER & METAINFO (.TORRENT)-----------------------
    def create_torrent_file(self, file_path, piece_length=1024, torrent_path=None):
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        num_pieces = (file_size + piece_length - 1) // piece_length
        pieces = []

        with open(file_path, 'rb') as f:
            for _ in range(num_pieces):
                chunk = f.read(piece_length)
                sha1 = hashlib.sha1(chunk).hexdigest()
                pieces.append(sha1)

        torrent_info = {
            "file_name": file_name,
            "file_size": file_size,
            "piece_length": piece_length,
            "pieces": pieces
        }

        # Save to .torrent file
        if not torrent_path:
            torrent_path = f"metainfo/{file_name}.torrent"
        
        with open(torrent_path, 'w') as tf:
            json.dump(torrent_info, tf, indent=2)

        # Generate info hash (used for tracker + peer ID)
        info_hash = hashlib.sha1(json.dumps(torrent_info, sort_keys=True).encode()).hexdigest()

        return torrent_info, info_hash

    def get_info_hash(self, torrent_file_path):
        with open(torrent_file_path, "r") as f:
            torrent_data = json.load(f)

        encoded = json.dumps(torrent_data, sort_keys=True).encode()
        return hashlib.sha1(encoded).hexdigest()

    def parse_torrent_file(self, torrent_path):
        with open(torrent_path, 'r') as f:
            torrent_info = json.load(f)
        return torrent_info

    #==================================================================================





    # -------------------------------send mode----------------------------
    def handle_client(self, conn, addr, file_path):
        try:
            print(f"[SEND] Connection from {addr}")

            # Receive requested offset and length
            data = conn.recv(1024).decode()
            if not data:
                return
            start, size = map(int, data.strip().split(','))

            with open(file_path, 'rb') as f:
                f.seek(start)
                chunk = f.read(size)

            conn.sendall(chunk)
            print(f"[SEND] Sent bytes {start} to {start + len(chunk) - 1} to {addr}")

        except Exception as e:
            print(f"[SEND] Error: {e}")
        finally:
            conn.close()

    def send_mode(self, file_path, port):
        print("[Peer] Hosting...")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, port))
        server.listen(5)
        print(f"[SEND] Serving '{file_path}' on {self.host}:{self.port}")
        while self.running:
            try:
                conn, addr = server.accept()
                t = Thread(target=self.handle_client, args=(conn, addr, file_path))
                t.daemon = True  
                self.threads.append(t)
                t.start()
            
            except Exception as e:
                print(f"[SEND] Error: {e}")
                break

    #====================================================================================

    def request_chunk(self, peer_ip, peer_port, start, size, save_path):
        try:
            print(f"[DOWNLOAD] Connecting to {peer_ip}:{peer_port}")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((peer_ip, peer_port))

            # Request chunk (e.g. "0,1024")
            request = f"{start},{size}"
            s.sendall(request.encode())

            # Receive chunk
            received = b''
            while len(received) < size:
                chunk = s.recv(min(4096, size - len(received)))
                if not chunk:
                    break
                received += chunk

            # Save chunk to file
            with open(save_path, 'wb') as f:
                f.write(received)

            print(f"[DOWNLOAD] Downloaded {len(received)} bytes and saved to {save_path}")
            s.close()

        except Exception as e:
            print(f"[DOWNLOAD] Error: {e}")

    def download_chunk(self, peer, index, piece_length, temp_path):
        temp_file = f"{temp_path}.part_{index}"
        try:
            self.request_chunk(peer['ip'], peer['port'], index * piece_length, piece_length, temp_file)
            with open(temp_file, 'rb') as f:
                data = f.read()
            return index, data
        except Exception as e:
            print(f"[ERROR] Failed to download piece {index} from {peer['ip']}:{peer['port']}")
            return index, None  # returns a tuple even on error

    



    #-------------------------download mode---------------------------------------------
    

    def download_from_peers(self, peers, torrent_info, save_path, max_workers=config.constants.MAX_SPLITTNES_RATE):
        print("===== Parallel Download Started ======")
        total_size = torrent_info['file_size']
        piece_length = torrent_info['piece_length']
        # file_name = torrent_info['file_name']
        num_pieces = (total_size + piece_length - 1) // piece_length

        # Prepare empty list for chunks
        #chunk_results = [None] * num_pieces

        not_success = []

        random_folder_name = str(uuid.uuid4())
        os.mkdir(random_folder_name)

        def download_task(index, path):
            peer = peers[index % len(peers)]
            return self.download_chunk(peer, index, piece_length, path)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_index = {
                executor.submit(download_task, i, os.path.join(random_folder_name, torrent_info["file_name"])): i for i in range(num_pieces)
            }

            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    i, chunk = future.result()
                    if chunk:
                        #chunk_results[i] = chunk
                        print(f"[OK] Piece {i} from {peers[i % len(peers)]['ip']}")
                    else:
                        print(f"[FAIL] Piece {i} failed.")
                        #print(f"[Trying again] Piece {i} from {peers[i % len(peers)]['ip']}")
                        # Retry downloading the piece
                        not_success.append(i)
                except Exception as e:
                    print(f"[ERROR] Piece {index} failed with {e}")

        # Check if all pieces downloaded
        if not_success:
            print("[ERROR] Some pieces failed to download. Retrying...")
            for i in not_success:
                chunk = download_task(i, os.path.join(random_folder_name, torrent_info["file_name"]))
                if chunk is None:
                    print(f"[ERROR] Piece {i} failed again.")
                    return False
                else:
                    #print(f"[OK] Piece {i} downloaded successfully.")
                    #chunk_results[i] = chunk_results[i][1]  # Unpack the tuple
                    not_success.remove(i)
                    print(f"[OK] Piece {i} from {peers[i % len(peers)]['ip']}")
                    
        if not_success:
            print("[ERROR] Some chunks failed to download.")
            return False

        # Write full file
        with open(save_path, 'wb') as f:
            for i in range(num_pieces):
                temp_file = os.path.join(random_folder_name, f"{torrent_info['file_name']}.part_{i}")
                with open(temp_file, 'rb') as chunk_file:
                    f.write(chunk_file.read())
                os.remove(temp_file)
        
        try:
            import shutil
            shutil.rmtree(random_folder_name)
            print(f"[CLEANUP] Temporary folder {random_folder_name} removed.")
        except Exception as e:
            print(f"[WARNING] Could not remove temporary folder: {e}")

        print("[✓] File download complete and reassembled.")
        return True

    def download_mode(self, torrent_info, peers):
        save_path = os.path.join("download", torrent_info['file_name'])
        success = self.download_from_peers(peers, torrent_info, save_path)
        if success:
            print(f"[DONE] File successfully assembled to: {save_path}")
        else:
            print("[ERROR] Failed to download all chunks.")

    #===================================================================================




    # --------------------------------PEER TO TRACKER --------------------------------------
    def send_message(self, tracker_socket, message):
        try:
            tracker_socket.send(message.encode())
            response = tracker_socket.recv(config.constants.BUFFER_SIZE).decode()
            return response
        except Exception as e:
            print(f"Error sending message: {e}")
            return None

    def announce_to_tracker(self, tracker_port, info_hash, peer_id, ip, port, event='started'):
        print("Enter announcing the tracker.........")
        # Prepare the message
        message = {
            "info_hash": info_hash,
            "peer_id": peer_id,
            "ip": ip,
            "port": port,
            "event": event
        }
        try:
            # Send message
            response = self.send_message(tracker_port, json.dumps(message))
            response = json.loads(response)
            print("[TRACKER] Response from tracker:", response)
        except Exception as e:
            print(f"[ERROR] Failed to announce to tracker: {e}")

    def connect_to_tracker(self):
        try:
            tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tracker_socket.connect((self.tracker_host, self.tracker_port))
            print(f"[Peer] Connected to tracker {self.tracker_host}:{self.tracker_port}")
            time.sleep(1)

            tracker_socket.send(self.host.encode())
            tracker_socket.send(str(self.port).encode())
        except Exception as e:
            print(f"[Peer] Failed to connect to tracker: {e}")

        #global flag
        print("Welcome to STA \n")
        print("------List of commands-----\n")
        print("send <filename>: upload file to tracker to save.\n")
        print("search <filename>: find the file to download to get information of the peer.\n")
        print("connect: connect to the peer to get the file.\n")
        print("exit: exit the peer and disconnect from the tracker.\n")
        time.sleep(1)
        while True:
            if self.flag == 1:
                time.sleep(1)
                continue

            user_input = input("Enter command: ")
            if user_input.lower() == "exit":
                print("[Peer] Exiting...")
                #exit all thread
                
                self.running = False
                for t in self.threads:
                    t.join(timeout=1)
                    
                tracker_socket.close()
                exit(0)

            elif user_input.startswith("download"):
                command, *args = user_input.split(" ", 1)
                filename = args[0]
                torrent_file = f"metainfo/{filename}.torrent"
                if not os.path.isfile(torrent_file):
                    print("----------Invalid file input---------------")
                    continue

                # response = self.send_message(tracker_socket, user_input)
                # print(response)

                info_hash = self.get_info_hash(torrent_file)
                torrent_info = self.parse_torrent_file(torrent_file)
                user_input += f" {info_hash}"
                peerlist_response = self.send_message(tracker_socket, user_input)
                peer_list = json.loads(peerlist_response)
                #print("milestone 0")
                self.download_mode(torrent_info, peer_list)

            elif user_input.startswith("send"):
                command, *args = user_input.split(" ", 1)
                filename = args[0]
                response = self.send_message(tracker_socket, user_input)
                print(response)
                if not(os.path.isfile(filename)):
                    print("----------Invalid file input---------------")
                    continue

                torrent_info, info_hash = self.create_torrent_file(filename)
                print(f"Peers that have the {filename} file")
                torrent_file_path = f"metainfo/{filename}.torrent"

                self.listen_port.append(generate_random_port())
                print(f"Listening on port {self.listen_port[-1]}")
                # Announce to tracker about the file
                self.announce_to_tracker(
                    tracker_port=tracker_socket,
                    info_hash=info_hash,
                    peer_id=self.peer_id,
                    ip =self.host,
                    port=self.listen_port[-1],
                    event='started'
                )

                t = Thread(target=lambda: self.send_mode(filename, self.listen_port[-1]))
                t.daemon = True
                self.threads.append(t)
                t.start()
                continue

            response = self.send_message(tracker_socket, user_input)
            if response:
                print(f"[Tracker]: {response}")

            else:
                print("[Peer] Unknown command.")
#==================================================================================

if __name__ == "__main__":
    peer_host = get_host_default_interface_ip()
    peer_port = generate_random_port()

    print(f"this is the peer ID: {peer_host} and the port: {peer_port}")

    # tracker_host = config.constants.TRACKER_ADDR[1]
    # tracker_port = 22236
    print("Enter the tracker host and port")
    tracker_host = input("Enter the tracker host: ")
    tracker_port = int(input("Enter the tracker port: "))


    # Thread(target=host_peer, args=[peer_host, peer_port]).start()
    peer = Peer(peer_host, peer_port, tracker_host, tracker_port)
    Peer.connect_to_tracker(peer)
    #connect_to_tracker(tracker_host, tracker_port, peer_host, peer_port)

