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



class PEER_BE:
    def __init__(self, host, port, tracker_host, tracker_post):
        self.host = host
        self.port = port
        self.peer_id = f"{host}:{port}"  # Unique identifier for the peer
        self.tracker_host = tracker_host
        self.tracker_port = tracker_post
        self.tracker_socket = None
        self.peers = []  # List of peers for downloading
        self.listen_port = []
        self.flag = 0
        self.running = True
        self.threads = []
#----------------------------------FOLDER & METAINFO (.TORRENT)-----------------------
    def create_torrent_file(self, file_path, piece_length=config.constants.CHUNK_PIECES_SIZE, torrent_path=None):
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
            # Receive requested offset and length
            data = conn.recv(1024).decode()
            if not data:
                return
            start, size = map(int, data.strip().split(','))

            with open(file_path, 'rb') as f:
                f.seek(start)
                chunk = f.read(size)

            conn.sendall(chunk)


        except Exception as e:
            print(f"[SEND] Error: {e}")
            pass
        finally:
            conn.close()

    def send_mode(self, file_path, port):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, port))
        server.listen(5)
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

    def request_chunk(self, peer_ip, peer_port, start, size, save_path, hash_validation):
        try:
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

            # check hash
            sha1 = hashlib.sha1(received).hexdigest()
            if sha1 != hash_validation[start // size]:
                print(f"[ERROR] Hash mismatch for {peer_ip}:{peer_port}. Expected {hash_validation}, got {sha1}")
                return False, f"Hash mismatch for {peer_ip}:{peer_port}. Expected {hash_validation}, got {sha1}"

            # Save chunk to file
            with open(save_path, 'wb') as f:
                f.write(received)


            s.close()
            return True, f"Downloaded {len(received)} bytes and saved to {save_path}"

        except Exception as e:
            print(f"[DOWNLOAD] Error: {e}")
            return False, f"Error: {e}"

    def download_chunk(self, peer, index, piece_length, temp_path, hash_validation):
        temp_file = f"{temp_path}.part_{index}"
        try:
            result, msg =self.request_chunk(peer['ip'], peer['port'], index * piece_length, piece_length, temp_file, hash_validation)
            if not result:
                return False, index  
            return True, index
        except Exception as e:
            print(f"[ERROR] Failed to download piece {index} from {peer['ip']}:{peer['port']}")
            return False, index  

    



    #-------------------------download mode---------------------------------------------
    

    def download_from_peers(self, peers, torrent_info, save_path, max_workers=config.constants.MAX_SPLITTNES_RATE):
        #print("===== Parallel Download Started ======")
        total_size = torrent_info['file_size']
        piece_length = torrent_info['piece_length']
        num_pieces = (total_size + piece_length - 1) // piece_length
        not_success = []

        random_folder_name = str(uuid.uuid4())
        os.mkdir(random_folder_name)

        def download_task(index, path, hash_validation):
            peer = peers[index % len(peers)]
            return self.download_chunk(peer, index, piece_length, path, hash_validation)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_index = {
                executor.submit(download_task, i, os.path.join(random_folder_name, torrent_info["file_name"]),
                                torrent_info["pieces"]): i for i in range(num_pieces)
            }

            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    result, i = future.result()
                    if not result:
                        print(f"[FAIL] Piece {i} failed.")
                        not_success.append(i)
                    else:
                        print(f"[OK] Piece {i} from {peers[i % len(peers)]['ip']}")

                        
                except Exception as e:
                    print(f"[ERROR] Piece {index} failed with {e}")
                    pass
                
        # Check if all pieces downloaded
        if not_success:
            print("[ERROR] Some pieces failed to download. Retrying...")
            for index in not_success:
                result, i = download_task(index, os.path.join(random_folder_name, torrent_info["file_name"]), torrent_info["pieces"])
                if result:
                    not_success.remove(i)
                    print(f"[ERROR] Piece {i} failed again.")

                    
        if not_success:
            print("[ERROR] Some chunks failed to download.")
            #print(not_success)
            return False, "Some chunks failed to download."

        print("[OK] All pieces downloaded successfully.")
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
            pass

        print("[✓] File download complete and reassembled.")
        return True, "File download complete and reassembled."

    def download_mode(self, torrent_info, peers):
        save_path = os.path.join("download", torrent_info['file_name'])
        success, msg = self.download_from_peers(peers, torrent_info, save_path)
        if success:
            print(f"[DONE] File successfully assembled to: {save_path}")
            return True, f"File successfully assembled to: {save_path}"
        else:
            print(f"[ERROR] Failed to download file: {msg}")

            return False, f"Failed {msg}"

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
            pass

    def connect_to_tracker(self):
        try:
            self.tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tracker_socket.connect((self.tracker_host, self.tracker_port))
            time.sleep(1)

            self.tracker_socket.send(self.host.encode())
            self.tracker_socket.send(str(self.port).encode())
            return True, f"Successfully connected to tracker {self.tracker_host}:{self.tracker_port}"
        except Exception as e:
            print(f"[Peer] Failed to connect to tracker: {e}")
            return False, f"Failed to connect to tracker: {e}"

    
#==================================================================================
    def upload_file(self, filepath):
        filename = filepath.split("/")[-1]
        try:
            if not os.path.isfile(filename):
                print(f"[ERROR] File '{filepath}' does not exist.")
                return None, "File does not exist."

            command = f"send {filename}"
            print(f"Command to tracker: {command}")
            self.send_message(self.tracker_socket, command)
            torrent_info, info_hash = self.create_torrent_file(filename)
            self.listen_port.append(generate_random_port())

            self.announce_to_tracker(
                tracker_port=self.tracker_socket,
                info_hash=info_hash,
                peer_id=self.peer_id,
                ip=self.host,
                port=self.listen_port[-1],
                event='started'
            )
            t = Thread(target=lambda: self.send_mode(filepath, self.listen_port[-1]))
            t.daemon = True
            self.threads.append(t)
            t.start()

            return True, f"File uploaded {filename} successfully."

        except Exception as e:
            return False, f"Failed to upload file: {e}"


    def download_file(self, filename, on_complete=None):
        torrent_file = f"metainfo/{filename}.torrent"
        print(f"[+] Download request for {torrent_file}")
        try:
            if not os.path.isfile(torrent_file):
                if on_complete:
                    on_complete(False, "File does not have a torrent file.")
                return False, "File does not have a torrent file."

            info_hash = self.get_info_hash(torrent_file)
            torrent_info = self.parse_torrent_file(torrent_file)

            peerlist_response = self.send_message(self.tracker_socket, f"download {filename} {info_hash}")
            peer_list = json.loads(peerlist_response)
            if not peer_list:
                if on_complete:
                    on_complete(False, "No peers available for download.")
                return False, "No peers available for download."

            def background_download():
                try:
                    success, msg = self.download_mode(torrent_info, peer_list)
                    print(f"[✓] Download finished: {msg}")
                    if on_complete:
                        on_complete(success, msg)
                except Exception as e:
                    print(f"[✗] Download failed: {e}")
                    if on_complete:
                        on_complete(False, str(e))

            t = Thread(target=background_download)
            t.daemon = True
            t.start()
            self.threads.append(t)

            return True, f"Download started for {filename}"
        except Exception as e:
            if on_complete:
                on_complete(False, f"Failed to download file: {e}")
            return False, f"Failed to download file: {e}"

