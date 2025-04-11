import tkinter as tk
from tkinter import filedialog, messagebox
from utils import *
import socket
import random
from threading import Thread
import time
import os
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from configs import CFG, Config, get_host_default_interface_ip

config = Config.from_json(CFG)

PIECE_SIZE = config.constants.CHUNK_PIECES_SIZE  # 512KB per piece
flag = 0

# Existing functions (e.g., create_torrent_file, download_mode, etc.) remain unchanged
# ...existing code...

#----------------------------------PEER_FE-----------------------

class PeerNodeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Peer Node")
        self.tracker_socket = None
        self.peer_host = get_host_default_interface_ip()
        self.peer_port = generate_random_port()
        self.tracker_host = config.constants.TRACKER_ADDR[1]
        self.tracker_port = 22236

        # GUI Elements
        self.create_widgets()

    def create_widgets(self):
        # Title
        tk.Label(self.root, text="Peer Node", font=("Arial", 16)).pack(pady=10)

        # Buttons
        tk.Button(self.root, text="Send File", command=self.send_file).pack(pady=5)
        tk.Button(self.root, text="Download File", command=self.download_file).pack(pady=5)
        tk.Button(self.root, text="Exit", command=self.exit_app).pack(pady=5)

        # Status
        self.status_label = tk.Label(self.root, text="Status: Disconnected", fg="red")
        self.status_label.pack(pady=10)

        # Connect to Tracker
        self.connect_to_tracker()

    def connect_to_tracker(self):
        try:
            self.tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tracker_socket.connect((self.tracker_host, self.tracker_port))
            self.status_label.config(text="Status: Connected to Tracker", fg="green")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect to tracker: {e}")

    def send_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Send")
        if not file_path:
            return

        try:
            torrent_info, info_hash = create_torrent_file(file_path)
            announce_to_tracker(
                tracker_port=self.tracker_socket,
                info_hash=info_hash,
                peer_id=self.peer_port,
                ip=self.peer_host,
                port=self.peer_port,
                event='started'
            )
            Thread(target=send_mode, args=(self.peer_host, self.peer_port, torrent_info["file_name"])).start()
            messagebox.showinfo("Success", f"File '{os.path.basename(file_path)}' is now being shared.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send file: {e}")

    def download_file(self):
        torrent_file = filedialog.askopenfilename(title="Select Torrent File", filetypes=[("Torrent Files", "*.torrent")])
        if not torrent_file:
            return

        try:
            info_hash = get_info_hash(torrent_file)
            torrent_info = parse_torrent_file(torrent_file)
            peerlist_response = send_message(self.tracker_socket, json.dumps(info_hash))
            peer_list = json.loads(peerlist_response)
            success = download_mode(torrent_info, peer_list)
            if success:
                messagebox.showinfo("Success", "File downloaded successfully.")
            else:
                messagebox.showerror("Error", "Failed to download all chunks.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to download file: {e}")

    def exit_app(self):
        if self.tracker_socket:
            self.tracker_socket.close()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = PeerNodeApp(root)
    root.mainloop()

#----------------------------------FOLDER & METAINFO (.TORRENT)-----------------------
def create_torrent_file(file_path, piece_length=1024, torrent_path=None):
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

def get_info_hash(torrent_file_path):
    with open(torrent_file_path, "r") as f:
        torrent_data = json.load(f)

    encoded = json.dumps(torrent_data, sort_keys=True).encode()
    return hashlib.sha1(encoded).hexdigest()

def parse_torrent_file(torrent_path):
    with open(torrent_path, 'r') as f:
        torrent_info = json.load(f)
    return torrent_info

#==================================================================================





# -------------------------------send mode----------------------------
def handle_client(conn, addr, file_path):
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

def send_mode(host, port, file_path):
    print("[Peer] Hosting...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[SEND] Serving '{file_path}' on {host}:{port}")
    while True:
        conn, addr = server.accept()
        Thread(target=handle_client, args=(conn, addr, file_path)).start()
#====================================================================================





#-------------------------download mode---------------------------------------------
def request_chunk(peer_ip, peer_port, start, size, save_path):
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

def download_chunk(peer, index, piece_length, temp_path):
    temp_file = f"{temp_path}.part{index}"
    try:
        request_chunk(peer['ip'], peer['port'], index * piece_length, piece_length, temp_file)
        with open(temp_file, 'rb') as f:
            data = f.read()
        return index, data  # returns a tuple
    except Exception as e:
        print(f"[ERROR] Failed to download piece {index} from {peer['ip']}:{peer['port']}")
        return index, None  # returns a tuple even on error

def download_from_peers(peers, torrent_info, save_path, max_workers=config.constants.MAX_SPLITTNES_RATE):
    print("===== Parallel Download Started =====")
    total_size = torrent_info['file_size']
    piece_length = torrent_info['piece_length']
    # file_name = torrent_info['file_name']
    num_pieces = (total_size + piece_length - 1) // piece_length

    # Prepare empty list for chunks
    chunk_results = [None] * num_pieces

    def download_task(index):
        peer = peers[index % len(peers)]
        return download_chunk(peer, index, piece_length, save_path)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_index = {
            executor.submit(download_task, i): i for i in range(num_pieces)
        }

        for future in as_completed(future_to_index):
            index = future_to_index[future]
            try:
                i, chunk = future.result()
                if chunk:
                    chunk_results[i] = chunk
                    print(f"[OK] Piece {i} from {peers[i % len(peers)]['ip']}")
                else:
                    print(f"[FAIL] Piece {i} failed.")
            except Exception as e:
                print(f"[ERROR] Piece {index} failed with {e}")

    # Check if all pieces downloaded
    if None in chunk_results:
        print("[ERROR] Some chunks failed to download.")
        return False

    # Write full file
    with open(save_path, 'wb') as f:
        for chunk in chunk_results:
            f.write(chunk)

    print("[✓] File download complete and reassembled.")
    return True

def download_mode(torrent_info, peers):
    save_path = os.path.join("download", torrent_info['file_name'])
    success = download_from_peers(peers, torrent_info, save_path)
    if success:
        print(f"[DONE] File successfully assembled to: {save_path}")
    else:
        print("[ERROR] Failed to download all chunks.")

#===================================================================================




# --------------------------------PEER TO TRACKER --------------------------------------
def send_message(tracker_socket, message):
    try:
        tracker_socket.send(message.encode())
        response = tracker_socket.recv(config.constants.BUFFER_SIZE).decode()
        return response
    except Exception as e:
        print(f"Error sending message: {e}")
        return None

def announce_to_tracker(tracker_port, info_hash, peer_id, ip, port, event='started'):
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
        response = send_message(tracker_port, json.dumps(message))
        response = json.loads(response)
        print("[TRACKER] Response from tracker:", response)
    except Exception as e:
        print(f"[ERROR] Failed to announce to tracker: {e}")

def connect_to_tracker(host, port, peerip, peerport):
    try:
        tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tracker_socket.connect((host, port))
        print(f"[Peer] Connected to tracker {host}:{port}")
        time.sleep(1)
        tracker_socket.send(peerip.encode("utf-8"))
        tracker_socket.send(str(peerport).encode("utf-8"))
    except Exception as e:
        print(f"[Peer] Failed to connect to tracker: {e}")

    global flag
    print("Welcome to STA \n")
    print("------List of commands-----\n")
    print("send <filename>: upload file to tracker to save.\n")
    print("search <filename>: find the file to download to get information of the peer.\n")
    print("connect: connect to the peer to get the file.\n")
    print("exit: exit the peer and disconnect from the tracker.\n")
    time.sleep(1)
    while True:
        if flag == 1:
            time.sleep(1)
            continue

        user_input = input("Enter command: ")
        if user_input.lower() == "exit":
            print("[Peer] Exiting...")
            exit(0)
            break

        elif (user_input.startswith("download")):
            command, *args = user_input.split(" ", 1)
            filename = args[0]
            torrent_file = f"metainfo/{filename}.torrent"
            if not(os.path.isfile(torrent_file)):
                print("----------Invalid file input---------------")
                continue
            response = send_message(tracker_socket, user_input)
            print(response)

            info_hash = get_info_hash(torrent_file)
            torrent_info = parse_torrent_file(torrent_file)
            peerlist_response = send_message(tracker_socket, json.dumps(info_hash))
            peer_list = json.loads(peerlist_response)
            print("milestone 0")
            download_mode(torrent_info, peer_list)

        elif user_input.startswith("send"):
            command, *args = user_input.split(" ", 1)
            filename = args[0]
            response = send_message(tracker_socket, user_input)
            print(response)
            if not(os.path.isfile(filename)):
                print("----------Invalid file input---------------")
                continue

            torrent_info, info_hash = create_torrent_file(filename)
            print(f"Peers that have the {filename} file")
            torrent_file_path = f"metainfo/{filename}.torrent"

            # Announce to tracker about the file
            announce_to_tracker(
                tracker_port=tracker_socket,
                info_hash=info_hash,
                peer_id=peerport,
                ip =peerip,
                port=peerport,
                event='started'
            )

            Thread(target=send_mode, args=(peerip, peerport, torrent_info["file_name"])).start()
            continue

        response = send_message(tracker_socket, user_input)
        if response:
            print(f"[Tracker]: {response}")

        else:
            print("[Peer] Unknown command.")
#==================================================================================

if __name__ == "__main__":
    peer_host = get_host_default_interface_ip()
    peer_port = generate_random_port()

    print(f"this is the peer ID: {peer_port}, the same as the port")

    tracker_host = config.constants.TRACKER_ADDR[1]
    tracker_port = 22236

    # Thread(target=host_peer, args=[peer_host, peer_port]).start()

    connect_to_tracker(tracker_host, tracker_port, peer_host, peer_port)

