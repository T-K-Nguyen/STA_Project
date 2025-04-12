import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox, DISABLED, CENTER, NORMAL
from PIL import Image, ImageTk
from utils import *
import socket
import random
from threading import Thread
import pickle
import threading
import time
import os
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from configs import CFG, Config, get_host_default_interface_ip
import math

WIDTH = 900
HEIGHT = 600
config = Config.from_json(CFG)


subFileSize= 512*1024 # 512KB
PIECE_SIZE = config.constants.CHUNK_PIECES_SIZE  # 512KB per piece
flag = 0

tracker_host = config.constants.TRACKER_ADDR[1]
tracker_port = 22236
    
tracker_socket = None
tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

peer_port = generate_random_port()
peer_ip = get_host_default_interface_ip()

# Existing functions (e.g., create_torrent_file, download_mode, etc.) remain unchanged
# ...existing code...

#----------------------------------PEER_FE-----------------------
class SlidePanel(ctk.CTkFrame):
  def __init__(self,parent,start_pos,end_pos):
      super().__init__(master=parent)
      
      self.start_pos=start_pos
      self.end_pos=end_pos
      self.width = abs(start_pos-end_pos)
      
      self.pos = start_pos
      self.in_start_pos = True
      
      self.place(relx=self.start_pos,rely=0,relwidth=self.width,relheight=0.65)
      
  def animate(self):
      if self.in_start_pos:
          self.animate_forward()
      else:
          self.animate_backward()
  def animate_forward(self):
      if self.pos > self.end_pos:
          self.pos -= 0.008
          self.place(relx=self.pos,rely=0,relwidth=self.width,relheight=0.65)
          self.after(10,self.animate_forward)
      else:
          self.in_start_pos = False
  def animate_backward(self):
      if self.pos < self.start_pos:
          self.pos += 0.008
          self.place(relx=self.pos,rely=0,relwidth=self.width,relheight= 0.65)
          self.after(10,self.animate_backward)
      else:
          self.in_start_pos = True

class PEER_FE(ctk.CTk):
  
  def __init__(self, peer_ip, peer_port, trackerHost, trackerPort):
    super().__init__()
    self.username = None
    self.password = None
    
    self.numberOfFileUploaded= 0
    self.numberOfFileDownloaded= 0
    
    self.fileUploaded= []
    self.fileDownloaded= []
    self.fileExist= []

    self.peer_ip= peer_ip
    self.peer_port= peer_port

    self.trackerHost = tracker_host
    self.trackerPort = tracker_port
    self.tracker_socket = tracker_socket
    
    #---------------------------initial frame for each page-----------------------------
    self.frameInitialPage= ctk.CTkFrame(self,width= 1020, height=700)
    self.frameExecuteLoginButton= ctk.CTkFrame(self,width=WIDTH,height=HEIGHT)
    self.frameConnectToServer= ctk.CTkFrame(self,width=WIDTH,height=HEIGHT)
    self.frameMainPage= ctk.CTkFrame(self,width=WIDTH,height=HEIGHT)
    self.frameExecuteUploadButton= ctk.CTkFrame(self,width=WIDTH,height=HEIGHT)
    self.frameExecuteDownloadButton= ctk.CTkFrame(self,width=WIDTH,height=HEIGHT)
    
    
    self.textFileExist= ctk.CTkTextbox(self.frameExecuteDownloadButton)
    
    self.animatePanelDownload = SlidePanel(self.frameExecuteDownloadButton, 1,0.7)
    self.outputFileDownload = ctk.CTkTextbox(self.animatePanelDownload)
    
    self.animatePaneUpload = SlidePanel(self.frameExecuteUploadButton, 1,0.7)
    self.outputFileUpload = ctk.CTkTextbox(self.animatePaneUpload)

    self.framestart= ctk.CTkFrame(self,width=WIDTH,height=HEIGHT)

    self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self, values=["Light", "Dark"],
                                                                       command=self.change_appearance_mode_event)
    self.appearance_mode_optionemenu.pack(side="bottom", padx=10, pady=(1, 1))

    self.ServerHost = None
    self.ServerPort = None

    self.resizable(False,False)
    self.title("tk")
    self.geometry("900x600")
  
    self.current_frame = self.initialPage()
    self.current_frame.pack()  


  def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)  
    
  def switch_frame(self, frame):
    self.current_frame.pack_forget()
    self.current_frame = frame()
    self.current_frame.pack(padx = 0) 
    
 
  def initialPage(self):
    
    frame_label = ctk.CTkLabel(self.frameInitialPage, text="WELCOME TO\n BITTORENT FILE SHARING", font=("Arial",40,"bold"))
    frame_label.place(relx=0.5,rely=0.4,anchor=tk.CENTER)

    button_start = ctk.CTkButton(self.frameInitialPage, text="START", font=("Arial", 15, "bold"),
                                    command=lambda:self.switch_frame(self.mainPage))
    button_start.place(relx=0.5,rely=0.7,anchor=tk.CENTER)
    

    
    return self.frameInitialPage


  def mainPage(self):
      
    frame_label = ctk.CTkLabel(self.frameMainPage, text="TORRENT", font=("Arial",40,"bold"))
    frame_label.place(relx=0.5,rely=0.2,anchor=tk.CENTER)
    
    frame_label = ctk.CTkLabel(self.frameMainPage, text="INFORMATION OF PEER", font=("Arial",20, "bold"))
    frame_label.place(relx=0.5,rely=0.4,anchor=tk.CENTER)
    
    frame_label = ctk.CTkLabel(self.frameMainPage, text="Peer Host: "+ self.peer_ip, font=("Arial", 15 ))
    frame_label.place(relx=0.5,rely=0.5,anchor=tk.CENTER)
    
    frame_label = ctk.CTkLabel(self.frameMainPage, text="Peer Port: "+ str(self.peer_port), font=("Arial", 15))
    frame_label.place(relx=0.5,rely=0.55,anchor=tk.CENTER)
    
    #----------------Button UPLOAD---------------------------------------------------------
    upload_image = ctk.CTkImage(Image.open("upload_icon.png"), size=(40, 40))
    btn_upload = ctk.CTkButton(self.frameMainPage, text="UPLOAD", font=("Arial", 20, "bold"),image= upload_image,
                                    command=lambda:self.switch_frame(self.executeUploadButton))
    btn_upload.place(relx=0.5,rely = 0.7,anchor =tk.CENTER)

    #---------------------------------------------------------------------------------------
    
    #---------------------------Button DOWNLOAD----------------------------------------------
    download_image = ctk.CTkImage(Image.open("download_icon.png").resize((40, 40)))
    self.btn_download = ctk.CTkButton(self.frameMainPage, text="DOWNLOAD", font=("Arial", 20, "bold"),image = download_image,
                                        command=lambda:self.switch_frame(self.executeDownloadButton))
    self.btn_download.place(relx=0.5,rely = 0.85,anchor =tk.CENTER)
    #----------------------------------------------------------------------------------------
    

  
    return self.frameMainPage

  def executeUploadButton(self):

    header_upload = ctk.CTkLabel(self.frameExecuteUploadButton, text="UPLOAD FILE", font=("Arial", 40,"bold"))
    header_upload.place(relx = 0.5,rely=0.3,anchor = CENTER)
    
    self.outputFileUpload.place(relx=0.5,rely=0.55,anchor=ctk.CENTER,relwidth=0.8,relheight=0.8)
    self.outputFileUpload.configure(state=DISABLED)


    back_image = ctk.CTkImage(Image.open("back.png").resize((40, 40)))
    btn_BACK= ctk.CTkButton(self.frameExecuteUploadButton,text="BACK", font=("Arial", 20,"bold"),image = back_image,
                          command =lambda: self.switch_frame(self.mainPage))
    btn_BACK.place(relx= 0.3, rely= 0.7, anchor= tk.CENTER)
    
    upload_image = ctk.CTkImage(Image.open("upload_icon.png").resize((40, 40)))
    btn_upload = ctk.CTkButton(self.frameExecuteUploadButton, text="UPLOAD", font=("Arial", 20,"bold"),image = upload_image,
                                command=lambda:(self.select_file()))      
    btn_upload.place(relx = 0.5,rely=0.7,anchor = CENTER)
  
    
    btn_view_repo=ctk.CTkButton(self.frameExecuteUploadButton,text="FILE UPLOADED", font=("Arial", 20,"bold"),
                          command =lambda:self.animatePaneUpload.animate())
    btn_view_repo.place(relx= 0.7, rely= 0.7, anchor= tk.CENTER)
    
    list_header=ctk.CTkLabel(self.animatePaneUpload, text = " LIST FILES ", font=("Comic Sans",30,"bold"))
    list_header.place(relx=0.5,rely=0.1,anchor=ctk.CENTER)
    # list_header.pack()

    return self.frameExecuteUploadButton
  
  def select_file(self):
    file_path = filedialog.askopenfilename()
    if file_path:
        try:
            filename = os.path.basename(file_path)
            print(f"Selected file: {filename}")
            if not os.path.isfile(file_path):
                messagebox.showerror("Error", "Invalid file selected.")
                return

            # Send the "send" command to the tracker
            user_input = f'send "{filename}"'
            response = send_message(self.tracker_socket, user_input)
            print(response)

            # Create the torrent file
            torrent_info, info_hash = create_torrent_file(filename)
            print(f"Peers that have the {filename} file")
            torrent_file_path = f"metainfo/{filename}.torrent"

            # Announce to the tracker
            announce_to_tracker(
                tracker_port=tracker_socket,
                info_hash=info_hash,
                peer_id=peer_port,
                ip =peer_ip,
                port=peer_port,
                event='started'
            )

            # Start the send mode in a separate thread
            Thread(target=send_mode, args=(self.peer_ip, self.peer_port, torrent_info["file_name"])).start()

            messagebox.showinfo("Success", f"File '{filename}' uploaded successfully!")
            self.fileUploaded.append(filename)
            self.showFileUploaded(filename)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to upload file: {e}")

  def showFileUploaded(self, fileName):
        self.outputFileUpload.configure(state=NORMAL)
        self.numberOfFileUploaded+= 1
        self.outputFileUpload.insert(ctk.END, f"{self.numberOfFileUploaded}.   \"{fileName}\"" +"\n\n" )
        self.outputFileUpload.see(ctk.END)
        self.outputFileUpload.configure(state=DISABLED)
  
  def executeDownloadButton(self):

    header_upload = ctk.CTkLabel(self.frameExecuteDownloadButton, text="DOWNLOAD FILE", font=("Arial", 40,"bold"))
    header_upload.place(relx = 0.5,rely=0.3,anchor = CENTER)
    

    
    self.outputFileDownload.place(relx=0.5,rely=0.55,anchor=ctk.CENTER,relwidth=0.8,relheight=0.8)
    self.outputFileDownload.configure(state=DISABLED)

    upload_label = ctk.CTkLabel(self.frameExecuteDownloadButton, text="Enter your file name", font=("Arial", 20,"bold"))
    upload_label.place(relx = 0.5, rely=0.5,anchor = tk.CENTER)

    dwnload_entry = ctk.CTkEntry(self.frameExecuteDownloadButton, width=300, height= 10)
    dwnload_entry.place(relx = 0.5, rely=0.55,anchor = tk.CENTER)

    back_image = ctk.CTkImage(Image.open("back.png").resize((40, 40)))    
    btn_BACK= ctk.CTkButton(self.frameExecuteDownloadButton,text="BACK", font=("Arial", 20,"bold"),image = back_image,
                          command =lambda: self.switch_frame(self.mainPage))
    btn_BACK.place(relx= 0.3, rely= 0.7, anchor= tk.CENTER)

    download_image = ctk.CTkImage(Image.open("download_icon.png").resize((40, 40)))
    btn_dwnload = ctk.CTkButton(self.frameExecuteDownloadButton, text="DOWNLOAD", font=("Arial", 20,"bold"),image = download_image,
                                command=lambda:(self.getFileDownload(dwnload_entry)))      
    btn_dwnload.place(relx = 0.5,rely=0.7,anchor = CENTER)
  
    
    btn_view_repo=ctk.CTkButton(self.frameExecuteDownloadButton,text="FILE DOWNLOADED", font=("Arial", 20,"bold"),
                          command =lambda: self.animatePanelDownload.animate())
    btn_view_repo.place(relx= 0.75, rely= 0.7, anchor= tk.CENTER)
    
    list_header=ctk.CTkLabel(self.animatePanelDownload, text = " LIST FILES ", font=("Comic Sans",30,"bold")
                              )
    list_header.place(relx=0.5,rely=0.1,anchor=ctk.CENTER)
    # list_header.pack()
    return self.frameExecuteDownloadButton

  def getFileDownload(self, download_entry):
    stringFileNameDownload = str(download_entry.get())
    print(stringFileNameDownload)
    if stringFileNameDownload == "":
        messagebox.showerror("Error", "File doesn't exist!")
        return

    torrent_file = f"metainfo/{stringFileNameDownload}.torrent"
    if not os.path.isfile(torrent_file):
        print("----------Invalid file input---------------")
        messagebox.showerror("Error", "Torrent file not found!")
        return

    # Gửi yêu cầu đến tracker
    user_input = f'download "{stringFileNameDownload}"'
    response = send_message(self.tracker_socket, user_input)
    print(f"[DEBUG] Tracker response: {response}")

    if not response:
        messagebox.showerror("Error", "No response from tracker!")
        return

    # Lấy danh sách peer từ tracker
    info_hash = get_info_hash(torrent_file)
    torrent_info = parse_torrent_file(torrent_file)
    peerlist_response = send_message(self.tracker_socket, json.dumps(info_hash))

    if not peerlist_response:
        print("[ERROR] No response from tracker for peer list.")
        messagebox.showerror("Error", "Failed to get peer list from tracker!")
        return

    try:
        peer_list = json.loads(peerlist_response)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to decode JSON: {e}")
        print(f"[DEBUG] Response content: {peerlist_response}")
        messagebox.showerror("Error", "Invalid response from tracker!")
        return

    print("milestone 0")
    download_mode(torrent_info, peer_list)
      
    self.switch_frame(self.executeDownloadButton)




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

def connect_to_tracker(host, port, peerip, peer_port):
    global tracker_socket
    try:
        tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tracker_socket.connect((host, port))
        print(f"[Peer] Connected to tracker {host}:{port}")
        time.sleep(1)
        tracker_socket.send(peerip.encode("utf-8"))
        tracker_socket.send(str(peer_port).encode("utf-8"))
    except Exception as e:
        print(f"[Peer] Failed to connect to tracker: {e}")

    global flag
    print("Welcome to STA \n")
    # print("------List of commands-----\n")
    # print("send <filename>: upload file to tracker to save.\n")
    # # print("search <filename>: find the file to download to get information of the peer.\n")
    # # print("connect: connect to the peer to get the file.\n")
    # print("exit: exit the peer and disconnect from the tracker.\n")
    # time.sleep(1)



    app = PEER_FE(peerip, peer_port, tracker_host, tracker_port)
    app.mainloop()
    exit
    # user_input = input("Enter command: ")
    # if user_input.lower() == "exit":
    #     print("[Peer] Exiting...")
    #     exit(0)

    # elif (user_input.startswith("download")):
    #         command, *args = user_input.split(" ", 1)
    #         filename = args[0]
    #         torrent_file = f"metainfo/{filename}.torrent"
    #         if not(os.path.isfile(torrent_file)):
    #             print("----------Invalid file input---------------")
    #         response = send_message(tracker_socket, user_input)
    #         print(response)

    #         info_hash = get_info_hash(torrent_file)
    #         torrent_info = parse_torrent_file(torrent_file)
    #         peerlist_response = send_message(tracker_socket, json.dumps(info_hash))
    #         peer_list = json.loads(peerlist_response)
    #         print("milestone 0")
    #         download_mode(torrent_info, peer_list)

    #     response = send_message(tracker_socket, user_input)
    #     if response:
    #         print(f"[Tracker]: {response}")

    #     else:
    #         print("[Peer] Unknown command.")

#==================================================================================

if __name__ == "__main__":
    peer_ip = peer_ip
    peer_port = peer_port

    print(f"this is the peer ID: {peer_port}, the same as the port")



    # Thread(target=host_peer, args=[peer_host, peer_port]).start()

    
    connect_to_tracker(tracker_host, tracker_port, peer_ip, peer_port)
    

