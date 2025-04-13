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
from peer_node_be import PEER_BE


WIDTH = 900
HEIGHT = 600
config = Config.from_json(CFG)

PIECE_SIZE = config.constants.CHUNK_PIECES_SIZE  # 512KB per piece


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
  
    def __init__(self, peer_ip, peer_port):
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

        self.trackerHost = None
        self.trackerPort = None
        self.peer_be = None
        
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


    def connect_to_tracker_dialog(self):
        connect_frame = ctk.CTkFrame(self, width=WIDTH, height=HEIGHT)
        
        # Header
        header = ctk.CTkLabel(connect_frame, text="CONNECT TO TRACKER", font=("Arial", 30, "bold"))
        header.place(relx=0.5, rely=0.2, anchor=tk.CENTER)
        
        # IP input
        ip_label = ctk.CTkLabel(connect_frame, text="Tracker IP:", font=("Arial", 15))
        ip_label.place(relx=0.3, rely=0.4, anchor=tk.E)
        
        ip_entry = ctk.CTkEntry(connect_frame, width=250)
        ip_entry.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
        ip_entry.insert(0, "192.168.3.206")  # Default to localhost
        
        # Port input
        port_label = ctk.CTkLabel(connect_frame, text="Tracker Port:", font=("Arial", 15))
        port_label.place(relx=0.3, rely=0.5, anchor=tk.E)
        
        port_entry = ctk.CTkEntry(connect_frame, width=250)
        port_entry.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        port_entry.insert(0, "22236")  # Default port
        
        # Status message
        status_label = ctk.CTkLabel(connect_frame, text="", font=("Arial", 14))
        status_label.place(relx=0.5, rely=0.6, anchor=tk.CENTER)


        def process_connect_to_tracker():
            self.trackerHost = ip_entry.get().strip()
            self.trackerPort = int(port_entry.get().strip())

            self.peer_be = PEER_BE(self.peer_ip, self.peer_port, self.trackerHost, self.trackerPort)
            
            status, msg = self.peer_be.connect_to_tracker()
            if status:
                status_label.configure(text=f"Connected to tracker at {self.trackerHost}:{self.trackerPort}", 
                                    text_color="green")
                # Switch to initial page after successful connection
                self.after(1500, lambda: self.switch_frame(self.mainPage))
            else:
                status_label.configure(text="Connection failed " + msg, text_color="red")
                

        # wait user enter the ip and port and push connect button
        connect_btn = ctk.CTkButton(connect_frame, text="CONNECT", font=("Arial", 16, "bold"),
                                command=process_connect_to_tracker)
        connect_btn.place(relx=0.5, rely=0.7, anchor=tk.CENTER)
        
        return connect_frame


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
                                        command=lambda:self.switch_frame(self.connect_to_tracker_dialog))
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
        upload_image = ctk.CTkImage(Image.open("images/upload_icon.png"), size=(40, 40))
        btn_upload = ctk.CTkButton(self.frameMainPage, text="UPLOAD", font=("Arial", 20, "bold"),image= upload_image,
                                        command=lambda:self.switch_frame(self.executeUploadButton))
        btn_upload.place(relx=0.5,rely = 0.7,anchor =tk.CENTER)

        #---------------------------------------------------------------------------------------
        
        #---------------------------Button DOWNLOAD----------------------------------------------
        download_image = ctk.CTkImage(Image.open("images/download_icon.png").resize((50, 50)))
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


        back_image = ctk.CTkImage(Image.open("images/back.png").resize((40, 40)))
        btn_BACK= ctk.CTkButton(self.frameExecuteUploadButton,text="BACK", font=("Arial", 20,"bold"),image = back_image,
                            command =lambda: self.switch_frame(self.mainPage))
        btn_BACK.place(relx= 0.3, rely= 0.7, anchor= tk.CENTER)
        
        upload_image = ctk.CTkImage(Image.open("images/upload_icon.png").resize((40, 40)))
        btn_upload = ctk.CTkButton(self.frameExecuteUploadButton, text="UPLOAD", font=("Arial", 20,"bold"),image = upload_image,
                                    command=lambda:(self.select_file()))      
        btn_upload.place(relx = 0.5,rely=0.7,anchor = CENTER)
    
        
        btn_view_repo=ctk.CTkButton(self.frameExecuteUploadButton,text="FILE UPLOADED", font=("Arial", 20,"bold"),
                            command =lambda:self.animatePaneUpload.animate())
        btn_view_repo.place(relx= 0.7, rely= 0.7, anchor= tk.CENTER)
        
        list_header=ctk.CTkLabel(self.animatePaneUpload, text = " LIST FILES ", font=("Comic Sans",30,"bold"))
        list_header.place(relx=0.5,rely=0.1,anchor=ctk.CENTER)

        return self.frameExecuteUploadButton
    
    def select_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            status, msg = self.peer_be.upload_file(filename)
            if status:
                self.fileUploaded.append(filename)
                self.showFileUploaded(filename)
                messagebox.showinfo("Success", msg)
        else:
            messagebox.showerror("Error", msg)
        

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

        back_image = ctk.CTkImage(Image.open("images/back.png").resize((40, 40)))    
        btn_BACK= ctk.CTkButton(self.frameExecuteDownloadButton,text="BACK", font=("Arial", 20,"bold"),image = back_image,
                            command =lambda: self.switch_frame(self.mainPage))
        btn_BACK.place(relx= 0.3, rely= 0.7, anchor= tk.CENTER)

        download_image = ctk.CTkImage(Image.open("images/download_icon.png").resize((40, 40)))
        btn_dwnload = ctk.CTkButton(self.frameExecuteDownloadButton, text="DOWNLOAD", font=("Arial", 20,"bold"),image = download_image,
                                    command=lambda:(self.getFileDownload(dwnload_entry)))      
        btn_dwnload.place(relx = 0.5,rely=0.7,anchor = CENTER)
    
        
        btn_view_repo=ctk.CTkButton(self.frameExecuteDownloadButton,text="FILE DOWNLOADED", font=("Arial", 20,"bold"),
                            command =lambda: self.animatePanelDownload.animate())
        btn_view_repo.place(relx= 0.75, rely= 0.7, anchor= tk.CENTER)
        
        list_header=ctk.CTkLabel(self.animatePanelDownload, text = " LIST FILES ", font=("Comic Sans",30,"bold")
                                )
        list_header.place(relx=0.5,rely=0.1,anchor=ctk.CENTER)

        return self.frameExecuteDownloadButton

    def getFileDownload(self, download_entry):
        stringFileNameDownload = str(download_entry.get())
        if stringFileNameDownload == "":
            messagebox.showerror("Error", "File doesn't exist!")
            return

        def on_download_complete(success, msg):
            if success:
                self.fileDownloaded.append(stringFileNameDownload)
                messagebox.showinfo("Success", msg)
            else:
                messagebox.showerror("Error", msg)

        self.peer_be.download_file(stringFileNameDownload, on_complete=on_download_complete)


if __name__ == "__main__":
    peer_host = get_host_default_interface_ip()
    peer_port = generate_random_port()

    peer_fe = PEER_FE(peer_host, peer_port)
    peer_fe.mainloop()
