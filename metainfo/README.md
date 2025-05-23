# STA_Project

**STA_Project** is a peer-to-peer (P2P) file-sharing application that enables users to download files by retrieving chunks from multiple peers concurrently, optimizing download speeds and reliability.

## 🚀 Features

- 🔄 Parallel Chunk Downloads from multiple peers
- 📡 Tracker-based Peer Discovery
- 🔒 Chunk Verification for data integrity
- ⏸️ Resumable Downloads (via saved partial chunks)
- 🧩 File Reassembly from multiple parts

## 📦 Prerequisites

- Python 3.x
- Install required packages:

```bash
pip install -r requirements.txt
```
## 📁 Installation
1. Clone the repository:
```bash
git clone https://github.com/T-K-Nguyen/STA_Project.git
cd STA_Project
```
2. Install dependencies:
```bash
    pip install -r requirements.txt
```
Something you need install `python3-tk` if you don't have it already.
```bash
sudo apt-get install python3-tk
```
And you should use python3.12 or lower, because the code is not compatible with python3.13 or higher (package `python3-tk` is not compatible with python3.13 or higher).

## 🛠️ Usage

### A. Start The tracker
- Make sure the file inside the download and metainfo is deleted.
- Put the file you want to share inside the My_STA folder.
- Start the Tracker.

Start the tracker (on IP your local host, default port 22236):
```bash
python tracker.py
```
You can keep track of the peers, which are seeding and the command history
by entering `show_peer` or `show_history`


### B. Start a Peer Node

To start a peer node and begin sharing or downloading:
```bash
python peer_node.py
```
You can create multiple peer on different terminals or virtual machine.

The peer port will be automatically generated,
the only input we need to give is the mode:
- exit
- download `<filename>`
- send`<filename>`

After that, now to take the matter simple you should create 3 peer_node
on the first two you can enter `send hello.txt` and on the third one you 
should enter `download hello.txt`.

The first 2 peer will create a `hello.txt.torrent` in the `metainfo` folder
and announce the tracker about it, then they will seed the same `hello.txt` file. 

And the downdload peer will take chunk from the seeding peer and assemble them
inside the `download` folder 


## 📂 Project Structure

| File              | Description                                                               |
|:------------------|:--------------------------------------------------------------------------|
| peer_node.py      | Peer logic: seeding, downloading, chunk handling                          |
| tracker.py	       | Tracker server: peer registration & lookup                                |
| .torrent file     | Metadata files for shared/downloaded files                                |
| .part* files	     | Temporary chunks during file download Colons can be used to align columns |


## 📚 Code Explanation

This section provides an overview of the main functions and 
components in the STA_Project. 
It will guide you through the logic behind key modules, 
so you can easily understand how everything fits together.

### 1. tracker.py — Tracker Server
The tracker.py file is responsible for managing the peer-to-peer (P2P) communication by handling peer registration and lookup.

- Functionality:

  - The tracker listens for peer requests to register themselves as seeders or leechers.

  - Tracks which peers have which pieces of the file, and provides this information to other peers upon request.

- Key Functions:

    - lishis(): take input from user to check history and peers.
    - handle_client(): important function that communicate with the peers.
    - run_tracker(): start the tracker connection and start listening to peers.
```bash
def lishis(self):
    # start taking input
    pass
    
def handle_client(self, conn, addr):
    # start taking input
    pass

def run_tracker(self):
    # start the tracker
    pass
```
### 2. `peer_node.py` — Peer Logic (Seeder/Leecher)
The peer_node.py file defines the peer node behavior, 
either as a seeder (uploading pieces) or leecher (downloading pieces). 
It interacts with the tracker and manages the file pieces.

- Functionality:

    - Peers connect to the tracker, 
  retrieve a list of peers, and download file pieces concurrently.

    - The peer node downloads file chunks from available peers 
  and writes them to disk, reassembling the complete file in the process.

- Key Functions:

`connect_to_tracker()`: This function handles the connection to the tracker. 
It sends the necessary information (like info_hash) and retrieves a list of peers to download from.

```bash
def connect_to_tracker(torrent_info):
    # Connects to the tracker and retrieves peer information.
    pass
```

`download_chunk()`:Downloads a specific chunk of the file from a peer. 
```bash
def download_chunk(peer, index, piece_length, temp_path):
    # Downloads a specific chunk from the peer and returns the data.
    pass
```

`download_from_peers()`:
This function manages the downloading of chunks from multiple peers concurrently. 
It uses threads(via ThreadPoolExecutor) 
to download different pieces of the file at the same time.
```bash
def download_from_peers(peers, torrent_info, save_path):
    # Manages concurrent downloads from multiple peers.
    pass

```


### 3. File Handling & Chunk Management
Files are divided into pieces (or chunks), which are downloaded from peers in parallel. Each chunk is requested, downloaded, and written to disk.

- Piece Length:

    - The file is split into smaller pieces based on the piece_length value, as defined in the .torrent file. Each piece is independently downloaded and later reassembled into the full file.

- Handling Chunks:

    - Chunks are saved to temporary .partX files as they are downloaded.
    - After all chunks are downloaded, the reassemble_file() function merges them into the full file. 
  It requests a chunk of the file and saves it to disk.

### 4. .torrent File & Tracker Interaction
A .torrent file contains essential metadata, including:

- **Info Hash**: A unique identifier for the file (used by the tracker).

- **Piece Length**: The size of each piece (or chunk).

- **Total File Size**: The size of the complete file.

- **Tracker URL**: The server responsible for handling peer registration and discovery.

When a peer wants to download a file:

1. It connects to the tracker and retrieves a list of peers.

2. The peer downloads file pieces from those peers concurrently.

3. The chunks are reassembled into the original file once all pieces are received.


### 5. Concurrent Downloads (MDDT-style)
This project leverages **Multiple Description Data Transfer (MDDT)** 
by downloading different file chunks from multiple peers at the same time. 
The download process is parallelized using Python's `ThreadPoolExecutor`, 
enabling faster and more reliable file retrieval.

Here’s how concurrency is handled:

- A peer requests pieces of the file from available peers using `download_chunk()`.

- Multiple pieces are downloaded in parallel using a pool of threads, allowing each chunk to be fetched from different peers.

### 6. Error Handling and Resuming Downloads
The code includes error handling to ensure that if a chunk download fails, 
it tries again with a different peer. 
If the program is stopped halfway through downloading, 
the `download_from_peers()` function can be resumed later, 
continuing from the last downloaded chunk.

## 🤝 Contributing
Pull requests are welcome! Feel free 
to fork the repo and submit improvements or bugfixes.


## 🙌 Acknowledgments
Special thanks to T-K-Nguyen for building 
this BitTorrent-style system for the STA (Computer Networks) Assignment.












