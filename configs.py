"""configs in json format"""
import json
import socket
def get_host_default_interface_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

CFG = {
    "directory": {
        "metainfo_dir": "metainfo/",
        "download_dir": "download/",
    },
    "constants": {
        "AVAILABLE_PORTS_RANGE": (1, 65535), # range of available ports on the local computer
        "TRACKER_ADDR": ('default_host', get_host_default_interface_ip()),
        "MAX_SEGMENT_DATA_SIZE": 65527,
        "BUFFER_SIZE": 1024,        # MACOSX UDP MTU is 9216
        "CHUNK_PIECES_SIZE": 512 * 1024, # Each chunk pieces(segments) must be lower than buffer size
        "MAX_SPLITTNES_RATE": 4,    # number of neighboring peers which the node take chunks of a file in parallel
        "NODE_TIME_INTERVAL": 20,        # the interval time that each node periodically informs the tracker (in seconds)
        "TRACKER_TIME_INTERVAL": 22      #the interval time that the tracker periodically checks which nodes are in the torrent (in seconds)
    },

}


class Config:
    """Config class which contains directories, constants, etc."""

    def __init__(self, directory, constants):
        self.directory = directory
        self.constants = constants


    @classmethod
    def from_json(cls, cfg):
        """Creates config from json"""
        params = json.loads(json.dumps(cfg), object_hook=HelperObject)
        return cls(params.directory, params.constants)


class HelperObject(object):
    """Helper class to convert json into Python object"""
    def __init__(self, dict_):
        self.__dict__.update(dict_)