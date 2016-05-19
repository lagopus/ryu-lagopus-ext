import struct
from . import packet_base
from . import packet_utils

class gtpu(packet_base.PacketBase):
    """
    """

    _PACK_STR = '!BBHI'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, flags=0x20, msgtype=255, teid=0):
        super(gtpu, self).__init__()
        self.flags = flags
        self.msgtype = msgtype
        self.teid = teid

    @classmethod
    def parser(cls, buf):
        (flags, msgtype, length, teid, ipver) = struct.unpack_from(cls._PACK_STR + 'B', buf)
        msg = cls(flags, msgtype, teid)
        return msg, gtpu.get_packet_type(ipver >> 4), buf[msg._MIN_LEN:]

    def serialize(self, payload, prev):
        return struct.pack(gtpu._PACK_STR,
                           self.flags, self.msgtype, len(payload), self.teid)
