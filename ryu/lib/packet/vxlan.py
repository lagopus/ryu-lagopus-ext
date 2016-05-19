import struct
from . import packet_base
from . import packet_utils

class vxlan(packet_base.PacketBase):
    """
    """

    _PACK_STR = '!BxxxI'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, flags=0x8, vni=0):
        super(vxlan, self).__init__()
        self.flags = flags
        self.vni = vni

    @classmethod
    def parser(cls, buf):
        (flags, vni) = struct.unpack_from(cls._PACK_STR, buf)
        vni = vni >> 8
        msg = cls(flags, vni)
        return msg, vxlan.get_packet_type(0), buf[msg._MIN_LEN:]

    def serialize(self, payload, prev):
        return struct.pack(vxlan._PACK_STR, self.flags, self.vni << 8)
