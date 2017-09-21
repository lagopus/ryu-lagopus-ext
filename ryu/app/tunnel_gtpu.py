from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

class TunnelGTPU(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TunnelGTPU, self).__init__(*args, **kwargs)
        # initialize mac address table.


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        type_eth  = (ofproto.OFPHTN_ONF << 16) | ofproto.OFPHTO_ETHERNET
        type_ip   = (ofproto.OFPHTN_ETHERTYPE << 16) | 0x0800
        type_udp   = (ofproto.OFPHTN_IP_PROTO << 16) | 17
        type_gtpu  = (ofproto.OFPHTN_UDP_TCP_PORT << 16) | 2152
        type_next = (ofproto.OFPHTN_ONF << 16) | ofproto.OFPHTO_USE_NEXT_PROTO

        print "type_eth ",  type_eth
        print "type_ip ",   type_ip
        print "type_udp ",  type_udp
        print "type_gtpu ",  type_gtpu
        print "type_next ", type_next

        # install the table-miss flow entry.

        # Encap Flow
        match = parser.OFPMatch(in_port=1)
        actions = [
                   # decap ether
                   parser.OFPActionDecap(type_eth, type_ip),
                   # encap gtpu
                   parser.OFPActionEncap(type_gtpu),
                   # set gtpu teid_field
                   parser.OFPActionSetField(gtpu_teid=1),
                   # encap udp
                   parser.OFPActionEncap(type_udp),
                   # set udp field
                   parser.OFPActionSetField(udp_src=5432),
                   parser.OFPActionSetField(udp_dst=2152),
                   # encap ip
                   parser.OFPActionEncap(type_ip),
                   # set ip field
                   parser.OFPActionSetField(ipv4_src='10.0.0.1'),
                   parser.OFPActionSetField(ipv4_dst='10.0.0.2'),
                   # encap ether
                   parser.OFPActionEncap(type_eth),
                   # set ether field
                   parser.OFPActionSetField(eth_src='aa:aa:aa:aa:aa:aa'),
                   parser.OFPActionSetField(eth_dst='bb:bb:bb:bb:bb:bb'),
                   # output
                   parser.OFPActionOutput(2, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

        # Decap Flow
        match = parser.OFPMatch(in_port=2)
        actions = [
                   # decap ether-ip
                   parser.OFPActionDecap(type_eth, type_ip),
                   # decap ip-udp
                   parser.OFPActionDecap(type_ip, type_udp),
                   # decap udp-gtpu
                   parser.OFPActionDecap(type_udp, type_gtpu),
                   # decap gtpu-ip
                   parser.OFPActionDecap(type_gtpu, type_ip),
                   # encap ether
                   parser.OFPActionEncap(type_eth),
                   # set ether field
                   parser.OFPActionSetField(eth_src='cc:cc:cc:cc:cc:cc'),
                   parser.OFPActionSetField(eth_dst='dd:dd:dd:dd:dd:dd'),
                   # output
                   parser.OFPActionOutput(1, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

