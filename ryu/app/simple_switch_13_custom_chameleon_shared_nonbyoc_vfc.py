# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


HARD_TIMEOUT = 600
IDLE_TIMEOUT = 300

VLAN_RANGE_PHYSNET1 = (3010,3400)
SHARED_VFC_PHYSNET1 = "br63"




class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
       

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)
        
        ### Send port description request message
        self.vlan_to_portgroup = {}
        self.uplink_port_range=(int(str(VLAN_RANGE_PHYSNET1[0])[-3:]),int(str(VLAN_RANGE_PHYSNET1[1])[-3:]))

        self.vlan_to_portgroup = {vlan : [] for vlan in range(self.uplink_port_range[0],self.uplink_port_range[1]+1)}
        self.send_port_desc_stats_request(datapath)
        self.logger.info("--- [switch_features_handler] uplink_port_range: %s", self.uplink_port_range)
        ###self.logger.info("--- [switch_features_handler] vlan_to_portgroup : %s", self.vlan_to_portgroup)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, 
                                    buffer_id=buffer_id,
                                    priority=priority, 
                                    match=match,
                                    idle_timeout=IDLE_TIMEOUT, 
                                    #hard_timeout=HARD_TIMEOUT,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, 
                                    priority=priority,
                                    match=match, 
                                    instructions=inst)

        datapath.send_msg(mod)

    def delete_flow(self, datapath, port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(in_port=port)

        mod = parser.OFPFlowMod(datapath=datapath, 
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY, 
                                out_group=ofproto.OFPG_ANY,
                                priority=1, 
                                match=match)

        datapath.send_msg(mod)

        actions = [parser.OFPActionOutput(port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, 
                                command=ofproto.OFPFC_DELETE,
                                out_port=port, 
                                out_group=ofproto.OFPG_ANY,
                                instructions=inst)

        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        ###self.send_port_stats_request(datapath)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        ### Print mac_to_port 
        self.logger.info("--- [_packet_in_handler] mac_to_port : %s ", self.mac_to_port )


        if dst in self.mac_to_port[dpid]:
            self.logger.info("--- [_packet_in_handler] dst in mac_to_port : %s ", dst )
            out_port = self.mac_to_port[dpid][dst]
            actions = [parser.OFPActionOutput(out_port)]
        else:
            self.logger.info("--- [_packet_in_handler] dst NOT in mac_to_port : %s ", dst )
            pp = self.find_portgroup(in_port)
            self.logger.info("--- [_packet_in_handler] pp : %s ", pp )
            portgroup = [ int(x) for x in self.vlan_to_portgroup[pp]]
            self.logger.info("--- [_packet_in_handler] portgroup : %s ", portgroup )

            out_port = ofproto.OFPP_ALL
            actions = []
            for port in portgroup:
                if not port == in_port: 
                    actions.append(parser.OFPActionOutput(port))

        self.logger.info("--- [_packet_in_handler] in_port : %s ", in_port )
        self.logger.info("--- [_packet_in_handler] actions : %s ", actions )


        #if dst in self.mac_to_port[dpid]:
        #    out_port = self.mac_to_port[dpid][dst]
        #else:
        #    out_port = ofproto.OFPP_ALL

        #actions = [parser.OFPActionOutput(out_port)]


        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_ALL:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                priority = 1
                self.add_flow(datapath, priority, match, actions, msg.buffer_id)
                return
            else:
                priority = 1
                self.add_flow(datapath, priority, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, 
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port, 
                                  actions=actions, 
                                  data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        dp = msg.datapath


        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
            self.delete_flow(dp,port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illegal port state %s %s", port_no, reason)

        self.logger.info('OFPPortStatus received: reason=%s desc=%s',reason, msg.desc)

        ### Send port description request message and re-create vlan_to_portgroup
        self.vlan_to_portgroup = {}
        ####self.vlan_to_portgroup = {vlan : [] for vlan in range(VLAN_RANGE_PHYSNET1[0],VLAN_RANGE_PHYSNET1[1]+1)}
        self.vlan_to_portgroup = {p : [] for p in range(self.uplink_port_range[0],self.uplink_port_range[1]+1)}
        self.send_port_desc_stats_request(dp)
        self.logger.info("--- [_port_status_handler] vlan_to_portgroup : %s", self.vlan_to_portgroup)


    def send_port_desc_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def _port_desc_stats_reply_handler(self, ev):
        ports = []
        for p in ev.msg.body:
            ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
                     'state=0x%08x curr=0x%08x advertised=0x%08x '
                     'supported=0x%08x peer=0x%08x curr_speed=%d '
                     'max_speed=%d' %
                     (p.port_no, p.hw_addr,
                      p.name, p.config,
                      p.state, p.curr, p.advertised,
                      p.supported, p.peer, p.curr_speed,
                      p.max_speed))
            self.logger.info("--- [_port_desc_stats_reply_handler] port_name: %s ", p.name) 
            self.vlan_to_portgroup_handler(str(p.name))
        self.logger.info('OFPPortDescStatsReply received: %s', ports)


    def vlan_to_portgroup_handler(self, port_name): 

        if len(port_name.split('-')) == 2:

            bridge, port_no = port_name.split('-')
            if bridge == SHARED_VFC_PHYSNET1 and ( self.uplink_port_range[0] <= int(port_no) <= self.uplink_port_range[1] ):
                self.logger.info("--- [vlan_to_portgroup_handler] Uplink port : %s", port_no)
                self.set_key(self.vlan_to_portgroup, int(port_no), port_no) 
            else: 
                self.logger.info("--- [vlan_to_portgroup_handler] Access port : %s", port_no)
                if len(str(port_no)) < 3:
                    port_no_str = '0' + str(port_no)
                else:
                    port_no_str = str(port_no)
                port_last_3digits = str(port_no_str)[-3:]
                for i in self.vlan_to_portgroup.keys():
                    if len(str(i)) < 3:
                        i_str = '0' + str(i)
                    else:
                        i_str = str(i)
                    vlan_last_3digits = str(i_str)[-3:]
                    if vlan_last_3digits == port_last_3digits:
                        self.set_key(self.vlan_to_portgroup, i, port_no)
                        break
            self.logger.info("--- [vlan_to_portgroup_handler] vlan_to_portgroup : %s", self.vlan_to_portgroup)
        else:
            self.logger.info("--- [vlan_to_portgroup_handler] LOCAL port_name : %s", port_name)
            pass


    def find_portgroup(self, port_no):
        if len(str(port_no)) < 3:
            port_no_str = '0' + str(port_no)
        else:
            port_no_str = str(port_no)
        port_last_3digits = str(port_no_str)[-3:]       
 
        for i in self.vlan_to_portgroup.keys():
            if len(str(i)) < 3:
                i_str = '0' + str(i)
            else:
                i_str = str(i)
            vlan_last_3digits = str(i_str)[-3:]

            if vlan_last_3digits == port_last_3digits:
                vlan = i
                break
            else:
                vlan = None
        return vlan


    def send_port_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
        datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        ports = []
        for stat in ev.msg.body:
            ports.append('port_no=%d '
                     'rx_packets=%d tx_packets=%d '
                     'rx_bytes=%d tx_bytes=%d '
                     'rx_dropped=%d tx_dropped=%d '
                     'rx_errors=%d tx_errors=%d '
                     'rx_frame_err=%d rx_over_err=%d rx_crc_err=%d '
                     'collisions=%d duration_sec=%d duration_nsec=%d' %
                     (stat.port_no,
                      stat.rx_packets, stat.tx_packets,
                      stat.rx_bytes, stat.tx_bytes,
                      stat.rx_dropped, stat.tx_dropped,
                      stat.rx_errors, stat.tx_errors,
                      stat.rx_frame_err, stat.rx_over_err,
                      stat.rx_crc_err, stat.collisions,
                      stat.duration_sec, stat.duration_nsec))
        self.logger.info('PortStats: %s', ports)


    # https://stackoverflow.com/a/41826126
    def set_key(self, dictionary, key, value):
        if key not in dictionary:
            dictionary[key] = value
        elif type(dictionary[key]) == list:
            dictionary[key].append(value)
        else:
            dictionary[key] = [dictionary[key], value]

