"""
fi
FINAL with pep 8
consts and another classes who is common to the agent
and server or just one of them because it is more organized here
"""
from PySide.QtGui import *
KAV_LAYER_PROTOCOLS = ['ether']
NETWORK_LAYER_PROTOCOLS = ['IP', 'ARP']
TRANSPORT_LAYER_PROTOCOLS = ['udp', 'tcp']
APP_LAYER_PROTOCOLS = ['dhcp', 'http']
HTTP_STRING = 'http'
UNKNOWN_PROTOCOL = 'unknown'
PROTOCOLS_LIST = ['ARP', 'ETHER', 'UDP', 'TCP',
                  'ICMP', 'RAW', 'IP', 'HTTP']
PROTOCOL_SEND_LEN = '|||'
HTTP_VERBS_AND_CONSTS = ['GET', 'HTTP', 'POST']
STOP_MSG = 'STOP'
CLOSED_ERROR = '[Errno 10054] An existing connection was ' \
               'forcibly closed by the remote host'
MINUS_ONE = -1
ZERO_NUMBER = 0
ARP_INDEX = DST_INDEX = NO_FILTER_INDEX = ZERO_NUMBER
ONE_NUMBER = 1
TEMP_RUN_IND = MAIN_WIDGET_INDEX = ETHER_INDEX =\
    IP_FILTER_INDEX = SRC_INDEX = ONE_NUMBER
TWO_NUMBER = 2
LIST_PACKETS_INDEX = FILTER_INDEX = UDP_INDEX \
    = PROTOCOL_INDEX = BOTH_INDEX = TWO_NUMBER
THREE_NUMBER = 3
LAST_PACKER_INDEX = PORT_INDEX = TCP_INDEX = OR_INDEX = THREE_NUMBER
FOUR_NUMBER = 4
IP_PARTS_NUM = ICMP_INDEX = FOUR_NUMBER
FIVE_NUMBER = 5
RAW_INDEX = FIVE_NUMBER
IP_INDEX = 6
HTTP_INDEX = 7
AND_STR = 'and'
OR_STR = 'or'
HALF_SECOND_TIMEOUT = 0.5
DPORT_STR = 'dport'
SPORT_STR = 'sport'
EQUAL_STR = '='
ONE_STR = '1'
TWO_STR = '2'
THREE_STR = '3'
EMPTY_STR = ''
FILE_ERROR = 'Bad file descriptor'
SPECIAL_PORTS_CHANGE_NAME = {'80': ['http', 'https', '80'],
                             '137': ['netbios_ns', '137'],
                             '67': ['bootps', '67'],
                             '68': ['bootpc', '68'],
                             '53': ['domain', '53'],
                             '1900': ['ssdp', '1900']}
MAX_PACKETS_TO_STORAGE = 3000
COMMA_STRING = ','
QUEUE_LEN = 10
LISTEN_ON_EVERY_NAME_IP = '0.0.0.0'
ONE_COMMA_STR = '1,'
TWO_COMMA_STR = '2,'
MAX_IP_NUMBER = 255
IP_SPLITTER = '.'
DOWN_RAW = '\r\n'
TWO_DOTS_STR = ':'
END_PACKET_SIGN = '|>'
PACKET_SPLITTER_SING = '|<'
BLANK_STR = ' '
BIGGEST_PORT = 65535
FILTERS_LIST = ['no filter', 'filter by ip address', 'filter by protocol',
                'filter by port']
IP_TYPES_LIST = ['destination', 'source', 'both', 'or']
PORT_TYPES_LIST = ['source port', 'destination port', 'both', 'or']
TEN = 10


def ip_is_valid(string_of_ip):
    """
    checking if the ip is valid and right
    string_of_ip - the string of ip to check
    """
    try:
        list_of_ip_numbers = string_of_ip.split(IP_SPLITTER)
        if len(list_of_ip_numbers) != IP_PARTS_NUM:
            return False
        for part_ip in list_of_ip_numbers:
            if int(part_ip) > MAX_IP_NUMBER or int(part_ip) < ZERO_NUMBER:
                return False
        return True
    except:
        return False


class Layer():
    """
    specific layer with all the knowledge about the specific layer
    text - the text of layer
    protocol_name - the name of the protocol of the layer
    layer_number - the number of the layer
    there are some features to the future versions
    """
    def __init__(self, text, protocol_name, layer_number):
        self.text = text
        self.protocol_name = protocol_name
        self.layer_number = layer_number

    def set_protocol_name(self, protocol_name):
        """
        set the protocol of layer
        """
        self.protocol_name = protocol_name

    def set_text(self, text):
        """
        set the text of layer
        """
        self.text = text

    def get_protocol(self):
        """
        get the protocol of layer
        """
        return self.protocol_name

    def get_text(self):
        """
        get the text of layer
        """
        return self.text

    def string_it(self):
        """
        return the string of the layer organized
        """
        str_temp = EMPTY_STR
        str_temp += self.protocol_name
        str_temp += PROTOCOL_TEXT_SPLITER
        str_temp += self.text
        return str_temp


class GeneralLayer:
    """
    general layer is general form of layer and it is important for
    the generality and for the other layers to have the same functions
    organized in this class
    """
    def __init__(self, list_of_protocols, layer_num):
        self.list_of_protocols = list_of_protocols
        self.layer_num = layer_num

    def do(self, temp_packet, protocol_of_layer, string_text_layer):
        """
        parse the general layer to specific layer
        temp packet - the packet to add the final layer
        protocol of later - the protocol of this layer
        string_text_layer - the text of the layer
        """
        protocol_identified = False
        if self.layer_num == ZERO_NUMBER:
            protocol_of_layer = protocol_of_layer[2::]
        for protocol_temp in self.list_of_protocols:
            if protocol_of_layer.lower() == protocol_temp.lower():
                protocol_identified = True
                temp_packet.append_layer(Layer(string_text_layer,
                                               protocol_of_layer,
                                               self.layer_num))
        if protocol_identified is False:
            temp_packet.append_layer(Layer(string_text_layer,
                                           protocol_of_layer,
                                           self.layer_num))


class Layer0(GeneralLayer):
    """
    the layer number 0 is the data link layer (kav)
    has specific known protocols
    """
    def __init__(self):
        GeneralLayer.__init__(self, KAV_LAYER_PROTOCOLS, ZERO_NUMBER)


class Layer1(GeneralLayer):
    """
    the layer number 1 is the network layer
    has specific known protocols
    """
    def __init__(self):
        GeneralLayer.__init__(self, NETWORK_LAYER_PROTOCOLS, ONE_NUMBER)


class Layer2(GeneralLayer):
    """
    the layer number 2 is the transport layer
    has specific known protocols
    """
    def __init__(self):
        GeneralLayer.__init__(self, TRANSPORT_LAYER_PROTOCOLS, TWO_NUMBER)


class Layer3(GeneralLayer):
    """
    the layer number 3 is the application layer
    has specific known protocols
    """
    def __init__(self):
        GeneralLayer.__init__(self, APP_LAYER_PROTOCOLS, THREE_NUMBER)

    def do(self, temp_packet, protocol_of_layer, string_text_layer):
        """
        special do function
        temp packet - the packet to add the final layer
        protocol of later - the protocol of this layer
        string_text_layer - the text of the layer
        """
        condition_temp_to_if = False
        for protocol_temp in self.list_of_protocols:
                if protocol_of_layer.lower() == protocol_temp.lower():
                    condition_temp_to_if = True
                    temp_packet.append_layer(Layer(string_text_layer,
                                                   protocol_of_layer,
                                                   self.layer_num))
        if condition_temp_to_if is False:
            if HTTP_STRING.upper() in string_text_layer:
                temp_packet.append_layer(Layer(string_text_layer,
                                               HTTP_STRING,
                                               self.layer_num))
            else:
                temp_packet.append_layer(Layer(string_text_layer,
                                               protocol_of_layer,
                                               self.layer_num))


layer_map = {ZERO_NUMBER: Layer0(), ONE_NUMBER: Layer1(),
             TWO_NUMBER: Layer2(), THREE_NUMBER: Layer3()}


class PacketClass():
    """
    class for a packet
    num_of_layers - the number of layers in the packet
    list_of_layers - list with all the layers of the packet,
    the layers are from the class Layer
    """
    def __init__(self, num_of_layers):
        self.num_of_layers = num_of_layers
        self.list_of_layers = []

    def append_layer(self, lay):
        """
        add a layer to the list of layers
        """
        self.list_of_layers.append(lay)

    def get_list(self):
        """
        returns the list of layers
        """
        return self.list_of_layers

    def printable(self):
        """
        sum the packet and return a string of the packet
        with all the layers organized by the protocol that I decided
        """
        final_string = EMPTY_STR
        for layer_to_string in self.list_of_layers:
            final_string += layer_to_string.string_it()
            final_string += PROTOCOL_TEXT_SPLITER
        return final_string

    def parse(self, string_of_packet_unorganized):
        """
        string_of_packet_unorganized - the string
        of the packet, not by my protocol
        build the packet by layers
        """
        try:
            list_of_layers =\
                string_of_packet_unorganized.split(PACKET_SPLITTER_SING)
            for layer_num in xrange(len(list_of_layers)):
                protocol_of_layer =\
                    list_of_layers[layer_num].split(BLANK_STR)[ZERO_NUMBER]
                text_layer =\
                    list_of_layers[layer_num].split(BLANK_STR)[TWO_NUMBER::]
                string_text_layer = EMPTY_STR
                for temp_string in text_layer:
                    string_text_layer += temp_string
                    string_text_layer += BLANK_STR
                string_text_layer = string_text_layer[:MINUS_ONE*TWO_NUMBER]
                if layer_num not in layer_map.keys():
                    GeneralLayer([], layer_num).do(self, protocol_of_layer,
                                                   string_text_layer)
                else:
                    layer_map[layer_num].do(self, protocol_of_layer,
                                            string_text_layer)
        except:
            pass

PROTOCOL_TEXT_SPLITER = '\||/'


class ThreadHandle():
    """
    the class keeps vars to the agent program,
    it helps to be synced about when to finish and what is the filter,
    in addition it keeps the packets that the specific agent sent,
    every agent has his own var from this class

    term_stop: bool who answer the question: stop?
        True - Stop
        False - continue
    packet_list: list of the packets that the agent sniffed
    thread_filter: the filter that the agent needs to filter by it
    """
    def __init__(self, term_stop):
        self.term_stop = term_stop
        self.packet_list = []
        # self.thread_filter = thread_filter

    def get_term(self):
        """
        return term_stop
        """
        return self.term_stop

    def set_term(self, term_stop):
        """
        change the term_stop by what its given
        """
        self.term_stop = term_stop

    def get_packet_list(self):
        """
        return the packet list
        """
        return self.packet_list

    def add_packet(self, pack):
        """
        add the packet who is given by
        the name pack, to the packet list
        """
        self.packet_list.append(pack)

    def clear_list(self):
        """
        restart the packet list, to avoid to many packets
        """
        self.packet_list = []

    def get_filter(self):
        """
        show the filter to sniff by
        """
        return self.thread_filter

    def set_filter(self, new_filter):
        self.thread_filter = new_filter
