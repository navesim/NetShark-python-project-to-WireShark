"""
fi
FINAL with pep8
agent responsible for sniffing and sending the good packets to the server,
agent need to run as long as the server runs and need to be synced to changes
at the filter.
"""

from threading import Thread
import socket
from classes import *
import functools
import sys
sys.path.append(r'.')
i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *
sys.stdin, sys.stdout, sys.stderr = i, o, e


MAX_PACKET = 1024
HTTP_STRING = 'http'
UDP_STRING = 'udp'
TCP_STRING = 'tcp'
DHCP_STRING = 'dhcp'
ETHER_STRING = 'ether'
UNKNOWN_PROTOCOL = 'unknown'
MY_IP = socket.gethostbyname_ex(socket.gethostname())[MINUS_ONE][MINUS_ONE]
LIST_OF_PACKETS = []

def send_packet_organize(packet_to_print):
    """
    return a string of packet with the protocols and with the send protocol
    """
    temp_string = packet_to_print.printable()
    temp_and_protocol = MY_IP + PROTOCOL_SEND_LEN + temp_string
    string_to_send = str(len(str(len(temp_and_protocol)))) +\
        str(len(temp_and_protocol)) + temp_and_protocol
    return string_to_send


def filter_packets(filter_numbers, packet_to_check):
    """
    the most important function in the agent
    filter_numbers : is the string that represents
    the filter that the agent needs to sniff by
    packet_to_check : the packet that sniffed
    the function checks if the packet answers on the requirement of the filter
    the filter can be some filters combined
    if the function returns true the packet answers to the filter
    else, if false, it doesnt
    """
    if filter_numbers == COMMA_STRING:
        return True
    condition_to_return = True
    list_of_filters_and_kinds = filter_numbers.split(COMMA_STRING)
    list_of_filters = list_of_filters_and_kinds[ONE_NUMBER::TWO_NUMBER]
    list_of_kinds = list_of_filters_and_kinds[::TWO_NUMBER]
    for cur_filter_index in xrange(len(list_of_filters)):
        cur_filter = list_of_filters[cur_filter_index]
        filter_id = cur_filter[ZERO_NUMBER]
        cond_temp = True
        if filter_id == ONE_STR:
            ip_kind = cur_filter[ONE_NUMBER]
            if ip_kind == ONE_STR:
                cond_temp = IP in packet_to_check and\
                    packet_to_check[IP].dst == cur_filter[TWO_NUMBER:]
            elif ip_kind == TWO_STR:
                cond_temp = IP in packet_to_check and\
                    packet_to_check[IP].src == cur_filter[TWO_NUMBER:]
            elif ip_kind == THREE_STR:
                cond_temp = IP in packet_to_check and\
                    packet_to_check[IP].src == cur_filter[TWO_NUMBER:] and\
                    packet_to_check[IP].dst == cur_filter[TWO_NUMBER:]
            else:
                cond_temp = IP in packet_to_check and\
                    (packet_to_check[IP].src == cur_filter[TWO_NUMBER:] or
                     packet_to_check[IP].dst == cur_filter[TWO_NUMBER:])
        elif filter_id == TWO_STR:
            asked_protocol = cur_filter[1:]
            if asked_protocol == PROTOCOLS_LIST[ARP_INDEX]:
                cond_temp = ARP in packet_to_check
            elif asked_protocol == PROTOCOLS_LIST[ETHER_INDEX]:
                cond_temp = Ether in packet_to_check
            elif asked_protocol == PROTOCOLS_LIST[UDP_INDEX]:
                cond_temp = UDP in packet_to_check
            elif asked_protocol == PROTOCOLS_LIST[TCP_INDEX]:
                cond_temp = TCP in packet_to_check
            elif asked_protocol == PROTOCOLS_LIST[ICMP_INDEX]:
                cond_temp = ICMP in packet_to_check
            elif asked_protocol == PROTOCOLS_LIST[RAW_INDEX]:
                cond_temp = Raw in packet_to_check
            elif asked_protocol == PROTOCOLS_LIST[IP_INDEX]:
                cond_temp = IP in packet_to_check
            elif asked_protocol == PROTOCOLS_LIST[HTTP_INDEX]:
                if Raw in packet_to_check:
                    cond_temp = Raw in packet_to_check
                    if cond_temp:
                        cond_temp = False
                    for http_exp in HTTP_VERBS_AND_CONSTS:
                        if http_exp in packet_to_check[Raw].load:
                            cond_temp = True
                else:
                    cond_temp = False
            else:
                return False
        elif filter_id == THREE_STR:
            port_to_filter = cur_filter[ONE_NUMBER:MINUS_ONE]
            if port_to_filter in SPECIAL_PORTS_CHANGE_NAME.keys():
                port_to_filter = SPECIAL_PORTS_CHANGE_NAME[port_to_filter]
            else:
                port_to_filter = [port_to_filter]
            port_kind = cur_filter[MINUS_ONE]
            scapy_packet_parts_list = []
            for a in packet_to_check:
                scapy_packet_parts_list.append(a)
            string_of_packet = str(scapy_packet_parts_list)
            if port_kind == ONE_STR:
                if SPORT_STR in string_of_packet:
                    sport_of_packet = string_of_packet.split('sport=')[
                        ONE_NUMBER].split(BLANK_STR)[ZERO_NUMBER]
                    cond_temp = sport_of_packet in port_to_filter
                else:
                    return False
            elif port_kind == TWO_STR:
                if DPORT_STR in string_of_packet:
                    dport_of_packet = string_of_packet.split('dport=')[
                        ONE_NUMBER].split(BLANK_STR)[ZERO_NUMBER]
                    cond_temp = dport_of_packet in port_to_filter
                else:
                    return False
            else:
                if DPORT_STR not in string_of_packet and SPORT_STR not in\
                        string_of_packet:
                    return False
                else:
                    dport_of_packet = MINUS_ONE
                    sport_of_packet = MINUS_ONE
                    if DPORT_STR in string_of_packet:
                        dport_of_packet =\
                            string_of_packet.split('dport=')[
                                ONE_NUMBER].split(' ')[ZERO_NUMBER]
                    elif SPORT_STR in string_of_packet:
                        sport_of_packet =\
                            string_of_packet.split('sport=')[
                                ONE_NUMBER].split(' ')[ZERO_NUMBER]
                    if port_kind == THREE_STR:
                        cond_temp = dport_of_packet in port_to_filter and\
                                    sport_of_packet in port_to_filter
                    else:
                        cond_temp = dport_of_packet in port_to_filter or\
                                    sport_of_packet in port_to_filter
        if list_of_kinds[cur_filter_index] == ONE_STR:
            condition_to_return = condition_to_return and cond_temp
        else:
            if list_of_kinds[cur_filter_index] == EMPTY_STR:
                return False
            condition_to_return = condition_to_return or cond_temp
    return condition_to_return


def sniffing_thread(socket_send):
    """
    the thread who is responsible for the sniffing
    while the program is running
    """
    while TERM_OBJ.get_term() is False:
        try:
            list_of_packet_to_send = sniff(count=ONE_NUMBER,
                                           lfilter=functools.
                                           partial(filter_packets,
                                                   TERM_OBJ.get_filter()),
                                           prn=functools.partial(
                                               prn_of_packet, socket_send),
                                           timeout=1)
            if len(list_of_packet_to_send) != ZERO_NUMBER:
                if len(TERM_OBJ.get_packet_list()) == MAX_PACKETS_TO_STORAGE:
                    TERM_OBJ.clear_list()
                TERM_OBJ.add_packet(list_of_packet_to_send[ZERO_NUMBER])
        except:
            pass


def prn_of_packet(socket_send, cur_packet):
    """
    if the packet answers to the filter it is sent to the server.
    the function arrangements the packet
    socket_send - the socket that the packet should be sent
    """
    try:
        scapy_packet_parts_list = []
        for a in cur_packet:
            scapy_packet_parts_list.append(a)
        string_of_packet = str(scapy_packet_parts_list)
        layers_num = len(string_of_packet.split(END_PACKET_SIGN))
        temp_packet = PacketClass(layers_num)
        temp_packet.parse(string_of_packet)
        LIST_OF_PACKETS.append(temp_packet)
        string_of_packet_to_send = send_packet_organize(temp_packet)
        try:
            socket_send.send(string_of_packet_to_send)
        except socket.error as msg:
            if str(msg) == CLOSED_ERROR:
                socket_send.close()
                TERM_OBJ.set_term(True)
    except:
        pass

TERM_OBJ = ThreadHandle(False)
ENTER_SERVER_IP = 'enter the server ip'
WRONG_IP = 'wrong ip'

def main():
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip_of_server = raw_input(ENTER_SERVER_IP)
    while ip_is_valid(ip_of_server) is False:
        print WRONG_IP
        ip_of_server = raw_input(ENTER_SERVER_IP)
    try:
        my_socket.connect((ip_of_server, 5566))
        len_of_len = my_socket.recv(ONE_NUMBER)
        len_of_filter = my_socket.recv(int(len_of_len))
        filter_numbers = my_socket.recv(int(len_of_filter))
        TERM_OBJ.set_filter(filter_numbers)
        a = Thread(target=sniffing_thread, args=(my_socket,))
        a.start()
        my_socket.settimeout(HALF_SECOND_TIMEOUT)
        packet_to_work = EMPTY_STR
        while packet_to_work != STOP_MSG or TERM_OBJ.get_term() is True:
            try:
                len_of_len = my_socket.recv(ONE_NUMBER)
                if len_of_len != EMPTY_STR and len_of_len is not None:
                    len_of_filter = my_socket.recv(int(len_of_len))
                    filter_to_activate = my_socket.recv(int(len_of_filter))
                    TERM_OBJ.set_filter(filter_to_activate)
            except socket.error as msg:

                if FILE_ERROR in str(msg):
                    TERM_OBJ.set_term(True)
                    break
            time.sleep(0.08)
    except socket.error as err:
        pass
    finally:
        TERM_OBJ.set_term(True)
        my_socket.close()


if __name__ == '__main__':
    main()
