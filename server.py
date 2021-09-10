"""
fin
FINAL with pep 8
the sever is the user.
responsible for the screen and the filter, to show the packets
and store them
"""
from classes import *
import socket
import sys
from threading import Thread
i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *
sys.stdin, sys.stdout, sys.stderr = i, o, e
from PySide import QtCore
MAIN_WINDOW_TEXT = 'main window'
CLIENTS_SOCKETS = []
CLIENT_HANDLE = {}
"""
CLIENT_HANDLE : {IP:[thread,term,list_packets, last_len]
"""
FILTER_NUMBER_STR = 'filter number : '
IP_FILTER_STR = 'filter by ip address:'
IP_LABEL = 'enter ip address: '
IP_TYPE_STR = 'ip type:'
PROTOCOLS_STR_FILTER = 'filter by protocol:'
PORT_LABEL_STR = 'filter by port:'
PORT_INPUT_REQUEST = 'enter port number: '
PORT_TYPE_LABEL = 'port type:'
JUMP_DIFFERENCE = 150
START_TAB_NUMBER = 100
PUSH_BUTTON_TEXT = 'apply all filters'
FILTER_WINDOW_TEXT = 'filter window'


def organize_filter_send(string_of_filter):
    """
    the function takes the string and return the
    string by protocol to send the filter string or stop massage
    """
    return str(len(str(len(string_of_filter)))) +\
        str(len(string_of_filter)) + string_of_filter


def agent_thread(agent_client_socket, filter_string_to_send, my_ip):
    """
    for every agent that connects to the server has a thread that receive
    the packets and store them in the list of packet of every agent
    """
    agent_client_socket.send(organize_filter_send(filter_string_to_send))
    packet_to_work = EMPTY_STR
    while CLIENT_HANDLE[my_ip][TEMP_RUN_IND] is False:
        try:
            len_of_len = agent_client_socket.recv(1)
            if len_of_len != EMPTY_STR:
                len_of_packet = agent_client_socket.recv(int(len_of_len))
                packet_to_work = agent_client_socket.recv(int(len_of_packet))
                handle_clients_packet(packet_to_work)
        except socket.error as err:
            if CLOSED_ERROR in str(err):
                del CLIENT_HANDLE[my_ip]
                VARS_TO_AFTER_FUNC[MAIN_WIDGET_INDEX].update_main_list()
                break


def handle_clients_packet(packet_received):
    """
    helps to the agent thread to store packets
    restart the list packet if it gets too many packets
    """
    ip_of_sender = packet_received.split(PROTOCOL_SEND_LEN)[ZERO_NUMBER]
    packet_to_save = packet_received.split(PROTOCOL_SEND_LEN)[ONE_NUMBER]
    if len(CLIENT_HANDLE[ip_of_sender][TWO_NUMBER]) == MAX_PACKETS_TO_STORAGE:
        CLIENT_HANDLE[ip_of_sender][LIST_PACKETS_INDEX] = []
    CLIENT_HANDLE[ip_of_sender][LIST_PACKETS_INDEX].append(packet_to_save)


def show_packet_prn(packet_text_protocol):
    """
    organize the packet nicely to the user and he
    would see the specific packet very clear and understandable
    """
    list_of_packet_parts = packet_text_protocol.split(PROTOCOL_TEXT_SPLITER)
    string_final_packet = EMPTY_STR
    temp_num_is_protocol = ZERO_NUMBER
    for packet_part in list_of_packet_parts:
        string_final_packet += packet_part
        if temp_num_is_protocol == ZERO_NUMBER:
            string_final_packet += TWO_DOTS_STR
            temp_num_is_protocol = ONE_NUMBER
        else:
            temp_num_is_protocol = ZERO_NUMBER
            string_final_packet += DOWN_RAW
        string_final_packet += DOWN_RAW
    return string_final_packet


class MyQtList(QListWidget):
    """
    the widget on the screen of the lists
    the list is like the QListWidget of PySide but I changed the vars
    of the list and changed the close event (what happens when you press X)
    I used QTimer, it does a func every known period
    """
    def __init__(self, ip_text):
        super(MyQtList, self).__init__()
        self.resize(500, 500)
        self.ip_text = ip_text
        self.my_timer = QtCore.QTimer()
        CLIENT_HANDLE[self.ip_text][THREE_NUMBER] = ZERO_NUMBER
        self.my_timer.timeout.connect(self.show_list)
        self.my_timer.start(100)
        self.clear_timer = QtCore.QTimer()
        self.clear_timer.timeout.connect(self.clear_all_list)
        self.clear_timer.start(60000)
        self.mes_box = QMessageBox()
        self.mes_box.setModal(False)
        self.itemClicked.connect(self.show_spec_packet)

    def show_spec_packet(self, item):
        """
        show clicked packet in a clear way
        """
        self.mes_box.setText(show_packet_prn(item.text()))
        self.mes_box.show()

    def clear_all_list(self):
        """
        clear the list
        """
        self.clear()

    def closeEvent(self, event):
        """
        the function is done when the user closed the QListWidget
        """
        main_widget = VARS_TO_AFTER_FUNC[MAIN_WIDGET_INDEX]
        for temp_window in main_widget.get_dialog_keeper():
            if temp_window.get_item().text() == self.ip_text:
                main_widget.get_dialog_keeper().remove(temp_window)
        event.accept()
        try:
            CLIENT_HANDLE[self.ip_text][LAST_PACKER_INDEX] = ZERO_NUMBER
        except:
            pass

    def show_list(self):
        """
        the function is updating the list on the screen
        """
        try:
            temp_len = CLIENT_HANDLE[self.ip_text][LAST_PACKER_INDEX]
            if CLIENT_HANDLE[self.ip_text][TEMP_RUN_IND] is False:
                len_of_packet_list =\
                    len(CLIENT_HANDLE[self.ip_text][LIST_PACKETS_INDEX])
                if (temp_len + TEN) < len_of_packet_list:
                    last_index = temp_len + TEN
                else:
                    last_index = len_of_packet_list
                for temp_index in xrange(temp_len, last_index):
                    self.addItem(CLIENT_HANDLE[
                        self.ip_text][LIST_PACKETS_INDEX][
                            temp_index].split(END_PACKET_SIGN)[ZERO_NUMBER])
                CLIENT_HANDLE[self.ip_text][LAST_PACKER_INDEX] = last_index
            self.removeItemWidget(self.item)
        except:
            pass


class DialogAndItem():
    """
    the class makes one var that contain the
    dialog (the list on the screen) and his data, like his ip
    dialog_keep - the widget on the screen
    item_keep - the information of the widget
    """
    def __init__(self, dialog_var, item_var):
        self.dialog_keep = dialog_var
        self.item_keep = item_var

    def get_dialog(self):
        """
        returns the dialog
        """
        return self.dialog_keep

    def get_item(self):
        """
        returns the information
        """
        return self.item_keep


def port_is_valid(port_to_check):
    """
    checking if the port that the user chose is valid and right
    """
    try:
        port_keep = int(port_to_check)
    except ValueError:
        return False
    if (port_keep > ZERO_NUMBER) and (port_keep < BIGGEST_PORT):
        return True
    return False


class FilterClass():
    """
    the class of one of the filters on the screen on the widget of the filter
    var_height - how to move the first var of every filter in height
    var_width - how to move the first var of every filter in width
    """
    def __init__(self, var_height, var_width,
                 filter_screen_var, number_filter):
        self.number_filter = number_filter
        self.combofilter = QComboBox(filter_screen_var)
        self.filter_lable = QLabel(filter_screen_var)
        self.filter_lable.setGeometry(ZERO_NUMBER,
                                      ZERO_NUMBER + var_width, 100, 10)
        self.filter_lable.setText(FILTER_NUMBER_STR + str(number_filter))
        self.filter_lable.show()
        self.combofilter.setGeometry(ZERO_NUMBER + var_height,
                                     20 + var_width, 150, 40)
        self.combofilter.addItems(FILTERS_LIST)
        self.ip_address_label = QLabel(filter_screen_var)
        self.ip_address_label.setGeometry(ZERO_NUMBER + var_height,
                                          60 + var_width, 100, 15)
        self.ip_address_label.setText(IP_FILTER_STR)
        self.line_edit_ip = QLineEdit(filter_screen_var)
        self.line_edit_ip.setGeometry(190 + var_height,
                                      60 + var_width, 100, 20)
        self.enter_ip_addr = QLabel(filter_screen_var)
        self.enter_ip_addr.setGeometry(100 + var_height,
                                       60 + var_width, 80, 15)
        self.enter_ip_addr.setText(IP_LABEL)
        self.combo_ip_type = QComboBox(filter_screen_var)
        self.type_ip_label = QLabel(filter_screen_var)
        self.type_ip_label.setGeometry(300 + var_height,
                                       60 + var_width, 50, 20)
        self.type_ip_label.setText(IP_TYPE_STR)
        self.combo_ip_type.setGeometry(350 + var_height,
                                       60 + var_width, 100, 20)
        self.combo_ip_type.addItems(IP_TYPES_LIST)
        self.protocol_label = QLabel(filter_screen_var)
        self.protocol_label.setGeometry(ZERO_NUMBER + var_height,
                                        85 + var_width, 90, 15)
        self.protocol_label.setText(PROTOCOLS_STR_FILTER)
        self.protocols_list_combo = QComboBox(filter_screen_var)
        self.protocols_list_combo.setGeometry(100 + var_height,
                                              80 + var_width, 80, 20)
        self.protocols_list_combo.addItems(PROTOCOLS_LIST)
        self.port_label = QLabel(filter_screen_var)
        self.port_label.setGeometry(0 + var_height, 100 + var_width, 90, 20)
        self.port_label.setText(PORT_LABEL_STR)
        self.line_edit_port = QLineEdit(filter_screen_var)
        self.line_edit_port.setGeometry(210 + var_height, 100 + var_width,
                                        100, 20)
        self.enter_port_number = QLabel(filter_screen_var)
        self.enter_port_number.setGeometry(100 + var_height, 100 + var_width,
                                           100, 20)
        self.enter_port_number.setText(PORT_INPUT_REQUEST)
        self.combo_port_type = QComboBox(filter_screen_var)
        self.type_port_label = QLabel(filter_screen_var)
        self.type_port_label.setGeometry(350 + var_height,
                                         100 + var_width, 50, 20)
        self.type_port_label.setText(PORT_TYPE_LABEL)
        self.combo_port_type.setGeometry(400 + var_height,
                                         100 + var_width, 100, 20)
        self.combo_port_type.addItems(PORT_TYPES_LIST)

    def one_filter_parse(self):
        """
        make one filter to string
        """
        filter_string = EMPTY_STR
        chosen_filter = self.combofilter.currentText()
        if chosen_filter == FILTERS_LIST[NO_FILTER_INDEX]:
            return filter_string
        elif chosen_filter == FILTERS_LIST[IP_FILTER_INDEX]:
            ip_selected = self.line_edit_ip.text()
            if ip_is_valid(ip_selected) is False:
                return filter_string
            filter_string += str(IP_FILTER_INDEX)
            filter_string +=\
                str(self.combo_ip_type.currentIndex() + ONE_NUMBER)
            filter_string += ip_selected
        elif chosen_filter == FILTERS_LIST[PROTOCOL_INDEX]:
            filter_string += str(PROTOCOL_INDEX)
            filter_string += self.protocols_list_combo.currentText()
        else:
            port_keeper = self.line_edit_port.text()
            if port_is_valid(port_keeper) is False:
                return filter_string
            filter_string += str(PORT_INDEX)
            filter_string += port_keeper
            filter_string +=\
                str(self.combo_port_type.currentIndex() + ONE_NUMBER)
        return filter_string


class FilterWidget(QWidget):
    """
    the widget of the filter on screen
    """
    def __init__(self):
        super(FilterWidget, self).__init__()
        self.resize(700, 800)
        self.filters_on_screen_list = []
        self.filters_on_screen_list.append(FilterClass(START_TAB_NUMBER,
                                                       ZERO_NUMBER, self,
                                                       ONE_NUMBER))
        self.filters_on_screen_list.append(FilterClass(START_TAB_NUMBER,
                                                       JUMP_DIFFERENCE,
                                                       self, TWO_NUMBER))
        self.filters_on_screen_list.append(FilterClass(
            START_TAB_NUMBER,
            TWO_NUMBER*JUMP_DIFFERENCE,
            self, THREE_NUMBER))
        self.filters_on_screen_list.append(FilterClass(
            START_TAB_NUMBER,
            THREE_NUMBER*JUMP_DIFFERENCE, self, FOUR_NUMBER))
        self.filters_on_screen_list.append(FilterClass(
            START_TAB_NUMBER,
            FOUR_NUMBER*JUMP_DIFFERENCE, self, FIVE_NUMBER))
        self.setWindowTitle(FILTER_WINDOW_TEXT)
        self.apply_btn = QPushButton(self)
        self.apply_btn.setText(PUSH_BUTTON_TEXT)
        self.apply_btn.clicked.connect(self.set_filter)
        self.apply_btn.setGeometry(600, 400, 100, 100)
        self.and_or_list = []
        temp_label = QLabel(self)
        temp_label.setGeometry(90, 755, 100, 10)
        temp_label.setText('filter 1')
        for temp_jump_dif in xrange(1, 5, 1):
            temp_combo = QComboBox(self)
            temp_combo.setGeometry(125*temp_jump_dif, 750, 50, 20)
            temp_combo.addItems([AND_STR, OR_STR])
            self.and_or_list.append(temp_combo)
            temp_label = QLabel(self)
            temp_label.setGeometry(75 + 125*temp_jump_dif, 755, 100, 10)
            temp_label.setText('filter ' + str(temp_jump_dif+1))

    def set_filter(self):
        """
        string the all filters and set it as the new filter
        """
        filter_list_of_string = []
        for temp_filter in self.filters_on_screen_list:
            filter_list_of_string.append(temp_filter.one_filter_parse())
        list_of_and_or = [AND_STR]
        for temp_and_or in self.and_or_list:
            list_of_and_or.append(temp_and_or.currentText())
        string_final = EMPTY_STR
        for temp_ind in xrange(len(list_of_and_or)):
            if filter_list_of_string[temp_ind] != EMPTY_STR:
                if list_of_and_or[temp_ind] == AND_STR:
                    string_final += ONE_COMMA_STR
                else:
                    string_final += TWO_COMMA_STR
                string_final += filter_list_of_string[temp_ind]
                string_final += COMMA_STRING

        if string_final == EMPTY_STR:
            string_final = COMMA_STRING
        else:
            string_final = string_final[:MINUS_ONE]
        if string_final != VARS_TO_AFTER_FUNC[FILTER_INDEX]:
            VARS_TO_AFTER_FUNC[FILTER_INDEX] = string_final
            try:
                for client_socket_temp in CLIENTS_SOCKETS:
                    client_socket_temp.send(organize_filter_send(string_final))
            except:
                pass
            VARS_TO_AFTER_FUNC[MAIN_WIDGET_INDEX].clear_all_lists()


class MainWidget(QMainWindow):
    """
    the screen of the main widget
    listwidget - the list of the connected agent's ip
    dialogkeeper - the widgets that open at the moment
    filter_window - the window of the filter
    """
    def __init__(self):
        self.listwidget = QListWidget()
        self.listwidget.setWindowTitle(MAIN_WINDOW_TEXT)
        self.listwidget.resize(QtCore.QSize(400, 400))
        self.listwidget.show()
        self.filter_window = FilterWidget()
        self.filter_window.show()
        self.dialogkeeper = []
        self.listwidget.itemClicked.connect(self.open_new)

    def get_main_list(self):
        """
        returns the list of the widgets
        """
        return self.listwidget

    def get_dialog_keeper(self):
        """
        returns the dialog keeper
        """
        return self.dialogkeeper

    def update_main_list(self):
        """
        clear the listwidget and update it to the connected agents
        """
        self.listwidget.clear()
        for client_ip in CLIENT_HANDLE.keys():
            self.listwidget.addItem(client_ip)

    def open_new(self, item):
        """
        open new dialog because item in listwidget was selcted
        """
        availability_check = True
        for var_temp in self.dialogkeeper:
            if var_temp.get_item().text() == item.text():
                availability_check = False
        if availability_check is True:
            newdialog = MyQtList(item.text())
            newdialog.setWindowTitle(item.text())
            newdialog.show()
            temp_var = DialogAndItem(newdialog, item)
            self.dialogkeeper.append(temp_var)

    def clear_all_lists(self):
        """
        clear the lists
        """
        for temp_item_list in self.dialogkeeper:
            temp_item_list.get_dialog().clear_all_list()


VARS_TO_AFTER_FUNC = []
# vars_to_after_func = [server socket, the main window widget, current filter


def accept_function_and_thread():
    """
    getting agents
    """
    try:
        my_socket = VARS_TO_AFTER_FUNC[ZERO_NUMBER]
        main_widget = VARS_TO_AFTER_FUNC[ONE_NUMBER]
        filters_string_to_send = VARS_TO_AFTER_FUNC[TWO_NUMBER]
        client_socket, client_address = my_socket.accept()
        ip_of_client = client_address[ZERO_NUMBER]
        if ip_of_client == '127.0.0.1':
            ip_of_client =\
                socket.gethostbyname_ex(
                    socket.gethostname())[MINUS_ONE][MINUS_ONE]
        client_socket.settimeout(HALF_SECOND_TIMEOUT)
        thread_of_agent = Thread(target=agent_thread,
                                 args=(client_socket,
                                       filters_string_to_send,
                                       ip_of_client,))
        thread_of_agent.start()
        CLIENT_HANDLE[ip_of_client] = [thread_of_agent,
                                       False, [], ZERO_NUMBER]
        main_widget.update_main_list()
        CLIENTS_SOCKETS.append(client_socket)
    except:
        pass


def main():
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        app = QApplication(sys.argv)
        my_socket.bind((LISTEN_ON_EVERY_NAME_IP, 5566))
        my_socket.listen(QUEUE_LEN)
        main_widget = MainWidget()
        my_socket.settimeout(0.1)
        VARS_TO_AFTER_FUNC.append(my_socket)
        VARS_TO_AFTER_FUNC.append(main_widget)
        VARS_TO_AFTER_FUNC.append(EMPTY_STR)
        qtimer = QtCore.QTimer()
        qtimer.timeout.connect(accept_function_and_thread)
        qtimer.start(1000)
        app.exec_()
        for key_of_d in CLIENT_HANDLE.keys():
            CLIENT_HANDLE[key_of_d][TEMP_RUN_IND] = True
        for client_socket in CLIENTS_SOCKETS:
            client_socket.send(str(len(str(len(STOP_MSG)))) +
                               str(len(STOP_MSG)) + STOP_MSG)
            client_socket.close()
    except:
        pass

if __name__ == '__main__':
    main()
