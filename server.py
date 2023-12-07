import time
from _thread import *
import socket
from socket import *
from struct import *
import _thread
from encryption_util import decrypt

list_lock = _thread.allocate_lock()
user_list = {}
room_user_info = {}
port_list = {}
port_host = 8080
secure_messages={}
stored_messages = {}
max_users = 2


def join_procedure(conn_h, room, user_name):
    if room not in room_user_info:
        room_user_info[room] = [user_name]
        conn_h.send(b'\nYou have joined a Newly created Room ' + room.encode())
    else:
        for member in room_user_info[room]:
            msg = '\nUser ' + user_name + ' joined room ' + room + '\n' + member + ': '
            send_msg(msg, member)
        room_user_info[room].append(user_name)
        conn_h.send(b'\nYou have joined an Existing Room ' + room.encode())

    print(room_user_info)


def chat_procedure(room, user, message):
    msg = '\n' + user + ' in ' + room + ' says: ' + message 
    room = room_user_info[room][:]
    room.remove(user)
    for member in room:
        send_msg(msg + '\n' + member + ': ', member)
    return


def list_procedure(conn_h, List):
    List = str(list(List))
    conn_h.send(pack('L', len(List)))
    conn_h.send(bytes(List, 'utf-8'))
    return
    

def send_msg(msg, member):
    m_socket = get_temp_socket( user_list[member])
    try:
        m_socket.send(bytes(msg, 'utf-8'))
    except ConnectionError:
        exception_handle(user_list[member])
    if msg.split(' ')[0] == 'secure-msg':
        return m_socket
    m_socket.close()
    return


def exit_procedure(room, user_name):
    room_user_info[room].remove(user_name)
    if len(room_user_info[room]) == 0:
        del room_user_info[room]
    else:
        for member in room_user_info[room]:
            msg = '\nUser ' + user_name + ' left room ' + room + '\n' + member + ': '
            send_msg(msg, member)
    print(room_user_info)
    return


def get_temp_socket(temp_port):
    sock = socket()
    try:
        sock.connect((gethostname(), temp_port))
    except ConnectionError:
        exception_handle(temp_port)
    return sock


def process_secure_message(sender, password, recipient, encrypted_message):
    stored_messages[recipient] = (password, encrypted_message)
    if recipient in user_list:
        send_msg(f"Secure message sent to {recipient} succesfully.\n{sender}: ", sender)
        send_msg(f"You have a secure message from {sender}. Use 'recover-msg <password>' to read. \n{recipient}: ", recipient)
    else:
        send_msg(f"User {recipient} not found or not connected.\n{sender}:")
    

def handle_recover_msg(recipient, upassword):
    if recipient in stored_messages:
        password, encrypted_message = stored_messages.pop(recipient)
        if upassword == password:  
            decrypted_message = decrypt(encrypted_message)
            msg = f"Secure message: {decrypted_message}" + "\n" + recipient +":"
            send_msg(msg, recipient)   
        else:
            send_msg("Decryption failed: Invalid password.\n{recipient}:", recipient)
            stored_messages[recipient] = (password, encrypted_message )
    else:
        send_msg("No secure message found.\n{recipient}: ", recipient)


def quit_procedure(conn_h, user_name):
    conn_h.close()
    time.sleep(2)
    del_list = []
    for room_members in room_user_info.values():
        if user_name in room_members:
            room_members.remove(user_name)
    if user_name in user_list:
        del user_list[user_name]
    for user in user_list.keys():
        msg = '\nUser ' + user_name + ' Left IRC Server\n' + user + ': '
        send_msg(msg, user)
    for room, member_list in room_user_info.items():
        if len(member_list) == 0:
            del_list.append(room)
    for room in del_list:
        del room_user_info[room]
    return


def receive_file(conn_h, sender, room, file_name, file_size):
    with open(file_name, 'wb') as file:
        remaining = file_size
        while remaining:
            chunk_size = 1024 if remaining >= 1024 else remaining
            data = conn_h.recv(chunk_size)
            if not data:
                break
            file.write(data)
            remaining -= len(data)
    notification = f"New file {file_name} received in room {room}\n{sender}: "
    for member in room_user_info[room]:
        send_msg(notification, member)


def exception_handle(port_message):
    del_list = []
    user_name = port_list.get(port_message, None)
    if user_name:
        del port_list[port_message]
        for room, members in room_user_info.items():
            if user_name in members:
                members.remove(user_name)
                notify_msg = f'\nUser {user_name} has disconnected.\n'
                for member in members:
                    send_msg(notify_msg, member)

        if user_name in user_list:
            del user_list[user_name]

        for room, members in list(room_user_info.items()):
            if not members:
                del_list.append(room)
        for room in del_list:
            del room_user_info[room]
    return


def c_handler(conn_h, port_message):
    user_name = port_list[port_message]
    while True:
        try:
            argument = conn_h.recv(128).decode('ascii')
            argument = argument.split(' ')
        except (ConnectionError, EOFError) as e:
            print(f"Client {user_name} has crashed.")
            break
        except Exception as e:
            print(f"Error: {e}")
            break

        else:
            functionality = argument[0]

        if functionality == 'join-room':
            join_procedure(conn_h, argument[1], user_name)


        elif functionality == 'chat-room':
            try:
                message = conn_h.recv(448).decode('ascii')
            except ConnectionError:
                exception_handle(port_message)
                _thread.exit()
            else:
                chat_procedure(argument[1], user_name, message)

        elif functionality == 'pvt-msg':
            try:
                message = conn_h.recv(448).decode('ascii')
            except ConnectionError:
                exception_handle(port_message)
                _thread.exit()
            else:
                member = argument[1]
                if member not in user_list:
                    msg = '\nIRC_User_Error1: Username ' + member + ' not found\n{user_name}: '
                    send_msg(msg, user_name)
                else:
                    msg = 'Private message from ' + user_name + ' says: ' + message + '\n' + argument[1] + ':'
                    send_msg(msg, argument[1])


        elif functionality == 'list':
            if argument[1] == 'rooms':
                if len(room_user_info) == 0:
                    msg = '\nNo rooms to display\n'
                    send_msg(msg, user_name)
                list_procedure(conn_h, room_user_info.keys())
            elif argument[1] == 'users':
                list_procedure(conn_h, user_list.keys())
            elif argument[1] == 'members':
                if argument[2] not in room_user_info:
                    msg = '\nIrcArgumentError3: Room ' + argument[2] + ' not found\n' + argument[-1] + ': '
                    send_msg(msg, user_name)
                else:
                    list_procedure(conn_h, room_user_info[argument[2]])


        elif functionality == 'multiple-msg-room':
            for i in range(1, len(argument), 2):
                room = argument[i]
                message = argument[i + 1]
                if room in room_user_info:
                    chat_procedure(room, user_name, message)
                else:
                    error_msg = f"Error: Room '{room}' does not exist or you are not a member of it.\n{user_name}: "
                    send_msg(error_msg, user_name)
        

        elif functionality == 'send-file':
            try:
                room, file_name, file_size = argument[1], argument[2], int(argument[3])
                if room in room_user_info and user_name in room_user_info[room]:
                    receive_file(conn_h,user_name, room, file_name, file_size)
                else:
                    error_msg = f"Error: Room '{room}' does not exist or you are not a member of it.\n{user_name} "
                    send_msg(error_msg, user_name)
            except Exception as e:
                error_msg = f"Error processing file transfer: {str(e)}"
                send_msg(error_msg, user_name)

        
        elif functionality == 'secure-msg':
            if len(argument) < 3:
                send_msg("Invalid secure-msg command format.\n{user_name}:", user_name)
            else:
                password = argument[1]
                receiver = argument[2]
                encrypted_message = ' '.join(argument[3:])
                process_secure_message(user_name, password, receiver, encrypted_message)
                

        elif functionality == 'recover-msg':
            if len(argument) < 2:
                send_msg("Invalid recover-msg command format.\n{user_name}:", user_name)
            else:
                password = argument[1]
                handle_recover_msg(user_name, password)


        elif functionality == 'broadcast-msg':
            msg = user_name + ' says: ' + conn_h.recv(448).decode('ascii')
            for user in user_list.keys():
                if user != user_name:
                    send_msg(msg + '\n' + user + ': ', user)


        elif functionality == 'exit-room':
            exit_procedure(argument[1], user_name)


        elif functionality == 'quit-irc':
            send_msg('\n Quiting out of the IRC Server\nHope you had fun Enjoying our IRC services!', user_name)
            quit_procedure(conn_h, user_name)
            break

    exception_handle(port_message)
    _thread.exit()
    


def start(h_socket, port_host):
    conn_h, addr_h = h_socket.accept()
    conn_h.send(b'\nWelcome to The Internet Relay Chat BY: Jathin, Piyush, Rasika')
    conn_h.send(b'\nENJOY THE IRC SERVICES')
    u_status = 'unregistered'
    global port_message
    active_users = len(user_list)
    while u_status == 'unregistered':
        try:
            reg_user = conn_h.recv(32).decode('ascii')
        except ConnectionError:
            _thread.exit()
        else:
            [user_stat, u_name] = reg_user.split(' ')
            if user_stat == 'register':
                list_lock.acquire()
                if u_name not in user_list:
                    user_list[u_name] = port_message 
                    list_lock.release()
                    port_list[port_message] = u_name
                    u_status = 'registered'
                    conn_h.send(bytes(u_status, 'utf-8'))
                    if(active_users >= max_users):
                        conn_h.send(b'\nThe room is full.')
                    else:
                        conn_h.send(b'\nYou Have Been Enrolled successfully!!')
                else:
                    list_lock.release()
                    conn_h.send(bytes(u_status, 'utf-8'))
                    conn_h.send(b'\nRegistration_Error: This Username is Already in use.\nPlease Enter  a Different UserName')
            elif user_stat != 'register':
                conn_h.send(b'\n Please Enter an UserName to Continue')
        if(active_users >= max_users):
            conn_h.send(b'\n  New users cannot be added')
            conn_h.close()
            return 
        print(user_list)
        c_handler(conn_h, port_message)

s_socket = socket()
s_socket.bind((gethostname(), 1234)) 
s_socket.listen() 
print('\nThe IRC Server is Active and Listening:... ')
while True:
    conn, addr = s_socket.accept() 
    conn.send(pack('L', port_host))
    port_message = port_host + 1 
    h_socket = socket()
    h_socket.bind((gethostname(), port_host))
    h_socket.listen()
    start_new_thread(start, (h_socket, port_host,))
    port_host += 5

