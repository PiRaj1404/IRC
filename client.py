import os
import sys
import _thread
from _thread import *
import socket
from socket import *
from struct import *
import ast
from encryption_util import encrypt


room_list = []
user_name = ''
flag = True
error_count=0


def help():
    print("\nUse the Commands Below")
    print(" ")
    print("\n	join room					Usage: 	join-room [room-name]\n\n	leave room					Usage: 	exit-room [room-name]\n\n	chat room					Usage: 	chat-room [room-name] [message]\n\n	private message					Usage: 	pvt-msg [user] [message]\n\n	join multiple rooms				Usage: 	join-multiple-rooms [room1] [room2]...\n\n	list						Usage: 	list rooms / list members [room-name]\n\n	secure messaging				Usage: 	secure-msg [password] [user] [message]\n\n	decrypt message					Usage: 	recover-msg [password]\n\n	file transfer					Usage: 	send-file [room-name]\n\n	multiple message room				Usage: 	multiple-msg-room [room1] [message1] [room2] [message2]...\n\n	disconnect					Usage: 	quit-irc\n\n	broadcast-msg					Usage:	broadcast-msg all [message]\n\n	help						Usage:	help")


def m_procedure(h_socket, command):
	header = ' '.join(command[0:2])
	message = ' '.join(command[2:])
	if len(message) > 448:
		print('Message_Error2: Message size is bigger than the permitted size')
		if input('\nSend anyway ? Y/N') == ('N' or 'n'):
			return
	try:
		h_socket.send(bytes(header, 'utf-8'))
		h_socket.send(bytes(message, 'utf-8'))
	except ConnectionError:
		exception_handle(h_socket)
	else:
		return


def list_procedure(h_socket, command):
	try:
		h_socket.send(bytes(command, 'utf-8'))
		buff = h_socket.recv(4)
	except ConnectionError:
		exception_handle(h_socket)
	else:
		size = unpack('L', buff)[0]
	try:
		string = h_socket.recv(size).decode('ascii')
	except ConnectionError:
		exception_handle(h_socket)
	else:
		List = ast.literal_eval(string)
		print('\n\t'+command.split(' ')[1]+': ', str(List)[1:-1])
	return


def send_secure_message( password, user, message):
    encrypted_message = encrypt(message)  
    command = f"secure-msg {password} {user} {encrypted_message}"
    h_socket.send(command.encode())


def exception_handle(sock):
	print('The IRC Server is Not Responding')
	quit_procedure(sock)
	exit()


def quit_procedure(sock):
	sock.close()
	global flag
	flag = False
	return


def multiple_msg_room_procedure(h_socket, command):
    full_command = ' '.join(command)
    try:
        h_socket.send(bytes(full_command, 'utf-8'))
    except ConnectionError:
        exception_handle(h_socket)
    


def join_multiple_rooms_procedure(h_socket, command):
    rooms = command[1:]
    for room in rooms:
        if room in room_list:
            print(f'Already in room: {room}')
            continue
        if len(room) > 10:
            print(f'RoomName_Error4: The maximum length allowed for RoomName is 10 characters - {room}')
            continue
        try:
            h_socket.send(bytes(f'join-room {room}', 'utf-8'))
            response = h_socket.recv(64).decode('ascii')
            print(response)
            if 'successfully' in response: 
                room_list.append(room)
        except ConnectionError:
            exception_handle(h_socket)


def s_handler(h_socket,user_name):
	global error_count
	while True:
		enter_input = input('%s:\n' %(user_name))
		input_split = enter_input.split(' ')
		functionality = input_split[0]
		if functionality == 'join-room':
			if len(input_split) < 2 or len(input_split[1].strip()) == 0:
				print('Argument_Error1: Command have less no of arguments then intended \n Please type an valid command'+'\nUsage: join-room <room-name>')
			elif len(input_split) > 2:
				print('Argument_Error2: Command have more no of arguments then intended \n Please type an valid command'+'\nUsage: join-room <room-name>')
			elif len(input_split) == 2:
				if len(input_split[1]) > 10:
					print('RoomName_Error4: The maximum Length allowed for RoomName is only Ten Characters')
				else:
					if input_split[1] not in room_list:
						try:
							h_socket.send(bytes(enter_input, 'utf-8'))
							print(h_socket.recv(64).decode('ascii'))
						except ConnectionError:
							exception_handle(h_socket)
						else:
							room_list.append(input_split[1])
					else:
						print('Command_Error2: The command can only be executed once for the given set of Arguments')


		elif functionality == 'join-multiple-rooms':
			if len(input_split) < 2:
				print('Argument_Error1: Command have less no of arguments then intended \n Please type a valid command' + '\nUsage: join-multiple-room <room1> <room2> ...')
			else:
				join_multiple_rooms_procedure(h_socket, input_split)


		elif functionality == 'exit-room':
			if len(input_split) < 2:
				print('Argument_Error1: Command have less no of arguments then intended \n Please type an valid command'+'\nUsage: exit-room <room-name>')
			elif len(input_split) > 2:
				print('Argument_Error2: Command have more no of arguments then intended \n Please type an valid command'+'\nUsage: exit-room <room-name>')
			elif len(input_split) == 2:
				if input_split[1] in room_list:
					room_list.remove(input_split[1])
					try:
						h_socket.send(bytes(enter_input, 'utf-8'))
					except ConnectionError:
						exception_handle(h_socket)
				else:
					print('Command_Error1: Invalid command. \n Please type an valid command')

		
		elif functionality == 'chat-room':
			if len(input_split) < 3:
				print('Argument_Error1: Command have less no of arguments then intended \n Please type an valid command'+'\nUsage: chat-room <room-name> <your message here>')
			else:
				if input_split[1] in room_list:
					m_procedure(h_socket, input_split)
				else:
					print('Message_Error1: Unauthorized message\n You do not have the Authorization for sending this message'+'\nPlease join the room to send messages')

		
		elif functionality == 'pvt-msg':
			if len(input_split) < 3:
				print('Argument_Error1: Command have less no of arguments then intended \n Please type an valid command'+'\nUsage: pvt-msg <recipient-name> <your message here>')
			else:
				m_procedure(h_socket, input_split)


		elif functionality == 'list':
			if len(input_split) > 3:
				print('Argument_Error2: Command have more no of arguments then intended \n Please type an valid command' + '\nUsage: list rooms OR list members <room-name>')
			elif len(input_split) < 2:
				print('Argument_Error1: Command have less no of arguments then intended \n Please type an valid command' + '\nUsage: list rooms OR list members <room-name>')
			elif input_split[1] == 'members':
				if len(input_split) < 3:
					print('Argument_Error1: Command have less no of arguments then intended \n Please type an valid command' + '\nUsage: list members <room-name>')
				else:
					list_procedure(h_socket, enter_input)
			elif input_split[1] == 'rooms' :
				if len(input_split) > 2:
					print('Argument_Error2: Command have more no of arguments then intended \n Please type an valid command'  + '\nUsage: list rooms')
				else:
					list_procedure(h_socket, enter_input)
			else:
				print('Command_Error1: Invalid Command. \n Please type an valid command')


		elif functionality == 'broadcast-msg':
			if len(input_split) < 3:
				print('Argument_Error1: Command have less no of arguments then intended \n Please type an valid command' + '\nUsage: broadcast-msg all <your message here>')
			else:
				m_procedure(h_socket, input_split)

		
		elif functionality == 'multiple-msg-room':
			if len(input_split) < 3 or len(input_split) % 2 != 1:
				print("Command_Error: Invalid number of arguments. The command format should be: multiple-msg-room <room> <message> <room> <message>...")
			else:
				multiple_msg_room_procedure(h_socket, input_split)

		
		elif functionality == 'secure-msg':
			if len(input_split) < 4:
				print("Argument_Error1: Command have less no of arguments then intended \n Please type an valid command'+'\nUsage: secure-msg <password> <user> <message>")
			else:
				password= input_split[1]
				user = input_split[2]
				secure_message = ' '.join(input_split[3:])
				send_secure_message( password, user, secure_message)


		elif functionality == 'recover-msg':
			if len(input_split) < 2:
				print("Argument_Error1: Command have less no of arguments then intended \n Please type an valid command'+'\nUsage: recover-msg <password>")
			else:
				password = input_split[1]
				h_socket.send(f"recover-msg {password}".encode())


		elif functionality == 'send-file':
			if len(input_split) < 2:
				print("Argument_Error1: Command have less no of arguments then intended \n Please type an valid command'+'\nUsage: send-file <room-name>")
			else:
				file_path = r'C:\Users\Student\Downloads\test-28.json'

				file_name = os.path.abspath(file_path)
				file_size = os.path.getsize(file_path)

				h_socket.send(f"send-file {input_split[1]} {file_name} {file_size}".encode())

				with open(file_path, 'rb') as file:
					bytes_to_send = file.read(1024)
					while bytes_to_send:
						h_socket.send(bytes_to_send)
						bytes_to_send = file.read(1024)

				
		elif functionality == 'quit-irc':
			if len(input_split) > 1:
				print('Argument_Error2: Command have more no of arguments then intended \n Please type an valid command'+'\nUsage: quit-irc')
			else:
				try:
					h_socket.send(bytes(enter_input, 'utf-8'))
				except ConnectionError:
					exception_handle(h_socket)
				#else:
				#	quit_routine(h_socket)
				finally:
					sys.exit()

		elif functionality == 'help':
			if len(input_split) > 1:
				print('Argument_Error2: Command have more no of arguments then intended \n Please type an valid command' + '\nUsage: help')
			else:
				help()
		else:
			error_count=error_count+1
			if(error_count == 3):
				print('Invalid command entered. Client crashed')
				sys.exit(0)
			else:
				print('Command_Error1: Invalid Command. \n Please type an valid command')


def start(h_socket):
        print(h_socket.recv(64).decode('ascii'))
        print(" ")
        print(h_socket.recv(64).decode('ascii'))
        print(" ")
        global user_name
        user_status = 'unregistered'
        while user_status == 'unregistered':
                user_name = input('Enter your UserName: ')
                if len(user_name)==0:
                        print('\n Username_Error1: The Username Cannot Be Empty \n Please type an valid UserName Again')
                elif len(user_name.split(' ')) > 1:
                        print('\n Username_Error2: The Username should not contain any spaces \n Please type an valid UserName Again')
                elif len(user_name.split(' ')) < 1:
                        print('\nA Username_Error3: The Username cannot be empty \n Please type an valid UserName Again')
                elif len(user_name.split(' ')) == 1:
                        if len(user_name) > 10:
                                print('\n Username_Error4: The maximum length allowed for Username is only 10 characters \n Please type an valid UserName Again')
                        else:
                                try:
                                        h_socket.send(bytes('register '+user_name, 'utf-8'))
                                        user_status = h_socket.recv(12).decode('ascii')
                                        print(h_socket.recv(128).decode('ascii'))
                                except ConnectionError:
                                        exception_handle(h_socket)
        print('\nTo see the Instructions type \"help\" \n')
        s_handler(h_socket, user_name)


def m_handler(m_socket):
	global flag
	global user_name
	while flag:
		connection_m, address_m = m_socket.accept()
		try:
			message = connection_m.recv(512).decode('ascii')
			print(message)

		except ConnectionError:
			exception_handle(m_socket)
		else:
			connection_m.close()
	_thread.exit()
	

s_socket = socket()
try:
	s_socket.connect((gethostname(), 1234))
	buff = s_socket.recv(4)
except ConnectionError:
	exception_handle(s_socket)

port_host = unpack('L', buff)[0]

s_socket.close()

h_socket = socket()
try:
	h_socket.connect((gethostname(), port_host))
except ConnectionError:
	exception_handle(h_socket)

port_message = port_host + 1

m_socket = socket()
try:
	m_socket.bind((gethostname(), port_message))
	m_socket.listen()
except ConnectionError:
	exception_handle(h_socket)


start_new_thread(m_handler, (m_socket,))
start(h_socket)
