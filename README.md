# Python IRC Chat Application

## Introduction
This project is a Python-based IRC (Internet Relay Chat) client and server application. It allows users to communicate in real-time through various chat rooms, send private messages, transfer files, and more, ensuring secure communication with encryption.

## Prerequisites
Before you begin, ensure you have met the following requirements:
- Python 3.x installed on your system
- Basic understanding of network programming in Python

## Installation
To install the Python IRC Chat Application, follow these steps:
1. Clone the repository: git clone https://github.com/PiRaj1404/IRC.git
2. Navigate to the cloned directory: cd [project_folder]


## Usage
To use the Python IRC Chat Application, you need to start both the server and the client. 

### Starting the Server
python server.py

### Starting the Client
python client.py
python client2.py



### Commands
Here are some commands you can use in the IRC Chat Application:

- `join-room [room-name]`: Join a chat room. If a new room name is entered, it's created else the user joins the existing room
- `exit-room [room-name]`: Leave a chat room.
- `chat-room [room-name] [message]`: Send a message to a specific chat room.
- `pvt-msg [user] [message]`: Send a private message to a user.
- `list rooms`: List all chat rooms.
- `list members [room-name]`: List all members in a specific room.
- `secure-msg [password] [user] [message]`: Send a secure message to a user which is encrypted.
- `recover-msg [password]`: Recover the secure message.
- `multiple-msg-room [room1] [msg1] [room2] [msg2] ...`: Client can send mutliple messages to multiple rooms 
- `send-file [room-name] [file-path]`: Send a file to a chat room.
- `quit-irc`: Client can disconnect from server.
- `join-multiple-rooms [room1] [room2]...`: Client can join multiple rooms at once
- `broadcast-msg all [message]`: Broadcasting the message to all members at once
- `help`: get all commands

## Contributing
Contributions to this project are welcome! If you have a suggestion that would make this better, please fork the repo and create a pull request. Don't forget to give the project a star! Thanks again!
