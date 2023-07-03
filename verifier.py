import socket, os
import json
import logging
from threading import Thread

import utils
import constants

logging.basicConfig(filename='verifier-logs.log', encoding='utf-8', level=logging.DEBUG)


class SocketListener(Thread):
    def __init__(self, host_IP, host_port, dest_IP, dest_port):
        super().__init__()
        self.host_IP = host_IP
        self.host_port = host_port
        self.dest_IP = dest_IP
        self.dest_port = dest_port

        self.p_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a socket object
        self.p_socket.bind((host_IP, host_port))  # Bind to the port

        self.c_socket = None
        self.s_socket = None
        self.counter = 0
        self.drop_mode = constants.DROP_MODES[2] # none

    def rcv_client(self):

        """
        Receive data from the client.
        """
        # self.c_socket.settimeout(1.0)   
        try:
            msg = self.s_socket.recv(constants.TLS_RECORD_SIZE_LIMIT)
            logging.debug(utils.prep_log_msg(msg, prefix='Rcvd client: '))
        except Exception as e: # timeout
            msg = None

        # self.c_socket.settimeout(None)
            
        return msg
    
    
    def rcv_server(self):
            
            """
            Receive data from the server.

            """

            # self.s_socket.settimeout(1.0)   
            try:
                msg = self.s_socket.recv(constants.TLS_RECORD_SIZE_LIMIT)
                logging.debug(utils.prep_log_msg(msg, prefix='Rcvd server: '))
            except Exception as e: # timeout
                msg = None
                
            # self.s_socket.settimeout(None)

            return msg
    
    def send_msg(self, msg, socket):
        """
        Send data to the client.

        :param msg:
            a string to send to the client
        :param socket:
            the socket over which the message is sent

        """

        socket.send(msg)

        
    def run(self):
        """
            Listen for incoming connections from the client.
        """
       
        while True:
            # Now wait for client connection.
            self.p_socket.listen()
            logging.info(utils.prep_log_msg(f"Listening at {host_IP} port {host_port}"))

            # Establish connection with client.
            try:
                self.c_socket, addr = self.p_socket.accept()
                logging.info(utils.prep_log_msg(f"Got connection from {addr}"))

            except Exception as e:
                logging.critical(utils.prep_log_msg('Failed connection with server with error: {e.__str__()}'))
                exit(1)
            
            # connect to the destination server
            try:
                socket.create_connection((dest_IP, dest_port))
                logging.info(utils.prep_log_msg(f"Connected to {dest_IP} port {dest_port}"))
            
            except Exception as e:
                logging.critical(utils.prep_log_msg(f'Failed connection with server with error: {e.__str__()}'))

            def fwding():                    
                while True:
                    c_stream = self.rcv_client()
                    # TODO: Put a counter on number of packets
                    
                    # check drop mode:
                    def check_drop_mode(stream):
                        drop_mode = False
                        if constants.bDROP_MSG_BEGIN in stream:
                            logging.debug(utils.prep_log_msg('Drop mode activated'))
                            drop_mode = constants.DROP_MODES[0] # drop

                        elif constants.bDROP_MSG_END in stream:
                            logging.debug(utils.prep_log_msg('Drop mode deactivated'))
                            drop_mode = constants.DROP_MODES[1] # done
                        
                        return drop_mode
                    
                    self.drop_mode = check_drop_mode(c_stream)

                    # remove drop identifiers from stream
                    if self.drop_mode == constants.DROP_MODES[0]:
                        c_stream = c_stream.replace(constants.bDROP_MSG_BEGIN, b'')

                    elif self.drop_mode == constants.DROP_MODES[1]:
                        c_stream = c_stream.replace(constants.bDROP_MSG_END, b'')
                        
                    if self.drop_mode == constants.DROP_MODES[2]:
                        self.send_msg(c_stream, self.s_socket)
                    
                    elif self.drop_mode == constants.DROP_MODES[0]:
                       challenges =  

                    logging.debug(utils.prep_log_msg('Client done sending'))

                    s_stream = b""
                    msg = self.rcv_server()
                    while msg:
                        s_stream += msg
                        msg = self.rcv_server()

                    self.send_msg(s_stream, self.c_socket)
                
                    logging.debug(utils.prep_log_msg('Server done sending'))

                    if not c_stream and not s_stream:
                        self.counter += 1

                    # breaks the loop when both the client and server are done sending
                    if self.counter == 2:
                        break

            # start forwarding
            fwding()
            self.c_socket.close()
            # dest socket closes automatically

if __name__ == '__main__':
    config = None

    # read config file
    try:
        with open('inputs-proxy.json') as f:
            inputs = json.load(f)

    except Exception as e:
        logging.critical(utils.prep_log_msg(e.__str__()))
        exit(1)
    
    verifier = inputs['verifier']
    prover = inputs['prover']

    host_IP = verifier['ip']
    host_port = verifier['port']
    dest_IP = prover['email_server']['host']
    dest_port = prover['email_server']['port']

    pid = os.getpid()
    sl = SocketListener(
        host_IP=host_IP,
        host_port=host_port,
        dest_IP=dest_IP,
        dest_port=dest_port
    )
    sl.start()

    input('Socket is listening, press any key to abort...')
    os.kill(pid, 9)