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
        try:
            msg = self.c_socket.recv(constants.TLS_RECORD_SIZE_LIMIT)
            logging.debug(utils.prep_log_msg(msg, prefix='Rcvd client: '))
        except Exception as e: # timeout
            logging.debug(utils.prep_log_msg(f'Timeout'))
            msg = None
                        
        return msg
    
    
    def rcv_server(self):
            
            """
            Receive data from the server.

            """

            try:
                msg = self.s_socket.recv(constants.TLS_RECORD_SIZE_LIMIT)
                logging.debug(utils.prep_log_msg(msg, prefix='Rcvd server: '))
            except Exception as e: # timeout
                msg = None
                
            return msg
    
    def send_msg(self, msg, socket):
        """
        Send data to the client.

        :param msg:
            a string to send to the client
        :param socket:
            the socket over which the message is sent

        """
        # fragment the message into chunks of size TLS_RECORD_SIZE_LIMIT
        # msg_chunks = [msg[i:i+constants.TLS_RECORD_SIZE_LIMIT] for i in range(0, len(msg), constants.TLS_RECORD_SIZE_LIMIT)]
        # for chunk in msg_chunks:
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
                self.s_socket = socket.create_connection((dest_IP, dest_port))
                logging.info(utils.prep_log_msg(f"Connected to {dest_IP} port {dest_port}"))
            
            except Exception as e:
                logging.critical(utils.prep_log_msg(f'Failed connection with server with error: {e.__str__()}'))

            self.c_socket.settimeout(constants.CLIENT_TIMEOUT)   
            self.s_socket.settimeout(constants.SERVER_TIMEOUT)  
            def fwding():                    
                while True:
                    def client():
                        msg = self.rcv_client()
                        c_stream = b"" 

                        if not msg:
                            return False
                        # TODO: Put a counter on number of packets

                        # check drop mode:
                        def get_drop_mode(msg):
                            drop_mode = constants.DROP_MODES[2] # "none"

                            if constants.bDROP_MSG_BEGIN in msg:
                                logging.debug(utils.prep_log_msg('Drop mode activated'))
                                drop_mode = constants.DROP_MODES[0] # "drop"

                            elif constants.bDROP_MSG_END in msg:
                                logging.debug(utils.prep_log_msg('Drop mode deactivated'))
                                drop_mode = constants.DROP_MODES[1] # "done"

                            # if drop_mode has been changed, return it
                            if drop_mode != constants.DROP_MODES[2]:
                                return drop_mode
                            else:
                                return self.drop_mode
                        
                        self.drop_mode = get_drop_mode(msg) 
                        
                        # send msg to server
                        if self.drop_mode == constants.DROP_MODES[2]:
                            c_stream = msg

                        # don't send msg to server; create a stream instead
                        # enter drop begin mode
                        elif self.drop_mode == constants.DROP_MODES[0]: 
                            msg = msg.replace(constants.bDROP_MSG_BEGIN, b'')

                            # client is sending challenges
                            while msg:
                                self.drop_mode = get_drop_mode(msg)
                                c_stream += msg                            

                                if self.drop_mode == constants.DROP_MODES[1]: # drop end mode
                                    break

                                msg = self.rcv_client()

                            if self.drop_mode != constants.DROP_MODES[1]:
                                logging.critical(utils.prep_log_msg('Drop end mode not found'))
                                exit(1)
                        
                        # enter drop end mode
                        if self.drop_mode == constants.DROP_MODES[1]:
                            # remove drop end identifier from stream  
                            c_stream = c_stream.replace(constants.bDROP_MSG_END, b'')

                            # extract challenges from stream
                            challenges, leftover = utils.parse_tls_packets(c_stream)
                            logging.debug(utils.prep_log_msg(f'Challenges: {challenges}'))

                            # recreate stream with selected challenges
                            c_stream = b""
                            for (i, challenge) in enumerate(challenges):
                                if i % 2 != 0: # skip every other challenge
                                    continue
                                else:
                                    c_stream += challenge
                            
                            c_stream += leftover
                            self.drop_mode = constants.DROP_MODES[2] # reset drop mode
                            
                        # send stream to server
                        self.send_msg(c_stream, self.s_socket)
                        logging.debug(utils.prep_log_msg('Client done sending'))

                        return True

                    def server():
                        s_stream = b""
                        msg = self.rcv_server()
                        while msg:
                            self.send_msg(msg, self.c_socket)
                            s_stream += msg
                            msg = self.rcv_server()

                        # self.send_msg(s_stream, self.c_socket)
                        logging.debug(utils.prep_log_msg('Server done sending'))

                        return s_stream != b""
                    
                    c_status = client()
                    s_status = server()

                    if not c_status and not s_status:
                        self.counter += 1

                    # breaks the loop when both the client and server are done sending
                    if self.counter == 2:
                        break

            def new_fwding():
                self.c_socket.settimeout(0.5)
                self.s_socket.settimeout(0.5)
                for i in range(15):
                    try:
                        c_msg = self.c_socket.recv(constants.TLS_RECORD_SIZE_LIMIT)
                        print(f'Client says: c_msg')
                        if c_msg:
                            self.send_msg(c_msg, self.s_socket)
                    except socket.timeout:
                        # print('Client timeout')
                        pass
                    
                    try:
                        s_msg = self.s_socket.recv(constants.TLS_RECORD_SIZE_LIMIT)
                        print(f'Server says: s_msg')
                        if s_msg:
                            self.send_msg(s_msg, self.c_socket)
                    except socket.timeout:
                        # print('Server timeout')
                        pass

            # start forwarding
            fwding()
            # new_fwding()

           

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