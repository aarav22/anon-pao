import socket
import time
import logging
import sys
import select
import pickle, otc
import utils, constants

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)-8s - %(message)s', filename='proxy.log')
logger = logging.getLogger(__name__)

class SessionTerminatedException(Exception):pass
class ProtocolViolationException(Exception):pass

class TcpSockBuff(object):
    ''' Wrapped Tcp Socket with access to last sent/received data '''
    def __init__(self, sock, peer=None):
        self.socket = None
        self.socket_ssl = None
        self.recvbuf = ''
        self.sndbuf = ''
        self.peer = peer
        self._init(sock)
        
    def _init(self, sock):
        self.socket = sock
        
    def connect(self, target=None):
        target = target or self.peer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return self.socket.connect(target)
    
    def accept(self):
        return self.socket.accept()
                
    def recv(self, buflen=8*1024, *args, **kwargs):
        if self.socket_ssl:
            chunks = []
            chunk = True
            data_pending = buflen
            while chunk and data_pending:
                chunk = self.socket_ssl.read(data_pending)
                chunks.append(chunk)
                data_pending = self.socket_ssl.pending()
            self.recvbuf = ''.join(chunks)
        else:
            self.recvbuf = self.socket.recv(buflen, *args, **kwargs)
        return self.recvbuf
    
   
    def sendall(self, data):
        self.socket.sendall(data)
        self.sndbuf = data
        
    

class Session(object):
    ''' Proxy session from client <-> proxy <-> server 
        @param inbound: inbound socket
        @param outbound: outbound socket
        @param target: target tuple ('ip',port) 
        @param buffer_size: socket buff size'''
    
    def __init__(self, proxy, inbound=None, outbound=None, target=None, buffer_size=4096, mode = 1):
        self.proxy = proxy
        self.bind = proxy.getsockname()
        self.inbound = TcpSockBuff(inbound)
        self.outbound = TcpSockBuff(outbound, peer=target)
        self.buffer_size = buffer_size
        self.datastore = {}
        self.drop_mode = constants.DROP_MODES[2] # none
        self.mode = mode
        self.num_challenges = 0
        self.challenges = []
        self.otc_receiver = otc.receive()

        if self.mode != 1:

            with open('keys/s_public.pem', 'rb') as f:
                self.sender_public = pickle.load(f)

            with open('keys/r_publics.pem', 'rb') as f:
                self.r_publics = pickle.load(f)

            with open('keys/r_secrets.pem', 'rb') as f:
                self.r_secrets = pickle.load(f)
    
    def __repr__(self):
        return "<Session %s [client: %s] --> [prxy: %s] --> [target: %s]>"%(hex(id(self)),
                                                                            self.inbound.peer,
                                                                            self.bind,
                                                                            self.outbound.peer)
    def __str__(self):
        return "<Session %s>"%hex(id(self))
        
    def connect(self, target):
        self.outbound.peer = target
        logger.info("%s connecting to target %s"%(self, repr(target)))
        return self.outbound.connect(target)
    
    def accept(self):
        sock, addr = self.proxy.accept()
        self.inbound = TcpSockBuff(sock)
        self.inbound.peer = addr
        logger.info("%s client %s has connected"%(self,repr(self.inbound.peer)))
        return sock,addr
    
    def get_peer_sockets(self):
        return [self.inbound.socket, self.outbound.socket]
    
    # @profile
    def notify_read(self, sock):
       
        if sock == self.proxy:
            self.accept()
            self.connect(self.outbound.peer)
        elif sock == self.inbound.socket:
            # new client -> prxy - data
            self.on_recv_peek(self.inbound, self)
            self.on_recv(self.inbound, self.outbound, self, who="client")
        elif sock == self.outbound.socket:
            # new sprxy <- target - data
            self.on_recv(self.outbound, self.inbound, self, who="server")
           
        return 
    
    
    def close(self):
        try:
            self.outbound.socket.shutdown(2)
            self.outbound.socket.close()
            self.inbound.socket.shutdown(2)
            self.inbound.socket.close()
        except socket.error as se:
            logger.warning("session.close(): Exception: %s"%repr(se))
        raise SessionTerminatedException()
    
    # @profile
    def on_recv(self, s_in, s_out, session, who="server"):
        data = s_in.recv(session.buffer_size)
        msg = data

        if who == "client" and self.mode != 0:
            # check drop mode:
            self.drop_mode = self.get_drop_mode(msg) 
            c_stream = b''

            # send msg to server
            if self.drop_mode == constants.DROP_MODES[2]:
                c_stream = msg

            # don't send msg to server; create a stream instead
            # enter drop begin mode
            elif self.drop_mode == constants.DROP_MODES[0]: 
                msg = msg.replace(constants.bDROP_MSG_BEGIN, b'')

                msg = s_in.recv(session.buffer_size)

                while msg:
                    self.drop_mode = self.get_drop_mode(msg)

                    if self.drop_mode == constants.DROP_MODES[1]: # drop end mode
                        self.challenges.append(msg.replace(constants.bDROP_MSG_END, b''))
                        print('Drop end mode found')
                        break

                    self.challenges.append(msg)
                    msg = s_in.recv(8 * 1024)

                if self.drop_mode == constants.DROP_MODES[1]: # drop end mode
                    c_stream = b''.join(self.challenges)

                    if self.mode == 2:
                        replies = utils.parse_replies(c_stream)
                        c_stream = b'' # we'll re-create the stream
                        
                        for i, challenge in enumerate(replies):
                            self.otc_receiver.public = self.r_publics[i]
                            self.otc_receiver.secret = self.r_secrets[i]

                            reply = pickle.loads(challenge)
                            new_m = self.otc_receiver.elect(self.sender_public, 0, *reply)
                            c_stream += new_m

                    elif self.mode == 1:
                        challenges, leftover = utils.parse_tls_packets(c_stream)
                        c_stream = b'' # we'll re-create the stream

                        for i, challenge in enumerate(challenges):
                            if len(challenges) % 2 != 0:
                                if (i % 2 == 0):
                                    c_stream += challenge
                            else:
                                if (i == 0  or i % 2 != 0) and i != 1:  # for even number of challenges, we want to send 0 from (0, 1) and odd subsequently
                                    c_stream += challenge

                        
                        c_stream += leftover


                    self.drop_mode = constants.DROP_MODES[2]

            data = c_stream

        if not len(data):
            return session.close()
       
        if data:
            s_out.sendall(data)
        return data
    
    def get_drop_mode(self, msg):
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
    
    def on_recv_peek(self, s_in, session): pass
    def mangle_client_data(self, session, data): 
        #   logger.debug("%s [client] <= [server]          %s"%(session,repr(data)))
          return data
    def mangle_server_data(self, session, data): 
        # logger.debug("%s [client] <= [server]          %s"%(session,repr(data)))
        return data
    
class ProxyServer(object):
    '''Proxy Class'''
    
    def __init__(self, listen, target, buffer_size=4096, delay=0.0001, mode=1):
        self.input_list = set([])
        self.sessions = {}  # sock:Session()
        self.callbacks = {} # name: [f,..]
        #
        self.listen = listen
        self.target = target
        self.mode = mode # 1: non-AEAD, 2: AEAD
        #
        self.buffer_size = buffer_size
        self.delay = delay
        self.bind = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.bind.bind(listen)
        self.bind.listen(200)
        
    def __str__(self):
        return "<Proxy %s listen=%s target=%s>"%(hex(id(self)),self.listen, self.target)

    def get_session_by_client_sock(self, sock):
        return self.sessions.get(sock)

    def set_callback(self, name, f):
        self.callbacks[name] = f

    # @profile
    def main_loop(self):
        self.input_list.add(self.bind)
        while True:
            time.sleep(self.delay)
            inputready, _, _ =  select.select(self.input_list, [], [])
            
            for sock in inputready:
                if not sock in self.input_list: 
                    # Check if inputready sock is still in the list of socks to read from
                    # as SessionTerminateException might remove multiple sockets from that list
                    # this might otherwise lead to bad FD access exceptions
                    continue
                session = None
                try:
                    if sock == self.bind:
                        # on_accept
                        session = Session(sock, target=self.target, mode=self.mode)
                        session.notify_read(sock)
                        for s in session.get_peer_sockets():
                            self.sessions[s]=session
                        self.input_list.update(session.get_peer_sockets())
                    
                    else:
                        # on_recv
                        try:
                            session = self.get_session_by_client_sock(sock)
                            session.notify_read(sock)

                        except SessionTerminatedException:
                            self.input_list.difference_update(session.get_peer_sockets())
                            logger.warning("%s terminated."%session)
                        
                except Exception as e:
                    logger.error("main: %s"%repr(e))

                    if session:
                        logger.error("main: removing all sockets associated with session that raised exception: %s"%repr(session))
                        try:
                            session.close()
                        except SessionTerminatedException: pass
                        self.input_list.difference_update(session.get_peer_sockets())
                    elif sock and sock!=self.bind:
                        # exception for non-bind socket - probably fine to close and remove it from our list
                        logger.error("main: removing socket that probably raised the exception")
                        sock.close()
                        self.input_list.remove(sock)
                    else:
                        # this is just super-fatal - something happened while processing our bind socket.
                        raise        


def main():
    from optparse import OptionParser
    ret = 0
    usage = """usage: %prog [options]
    
       example: %prog --listen 0.0.0.0:25 --remote mail.server.tld:25 
    """
    parser = OptionParser(usage=usage)
    parser.add_option("-q", "--quiet",
                  action="store_false", dest="verbose", default=True,
                  help="be quiet [default: %default]")
    parser.add_option("-l", "--listen", dest="listen", help="listen ip:port [default: 0.0.0.0:<remote_port>]")
    parser.add_option("-r", "--remote", dest="remote", help="remote target ip:port to forward sessions to")
    parser.add_option("-k", "--key", dest="key", default="server.pem", help="SSL Certificate and Private key file to use, PEM format assumed [default: %default]")
    parser.add_option("-s", "--generic-ssl-intercept",
                  action="store_true", dest="generic_tls_intercept", default=False,
                  help="dynamically intercept SSL/TLS")
    parser.add_option("-b", "--bufsiz", dest="buffer_size", type="int", default=4*1024)
    # add option to add a mode value 1) non-AEAD 2) AEAD
    parser.add_option("-m", "--mode", dest="mode", type="int", default=1) 
        
    all_vectors = []
    
    parser.add_option("-x", "--vectors",
                  default="ALL",
                  help="Comma separated list of vectors. Use 'ALL' (default) to select all vectors, 'NONE' for tcp/ssl proxy mode."
                  " [default: %default]")
    # parse args
    (options, args) = parser.parse_args()
    # normalize args
    if not options.verbose:
        logger.setLevel(logging.INFO)
    if not options.remote:
        parser.error("mandatory option: remote")
    if ":" not in options.remote and ":" in options.listen:
        # no port in remote, but there is one in listen. use this one
        options.remote = (options.remote.strip(), int(options.listen.strip().split(":")[1]))
        logger.warning("no remote port specified - falling back to %s:%d (listen port)"%options.remote)
    elif ":" in options.remote:
        options.remote = options.remote.strip().split(":")
        options.remote = (options.remote[0], int(options.remote[1]))
    else:
        parser.error("neither remote nor listen is in the format <host>:<port>")
    if not options.listen:
        logger.warning("no listen port specified - falling back to 0.0.0.0:%d (remote port)"%options.remote[1])
        options.listen = ("0.0.0.0",options.remote[1])
    elif ":" in options.listen:
        options.listen = options.listen.strip().split(":")
        options.listen = (options.listen[0], int(options.listen[1]))
    else:
        options.listen = (options.listen.strip(), options.remote[1])
        logger.warning("no listen port specified - falling back to %s:%d (remote port)"%options.listen)
    options.vectors = [o.strip() for o in options.vectors.strip().split(",")]
    if 'NONE' in (v.upper() for v in options.vectors):
        options.vectors = []

          
    # ---- start up engines ----
    prx = ProxyServer(listen=options.listen, target=options.remote, mode=int(options.mode),
                      buffer_size=options.buffer_size, delay=0)
    logger.info("%s ready."%prx)

    import cProfile, pstats, io
    from pstats import SortKey
    pr = cProfile.Profile()
    pr.enable()
    try:
        prx.main_loop()
    except KeyboardInterrupt:
        logger.warning( "Ctrl C - Stopping server")
        ret+=1
    pr.disable()
    s = io.StringIO()
    sortby = SortKey.CUMULATIVE
    ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    ps.dump_stats("proxy.txt")
    print(s.getvalue())
        
    sys.exit(ret)
    
if __name__ == '__main__':
    main()