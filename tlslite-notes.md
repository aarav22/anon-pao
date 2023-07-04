## Using tlslite-ng to send email using smtplib
1. Create an SMTP object that connects to the server; SMTP_TLS(host, port); 
  - calls connect() and assigns self.sock
2. Use [HandshakeSettings](https://tlslite-ng.readthedocs.io/en/latest/tlslite.handshakesettings.html?highlight=handshakeSettings) to set the TLS version, cipher suite, and other options. 
3. Start TLS encryption :: starttls(); pass the HandshakeSettings object as an argument.
   - If the server supports TLS, it will return a 220 response code
   - Creates a [ClientHelper](https://tlslite-ng.readthedocs.io/en/latest/tlslite.integration.clienthelper.html?highlight=clientHelper#tlslite.integration.clienthelper.ClientHelper) object.
   - Creates a [TLSConnection](https://tlslite-ng.readthedocs.io/en/latest/tlslite.tlsconnection.html?highlight=tlsconnection#tlslite.tlsconnection.TLSConnection) object. This class wraps a [socket](https://docs.python.org/3/library/socket.html#socket.socket) and provides TLS handshaking and data transfer. Calls TLSRecordLayer().
   - TLSRecordLayer() creates a [TLSRecordLayer](https://tlslite-ng.readthedocs.io/en/latest/tlslite.tlsrecordlayer.html?highlight=tlsrecordlayer#tlslite.tlsrecordlayer.TLSRecordLayer) object. This class wraps a socket and provides TLS record layer functionality.
   - It wraps the socket in [BufferedSocket](https://tlslite-ng.readthedocs.io/en/latest/tlslite.bufferedsocket.html?highlight=socket) that will buffer reads and writes to a real socket object.
   - Then intializes self._recordLayer with [RecordLayer(sock)](https://tlslite-ng.readthedocs.io/en/latest/tlslite.recordlayer.html?highlight=RecordLayer#tlslite.recordlayer.RecordLayer) object.
   - Now we have a TLSConnection object that wraps a socket and provides TLS handshaking and data transfer. We now need to perform the TLS handshake using ClientHelper's _handshake() method. Since there is no client authentication (assuming), we use handshakeClientAnonymous() method.
   - We pass [session](https://tlslite-ng.readthedocs.io/en/latest/tlslite.session.html?highlight=session#tlslite.session.Session) object to the handshakeClientAnonymous() method. This object contains the TLS session information. It is used to resume a previous session. Calls _handshakeClientAsync() method.
   - This further calls a helper, _handshakeClientAsyncHelper() method. Calls _clientSendHello() and _clientGetServerHello() methods. 
   - _clientSendClientHello: Initialize acceptable ciphersuites,  certificate types, TLS extensions like useEncryptThenMAC or useExtendedMasterSecret. Send ClientHello with resumable session or without. We do this by intializing a [ClientHello](https://tlslite-ng.readthedocs.io/en/latest/tlslite.messages.html?highlight=clienthello#tlslite.messages.ClientHello) object. Use the create() method to create a ClientHello message.
   - _clientGetServerHello: Receive ServerHello message. Initialize the session object with the server's random value. Reads next message from socket, defragment message. Checks if response by server is correct. If not, raises exceptions.
   - Can print serverHello and clientHello here.
   - AES-128 lies in ECDH cipher suites. So, we need to perform ECDH key exchange. Calls ECDHE_RSAKeyExchange to get a [ECDHE_RSAKeyExchange](https://tlslite-ng.readthedocs.io/en/latest/tlslite.keyexchange.html?highlight=ECDHE_RSAKeyExchange#tlslite.keyexchange.ECDHE_RSAKeyExchange) instance.
   - Call _clientGetKeyExchange() method. This method receives the ServerKeyExchange message from the server. It also receives the ServerHelloDone message. Verifies signature on the Server Key Exchange message in verifyServerKeyExchange() method by calling _tls12_verify_SKE() method; we have server's public key and signature.
   - Now, do client key exchange. Calls makeClientKeyExchange() method. This method creates a ClientKeyExchange instance. And send the message through the socket. At this point we have premasterSecret.
   - Finishes things of with a Finished message. Calls _clientFinished() method. This method creates a Finished message and sends it through the socket. This is where all the magic is happening; we calculate the masterSecret using calc_key, and the remaining keys by calling _calcPendingStates() from tlsrecordlayer.py. 
    - _calcPendingStates calls calcPendingStates in recordlayer.py which calls _getCiherSettings to get key length, IV length and createCipherFunc(createAES (check cipherfactory.py) in this case).
    - Also calls _getMacSettings to get MAC length and digestmod (hashlib.sha256 in this case).
    - Initializes createMACFunc by calling _getHMACMethod -> createHMAC()
   - Create a session now and save values of serverRandom, clientRandom, masterSecret, cipherSuite, and compressionMethod. We can use this session object to resume a previous session.
   - Handshake is complete. We can now send and receive data.



   Message Encryption: 
   - sendmail() in smtplib receives the full email body, rcpts and sender. 
   - This is first processed to fix eol's (\r \n) and then encoded to bytes using encode('ascii') method.
   - calls self.data() method to send the data. This is what we need to intercept as a proxy. Then a call to self.send() method is made. That calls sendall() method of the socket object in tlsrecordlayer.py. 
   - This calls write() which calls writeAsync() which creates an ApplicationData message on the msg, storing the message as a bytearray. This calls _sendMsg from tlsrecordlayer.py
   - Here we check if the msg is below the record size limit. If not, we fragment the message. The record size limit is 16384 bytes or 16KB. calls _sendMsgThroughSocket() method. Calls sendRecord() method from recordlayer.py. 
   - Calls _macThenEncrypt since that is what we want in this case.
   - First we add macBytes to the msg, which are obtained by calling self.calculateMAC().
   - The HMAC object is defined in C:\Users\aarav\AppData\Local\Programs\Python\Python38\Lib\hmac.py

    ```python 
    File "C:\Users\username\AppData\Local\Programs\Python\Python38\lib\smtplib.py", line 895, in sendmail
        (code, resp) = self.data(msg)
    File "C:\Users\username\AppData\Local\Programs\Python\Python38\lib\smtplib.py", line 575, in data
        self.send(q)
    File "C:\Users\username\AppData\Local\Programs\Python\Python38\lib\smtplib.py", line 361, in send
        self.sock.sendall(s)
    File "path\to\tlslite\tlsrecordlayer.py", line 577, in sendall
        self.write(s)
    File "path\to\tlslite\tlsrecordlayer.py", line 420, in write
        for result in self.writeAsync(s):
    File "path\to\tlslite\tlsrecordlayer.py", line 439, in writeAsync
        for result in self._sendMsg(applicationData): 
    File "path\to\\tlslite\tlsrecordlayer.py", line 943, in _sendMsg
        for result in self._sendMsgThroughSocket(msgFragment):
    File "path\to\tlslite\tlsrecordlayer.py", line 971, in _sendMsgThroughSocket
        for result in self._recordLayer.sendRecord(msg):
    File "path\to\tlslite\recordlayer.py", line 627, in sendRecord
        data = self._macThenEncrypt(data, contentType)
    File "path\to\tlslite\recordlayer.py", line 489, in _macThenEncrypt
        data = self._writeState.encContext.encrypt(data)
    File "path\to\tlslite\utils\python_aes.py", line 37, in encrypt
        traceback.print_stack(file=sys.stdout)



1. Login to the server
2. Send the mail
3. Quit the SMTP server


- We used the following to print the stack trace.

   ``` python
        import sys
        import traceback
        traceback.print_stack(file=sys.stdout)
    ```