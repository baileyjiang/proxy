from socket import *
from urlparse import *
from multiprocessing import Process, Lock
import re
import hashlib
import sys

def main():

    # Check for a command line argument for the port. If there's an error, stop the program.
    try:
        serverPort = int(sys.argv[1])
    except Exception, e:
        print "Requires 1 additional argument for port to use"
        return;

    # Startup and listen for connections.
    serverAddress = 'localhost'
    serverSocket = socket(AF_INET,SOCK_STREAM)
    
    serverSocket.bind((serverAddress,serverPort))
    print 'Bound to:', serverSocket.getsockname()
    
    serverSocket.listen(1)
    
    while 1:
        # Process all connections
        Process(target=processConnection, args=(serverSocket,)).start()

# This function processes our connection. It gets the request from the client, processes it, sends it to the server, and forwards it back to the client.
def processConnection(serverSocket):

    connectionSocket, addr = serverSocket.accept()
    print 'Accepted connection from:', connectionSocket.getpeername(), ' fd: ' , connectionSocket.fileno()
    
    # Process our client request. 
    request = getInput(connectionSocket)

    # Process the client's request. If we run into an exception, stop.
    try:
    	formattedRequest, parsedURI = processRequests(request, connectionSocket)
    except Exception, e:
    	print e
	return

    clientSocket = socket(AF_INET, SOCK_STREAM)
    print 'Bound to: (after socket call)', clientSocket.getsockname()
    
    # Check if there's a port, else default 80.
    port = parsedURI.port
    if not port:
        port = 80

    # Start a connection to the server.
    clientSocket.connect((parsedURI.hostname,port))
    print 'Bound to: (after connect call)', clientSocket.getsockname()
    
    print "SENDING: "
    print formattedRequest
    print "\n"
    clientSocket.send(formattedRequest)
    
    response = clientSocket.recv(2048)
    processedResponse = processResponse(response)

    print "RECEIVE FROM SERVER :\n" + processedResponse + "\n"
    
    clientSocket.close()
    
    connectionSocket.send(processedResponse)
    connectionSocket.close()
    print "Done with this one"


# Gets the request from the client.
def getInput(connectionSocket):
    # Process number of lines
    message = connectionSocket.recv(1024)
    messageList = []
    messageList.append(message)
    receiveList = message.splitlines()
    while len(receiveList) is not 0: 
    	# If we get a plain newline, client is done with request. Else keep processing lines for additional headers.
    	if receiveList[len(receiveList)-1] != "":
	    message = connectionSocket.recv(1024)
       	    receiveList = message.splitlines()
       	    messageList.append(message)
	else:
	    break

    return messageList;

# Processes the response from the server and see if it is malware.
def processResponse(response):
    # Split the response between the headers and the object.
    responseMessage = response.partition("\r\n\r\n")
    # Calculate the MD5 hash of the object.
    hashed = hashlib.md5(responseMessage[2]).hexdigest()
    # Create a new connection to cymru to verify if the object is malware or not.
    hashSocket = socket(AF_INET, SOCK_STREAM)
    hashSocket.connect(("hash.cymru.com", 43))
    hashSocket.send(hashed + "\r\n")
    hashResponse = hashSocket.recv(2048)
    hashSocket.close()
    responseList = hashResponse.split()
    for x in range (0, len(responseList)):
        # If cymru reports NO_DATA, then there is no malware. Return the original response from the server.
        if responseList[x] == 'NO_DATA':
            return response;
    # Cymru found malware, replace the object with a simple HTML saying that the content has been blocked and return a new response.
    responseMessage = list(responseMessage)
    responseMessage[2] = "<!DOCTYPE html>\r\n<html>\r\n<body>\r\n\r\n<h1>The content has been blocked due to suspicion of malware.</h1>\r\n</body>\r\n</html>\r\n"
    responseMessage = tuple(responseMessage)
    return "".join(responseMessage);

# Processes the request from the client.
def processRequests(request, connectionSocket):
    # Delimit the request with newlines.
    firstSplit = request[0].split("\r\n")
    # Get the first line and split it for processing.
    splitArray = firstSplit[0].split()

    # If the user's request did not contain three phrases, raise exception on a bad request.
    if len(splitArray) != 3:
        connectionSocket.send("HTTP/1.0 400 Bad Request\n")
        connectionSocket.close()
        print "Client error: HTTP/1.0 400 Bad Request"
        raise Exception("Bad Request")

    # If user requests anything other than GET, raise exception.
    if splitArray[0] != 'GET':
        connectionSocket.send("HTTP/1.0 501 Not Implemented\n")
        connectionSocket.close()
        print "Client error: HTTP/1.0 501 Not Implemented"
        raise Exception("Not Implemented")

    absoluteURI = splitArray[1]

    parsedURI = urlparse(absoluteURI)

    # If there's no path, default to root.
    path = parsedURI.path
    if not path:
        path = "/"
    
    formattedRequest = "GET " + path + " " + "HTTP/1.0" + "\r\n" + "Host: " + parsedURI.hostname + "\r\n" + "Connection: close\r\n"

    # Process additional headers.
    for x in range(1, len(firstSplit)):
        match = re.search("(.*: .*)", firstSplit[x])
        if match:
	    # Already processed the host header. Do not do if they have the host header. Do the same for connection.
	    if "Host" not in match.group() and "Connection" not in match.group():
                formattedRequest = formattedRequest + match.group() + "\r\n"
    formattedRequest = formattedRequest + "\r\n"
    return (formattedRequest, parsedURI)

if __name__ == '__main__':
    main();
