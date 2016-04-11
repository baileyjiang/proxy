How to use:

1. Execute the program with python on linux (developed with 2.7). Specify the port number after the program:
    python proxy.py [portNumber]
2. As a client, you can connect to the proxy using telnet (default host and port is localhost 12333):
    telnet localhost 12333
3. Type your request like so:
    GET http://www.google.com HTTP/1.0
4. You may input additional headers after the first GET line.
5. Entering a newline without any headers will finish the client request and send it off to the proxy.
6. The proxy will return the response from the server and close the connection gracefully.
7. If the client enters anything other than a GET, the proxy will return a not implemented response and close the connection.
8. If the client enters an improper HTTP request, the proxy will return a bad request response and close the connection.
9. You can change the port and the address of the proxy by changing lines 12 and 13 in proxy.py by specifying a different port and address.
10. The proxy should continue to run after processing multiple requests from clients.
11. Additionally, one may configure a browser to work with the proxy.
12. You can also use cURL with the proxy with:
    curl --proxy1.0 [proxyAddress:proxyPort] [url]
