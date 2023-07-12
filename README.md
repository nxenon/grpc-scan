# GRPC-Scan

GRPC-Scan finds GRPC Endpoints, Services, Messages and fields in Javascript files. This is useful when you are pentesting web application which uses grpc-web javascript webpacked files.


# Requirements

    pip3 install -r requirements.txt

# Usage
        
    python3 grpc-scan.py --file main.js
    cat main.js | python3 grpc-scan.py --stdin

# Help

    xenon@xenon:~/python3 grpc-scan.py --help

    python3 grpc-scan.py [INPUT]
    Input Arguments:
      --file      file name of js file
      --stdin     get input from standard input
    Help:
      --help      print help message

# Output Example

        
    xenon@xenon:~/python3 grpc-scan.py --file main.js

    Found Endpoints:
      /grpc.gateway.testing.EchoService/Echo
      /grpc.gateway.testing.EchoService/EchoAbort
      /grpc.gateway.testing.EchoService/NoOp
      /grpc.gateway.testing.EchoService/ServerStreamingEcho
      /grpc.gateway.testing.EchoService/ServerStreamingEchoAbort
    
    Found Messages:
      grpc.gateway.testing.EchoRequest:
            Message
      grpc.gateway.testing.EchoResponse:
            Message
            MessageCount
      grpc.gateway.testing.ServerStreamingEchoRequest:
            Message
            MessageCount
            MessageInterval
      grpc.gateway.testing.ServerStreamingEchoResponse:
            Message
      grpc.gateway.testing.ClientStreamingEchoRequest:
            Message
      grpc.gateway.testing.ClientStreamingEchoResponse:
            MessageCount
