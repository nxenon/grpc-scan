# GRPC-Scan

GRPC-Scan finds GRPC Endpoints, Services, Messages and fields in Javascript files. This is useful when you are pentesting web application which uses grpc-web javascript webpacked files.


# Requirements

    pip3 install -r requirements.txt

# Javascript Files Note

For saving javascript files, you have to open them in browser and save the file or download it directly.

**Do not** copy and paste the javascript content. 

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
            Message --> 1
            Name --> 2
            Age --> 3
            IsAdmin --> 4
            Weight --> 5
            Test --> 6
            Test2 --> 7
            Test3 --> 16
            Test4 --> 20
      grpc.gateway.testing.EchoResponse:
            Message --> 1
            Name --> 2
            Age --> 3
            IsAdmin --> 4
            Weight --> 5
            Test --> 6
            Test2 --> 7
            Test3 --> 16
            Test4 --> 20
            MessageCount --> 8
      grpc.gateway.testing.ServerStreamingEchoRequest:
            Message --> 1
            MessageCount --> 2
            MessageInterval --> 3
      grpc.gateway.testing.ServerStreamingEchoResponse:
            Message --> 1
      grpc.gateway.testing.ClientStreamingEchoRequest:
            Message --> 1
      grpc.gateway.testing.ClientStreamingEchoResponse:
            MessageCount --> 1
