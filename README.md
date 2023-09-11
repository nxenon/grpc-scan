# gRPC Web Pentest Suite

gRPC-Pentest-Suite is set of tools for pentesting / hacking gRPC Web applications.

Available Content Types:
- [x] application/grpc-web-text
- [ ] application/grpc-web [coming soon]

gRPC-Pentest-Suite contains these 2 tools:
- **[grpc-scan](#grpc-coder-usage)** scanning the gRPC-web javascript webpacked files to detect grpc endpoints, services, messages and field types
- **[grpc-coder](#grpc-coder-usage)** encoding and decoding gRPC-web payloads for pentesting (manipulating payloads)
- **[grpc-coder-burp-extension](#grpc-coder-extension-usage)** extension for burp suite to easily using gRPC-Coder tool

# Hacking into gRPC-Web YouTube Video
This video includes using both gRPC Scan tool and gRPC Coder Burp Suite Extension: How to manipulate gRPC-Web payloads and analyse the JavaScript webpacked files to find hidden endpoints, services and messages.
[Watch](https://youtu.be/VoDyweIjT2U?si=kXWbQELnJZfyHaId)


[![Watch the video](https://img.youtube.com/vi/VoDyweIjT2U/maxresdefault.jpg)](https://youtu.be/VoDyweIjT2U?si=kXWbQELnJZfyHaId)

# Requirements

    pip3 install -r requirements.txt

for **grpc-coder.py** you need to install [protoscope](https://github.com/protocolbuffers/protoscope) in system gloablly.
    
    go install github.com/protocolbuffers/protoscope/cmd/protoscope...@latest

for **gRPC Coder Burp Extension** you need to have these requirements:
- download the whole repository (because the script needs grpc.coder.py)
- jython must be installed and configured in burp
- protoscope must be installed globally on system (because the extension runs a protoscope command)
- python3 must be installed to run the grpc-coder.py script (because the gRPC-Coder is written in python3)
- in windows python 3 binary name is **python** and in linux and mac the binary name is **python3** 

the extension runs two **safe** commands to work with grpc-coder.py and protoscope tools.

# gRPC Coder Extension Usage
after installing the extension it adds to menu items into extensions menu item:
- gRPC Coder **Decode**
- gRPC Coder **Encode**

Steps:
1. select the gRPC-Web base64 payload in burp interceptor or repeater to and click on Decode item for decoding to human-readable format
2. edit the text and select the new edited text and click on Encode item for encoding to gRPC-Web base64 format

## Watch the Extension Usage Video on YouTube
[Watch](https://youtu.be/w75_ixNzM24)

[![Watch the video](https://img.youtube.com/vi/w75_ixNzM24/maxresdefault.jpg)](https://youtu.be/w75_ixNzM24)


# gRPC Coder Extension Installation
1. Download the Whole Repository (the extension needs some files in this repo)
2. add [grpc-coder-burp-extension.py](grpc-coder-burp-extension.py) in Burp Extensions.

Note: [protoscope](https://github.com/protocolbuffers/protoscope) and python3 must be system globally installed.

# gRPC-Coder Usage

**GRPC-Coder.py** has two options:
- [Encode](#encoding)
- [Decode](#decoding)

[grpc-coder.py](grpc-coder.py)

    python3 grpc-coder.py --help

    echo payload | python3 grpc-coder.py [--encode OR --decode]

    General Arguments:
      --encode      encode protoscope binary output to application/grpc-web-text
      --decode      decode application/grpc-web-text base64 encoded payload to protoscope format
    Help:
      --help        print help message

## Decoding

In Burp Suite when you intercept the request, get the gRPC-Web base64 encoded payload and give it to the script as standard input:

    echo "AAAAABYSC0FtaW4gTmFzaXJpGDY6BVhlbm9u" | python3 grpc-coder.py --decode | protoscope > out.txt
    cat out.txt

content of out.txt:

    2: {"Amin Nasiri"}
    3: 54
    7: {"Xenon"}
    
    vim out.txt
    ... edit the file

content of edited out.txt:

    cat out.txt
    2: {"Amin Nasiri Xenon GRPC"}
    3: 54
    7: {"<script>alert(origin)</script>"}


now you have to encode the new payload: [Encode](#encoding)

## Encoding

after editing [decoded](#decoding) payload you have to encode it:

    protoscope -s out.txt | python3 grpc-coder.py --encode

Output:
    
    AAAAADoSFkFtaW4gTmFzaXJpIFhlbm9uIEdSUEMYNjoePHNjcmlwdD5hbGVydChvcmlnaW4pPC9zY3JpcHQ+

Then you put the new base64 payload into Burp Suite intercepted request.

# gRPC-Scan Usage

[grpc-scan.py](grpc-scan.py)
        
    python3 grpc-scan.py --file main.js
    OR
    cat main.js | python3 grpc-scan.py --stdin

# gRPC-Scan Javascript Files Note

For saving javascript files, you have to open them in browser and save the file or download it directly.

**Do not** copy and paste the javascript content.

ProtoBuf Version Support:
- Version 3 [OK]
- Version 2 [Some Features do not work]

# gRPC-Scan Help

    python3 grpc-scan.py --help

    python3 grpc-scan.py [INPUT]
    Input Arguments:
      --file      file name of js file
      --stdin     get input from standard input
    Help:
      --help      print help message

# gRPC-Scan Output Example

        
    python3 grpc-scan.py --file main.js

    Found Endpoints:
      /grpc.gateway.testing.EchoService/Echo
      /grpc.gateway.testing.EchoService/EchoAbort
      /grpc.gateway.testing.EchoService/NoOp
      /grpc.gateway.testing.EchoService/ServerStreamingEcho
      /grpc.gateway.testing.EchoService/ServerStreamingEchoAbort
    
    Found Messages:
    
    grpc.gateway.testing.EchoRequest:
    +------------+--------------------+--------------+
    | Field Name |     Field Type     | Field Number |
    +============+====================+==============+
    | Message    | Proto3StringField  | 1            |
    +------------+--------------------+--------------+
    | Name       | Proto3StringField  | 2            |
    +------------+--------------------+--------------+
    | Age        | Proto3IntField     | 3            |
    +------------+--------------------+--------------+
    | IsAdmin    | Proto3BooleanField | 4            |
    +------------+--------------------+--------------+
    | Weight     | Proto3FloatField   | 5            |
    +------------+--------------------+--------------+
    | Test       | Proto3StringField  | 6            |
    +------------+--------------------+--------------+
    | Test2      | Proto3StringField  | 7            |
    +------------+--------------------+--------------+
    | Test3      | Proto3StringField  | 16           |
    +------------+--------------------+--------------+
    | Test4      | Proto3StringField  | 20           |
    +------------+--------------------+--------------+
    
    grpc.gateway.testing.EchoResponse:
    +--------------+--------------------+--------------+
    |  Field Name  |     Field Type     | Field Number |
    +==============+====================+==============+
    | Message      | Proto3StringField  | 1            |
    +--------------+--------------------+--------------+
    | Name         | Proto3StringField  | 2            |
    +--------------+--------------------+--------------+
    | Age          | Proto3IntField     | 3            |
    +--------------+--------------------+--------------+
    | IsAdmin      | Proto3BooleanField | 4            |
    +--------------+--------------------+--------------+
    | Weight       | Proto3FloatField   | 5            |
    +--------------+--------------------+--------------+
    | Test         | Proto3StringField  | 6            |
    +--------------+--------------------+--------------+
    | Test2        | Proto3StringField  | 7            |
    +--------------+--------------------+--------------+
    | Test3        | Proto3StringField  | 16           |
    +--------------+--------------------+--------------+
    | Test4        | Proto3StringField  | 20           |
    +--------------+--------------------+--------------+
    | MessageCount | Proto3IntField     | 8            |
    +--------------+--------------------+--------------+
    
    grpc.gateway.testing.ServerStreamingEchoRequest:
    +-----------------+-------------------+--------------+
    |   Field Name    |    Field Type     | Field Number |
    +=================+===================+==============+
    | Message         | Proto3StringField | 1            |
    +-----------------+-------------------+--------------+
    | MessageCount    | Proto3IntField    | 2            |
    +-----------------+-------------------+--------------+
    | MessageInterval | Proto3IntField    | 3            |
    +-----------------+-------------------+--------------+
    
    grpc.gateway.testing.ServerStreamingEchoResponse:
    +------------+-------------------+--------------+
    | Field Name |    Field Type     | Field Number |
    +============+===================+==============+
    | Message    | Proto3StringField | 1            |
    +------------+-------------------+--------------+
    
    grpc.gateway.testing.ClientStreamingEchoRequest:
    +------------+-------------------+--------------+
    | Field Name |    Field Type     | Field Number |
    +============+===================+==============+
    | Message    | Proto3StringField | 1            |
    +------------+-------------------+--------------+
    
    grpc.gateway.testing.ClientStreamingEchoResponse:
    +--------------+----------------+--------------+
    |  Field Name  |   Field Type   | Field Number |
    +==============+================+==============+
    | MessageCount | Proto3IntField | 1            |
    +--------------+----------------+--------------+
    

# gRPC Lab
For testing this tool and getting familiar with gRPC-Web, I made a [lab](https://github.com/nxenon/grpc-lab) for gRPC & gRPC-Web.
