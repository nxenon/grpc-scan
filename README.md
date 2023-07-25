# GRPC-Pentest-Suite

GRPC-Pentest-Suite is set of tools for pentesting grpc-web applications.

GRPC-Pentest-Suite contains these 2 tools:
- **[grpc-scan](https://github.com/nxenon/grpc-pentest-suite/blob/main/grpc-scan.py)** scanning the grpc-web javascript webpacked files to detect grpc endpoints, services, messages and field types
- **[grpc-coder](https://github.com/nxenon/grpc-pentest-suite/blob/main/grpc-coder.py)** encoding and decoding grpc-web payloads for pentesting (manipulating payloads)

# Requirements

    pip3 install -r requirements.txt

for **grpc-coder.py** you need to install [protoscope](https://github.com/protocolbuffers/protoscope) in system gloablly.
    
    go install github.com/protocolbuffers/protoscope/cmd/protoscope...@latest

# GRPC-Coder Usage

**GRPC-Coder.py** has two options:
- [Encode](#encoding)
- [Decode](#decoding)


    python3 grpc-scan.py --help

    echo payload | python3 grpc-coder.py [--encode OR --decode]

    General Arguments:
      --encode      to encode protoscope tool binary output to grpc-web base64 encoded payload
      --decode      to decode grpc-web base64 encoded payload to protoscope tool hex format
    Help:
      --help        print help message

## Decoding

In Burp Suite when you intercept the request, get the grpc-web base64 encoded payload and give it to the script as standard input:

    echo "AAAAABkKBGFtaW4YAIIBBXhlbm9uogEGbmFzaXJp" | python3 grpc-coder.py --decode | protoscope > out.txt
    cat out.txt

content of out.txt:

    1: {"amin"}
    3: 0
    16: {"xenon"}
    20: {"nasiri"}
    
    vim out.txt
    ... edit the file

content of edited out.txt:

    cat out.txt
    1: {"amin GRPC"}
    3: 0
    16: {"xenon Web"}
    20: {"nasiri 54"}

now you have to encode the new payload: [Encode](#encoding)

## Encoding

after editing [decoded](#decoding) payload you have to encode it:

    protoscope -s out.txt | python3 grpc-coder.py --encode

Output:
    
    AAAAACUKCWFtaW4gR1JQQxgAggEJeGVub24gV2ViogEJbmFzaXJpIDU0

Then you put the new base64 payload into Burp Suite intercepted request.

# GRPC-Scan Usage
        
    python3 grpc-scan.py --file main.js
    OR
    cat main.js | python3 grpc-scan.py --stdin

# GRPC-Scan Javascript Files Note

For saving javascript files, you have to open them in browser and save the file or download it directly.

**Do not** copy and paste the javascript content.

ProtoBuf Version Support:
- Version 3 [OK]
- Version 2 [Some Features do not work]

# GRPC-Scan Help

    python3 grpc-scan.py --help

    python3 grpc-scan.py [INPUT]
    Input Arguments:
      --file      file name of js file
      --stdin     get input from standard input
    Help:
      --help      print help message

# GRPC-Scan Output Example

        
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
    
