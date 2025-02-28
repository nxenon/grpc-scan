# gRPC Web Pentest Suite

gRPC-Pentest-Suite is set of tools for pentesting / hacking gRPC Web applications.

Available Content Types:
- [x] application/grpc-web-text
- [x] application/grpc-web+proto


gRPC-Pentest-Suite contains these 2 tools:
- **[grpc_scan](#grpc-coder-usage)** scanning the gRPC-web javascript webpacked files to detect grpc endpoints, services, messages and field types
- **[grpc_web_burp_extension.py](#grpc-coder-extension-usage)** extension for burp suite to easily using gRPC-Coder tool
  - [x] application/grpc-web-text support
  - [x] application/grpc-web+proto support
- **[grpc_coder](#grpc-coder-usage)** encoding and decoding gRPC-web payloads for pentesting (manipulating payloads)
  - [x] only application/grpc-web-text support
- **[big_string_chunker](#big-string-chunker-tool)** this tool chunks a big string into pieces of 80 characters, so that gRPC-coder can encode it (also reverse)
- **[old_grpc_web_burp_extension_with_dependency.py](#grpc-coder-old-extension-with-dependency-installation)** old extension for burp suite which has some dependencies
  - [x] only application/grpc-web-text support


# Video of New Extension
[grpc_web_burp_extension.py](./grpc_web_burp_extension.py) file is new extension which does not have any dependencies and all dependencies are in this repo (in lib dir).

## gRPC-Web Burp Extension Images
- Main Settings:
  
![mainSettingsImage](https://github.com/user-attachments/assets/77d0dc20-f6a2-4ac6-b955-00cd6f90e0ec)

- Message Editor:
  
![messageEditorMainImage](https://github.com/user-attachments/assets/2a72647c-bea6-44c5-920e-da051cdc93e0)

- Message Editor Decoded:
  
![messageEditorDecodedImage](https://github.com/user-attachments/assets/1c9a972c-42df-45ef-9317-989c912bfa99)

## Todo
- [ ] Create tutorial video for using new extension

# gRPC-Web Coder New Extension Usage [recommended]
- The extension automatically gets enabled when the request has `Content-Type` or `x-grpc-content-type` headers (based on the settings you have set) with value of:
  - application/grpc-web-text (extension automatically decodes and encodes the body)
  - application/grpc-web+proto (extension automatically decodes and encodes the body)
- Also, there is new burp tab which you can enable or disable encoding format checkboxes

## gRPC-Web Coder New Extension Installation 
1. Download the Whole Repository (the extension needs files in this repo)
2. add [grpc_web_burp_extension.py](grpc_web_burp_extension.py) in Burp Extensions.

## gRPC-Web Coder New Extension Features
- New tab in repeater message editor
- edit proto type definition
- automatically detect grpc-web-text requests (via `Content-Type` or `x-grpc-content-type` headers)
  - note: `x-grpc-content-type` is for when you want manually enable gRPC-Web Decoder Tab
  - note: if you set value of headers to application/grpc-web-text the extension automatically decodes and encodes the payloads


# gRPC Coder Old Extension (with dependency) Usage
after installing the extension it adds to menu items into extensions menu item:
- gRPC Coder **Decode**
- gRPC Coder **Encode**

Steps:
1. select the gRPC-Web base64 payload in burp interceptor or repeater and click on Decode item for decoding to human-readable format
2. edit the text and select the new edited text and click on Encode item for encoding to gRPC-Web base64 format

## Hacking into gRPC-Web Article & YouTube Video (old Extension)
This article includes the methodology for pentesting gRPC-Web and a methodology for finding hidden servies and endpoints. Read [Hacking into gRPC-Web](https://infosecwriteups.com/hacking-into-grpc-web-a54053757a45) article and for `application/grpc-web+proto` see this article [Hacking into gRPC-Web : Part 2](https://medium.com/@nxenon/hacking-into-grpc-web-part-2-f8540309e1e8).

This video includes using both gRPC Scan tool and gRPC Coder Burp Suite Extension: How to manipulate gRPC-Web payloads and analyse the JavaScript webpacked files to find hidden endpoints, services and messages.
[Watch](https://youtu.be/VoDyweIjT2U?si=kXWbQELnJZfyHaId)


[![Watch the video](https://img.youtube.com/vi/VoDyweIjT2U/maxresdefault.jpg)](https://youtu.be/VoDyweIjT2U?si=kXWbQELnJZfyHaId)

## Watch the Old Extension Usage Video on YouTube
[Watch](https://youtu.be/w75_ixNzM24)

[![Watch the video](https://img.youtube.com/vi/w75_ixNzM24/maxresdefault.jpg)](https://youtu.be/w75_ixNzM24)

# gRPC Coder Old Extension (with dependency) Installation
1. Download the Whole Repository (the extension needs some files in this repo)
2. add [old_grpc_web_burp_extension_with_dependency.py](old_grpc_web_burp_extension_with_dependency.py) in Burp Extensions.
3. This extension has some dependencies which need to be installed: [Requirements](#requirements-for-burp-suite-old-extension-with-dependency)

Note: [protoscope](https://github.com/protocolbuffers/protoscope) and python3 must be system globally installed.


## Requirements for Burp Suite Old Extension (with dependency)

    pip3 install -r requirements.txt

for **grpc_coder.py** you need to install [protoscope](https://github.com/protocolbuffers/protoscope) in system gloablly.
    
    go install github.com/protocolbuffers/protoscope/cmd/protoscope...@latest

for **gRPC Coder Burp Extension** you need to have these requirements:
- download the whole repository (because the script needs grpc.coder.py)
- jython must be installed and configured in burp
- protoscope must be installed globally on system (because the extension runs a protoscope command)
- python3 must be installed to run the grpc_coder.py script (because the gRPC-Coder is written in python3)
- in windows python 3 binary name is **python** and in linux and mac the binary name is **python3** 

the extension runs two **safe** commands to work with grpc_coder.py and protoscope tools.

## Old Extension Features
New Features:
1. Automatically Encode/Decode by New Decoded Protobuf Tab (you can directly view the decoded protobuf in the Burp tool (Repeater, Proxy, Intruder...) AND automatically encode it back if we changed anything.)

![1. decoded_protobuf_tab_image](https://github.com/user-attachments/assets/293888a8-12ad-4152-913a-6883df625502)

2. Scanner Insertion Points (now if you right-click on an application/grpc-web-text HTTP request / host -> Scan -> Active Scan, Burp will manage to recognize the format, decode it, insert payloads in any field, and encode it back.)


        1: {
          9: 0
          10: 0
          19: {"test"}
          25: {
            "#{\"\".getClass().forName(\"java.net.URL\").getConstructors()[2].newInstance(\"http:/"
          "/xxxx.oastify.com.\").hashCode()}"
          }
        }
        10: {2: 20}

# gRPC-Coder Usage

**grpc_coder.py** has two options:
- [Encode](#encoding)
- [Decode](#decoding)

[grpc_coder.py](grpc_coder.py)

    python3 grpc_coder.py --help

    echo payload | python3 grpc_coder.py [--encode OR --decode]

    General Arguments:
      --encode       encode protoscope binary output to application/grpc-web-text
      --decode       decode application/grpc-web-text base64 encoded payload to protoscope format
      --type         content-type of payload [default: grpc-web-text] available types: [grpc-web-text, grpc-web+proto]
    
    Input Arguments:
    Default Input is Standard Input
      --file        to get input from a file 
    
    Help:
      --help        print help message

## Decoding

In Burp Suite when you intercept the request, get the gRPC-Web base64 encoded payload and give it to the script as standard input:

    echo "AAAAABYSC0FtaW4gTmFzaXJpGDY6BVhlbm9u" | python3 grpc_coder.py --decode --type grpc-web-text | protoscope > out.txt
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

    protoscope -s out.txt | python3 grpc_coder.py --encode --type grpc-web-text

Output:
    
    AAAAADoSFkFtaW4gTmFzaXJpIFhlbm9uIEdSUEMYNjoePHNjcmlwdD5hbGVydChvcmlnaW4pPC9zY3JpcHQ+

Then you put the new base64 payload into Burp Suite intercepted request.

# Big String Chunker Tool
When you have a big string that you want to put it into a value in protobuf fields, you have to make that string into some pieces of characters using [big_string_chunker.py](big_string_chunker.py).

For Example:

    This String is big:
      "T2dnUwACAAAAAAAAAABzFQAAAAAAAAAJCzcBE09wdXNIZWFkAQE4AYC7AAAAAABPZ2dTAAAAAAAAAAAAAHMVAAABAAAAo2rOoQE3T3B1c1RhZ3MPAAAAbGlib3B1cyB1bmtub3duAQAAABQAAABFTkNPREVSPU1vemlsbGExMjQuME9nZ1MAAMAwAAAAAAAAcxUAAAIAAAD1DNygG//T/yb/KP//CP8h/yT/JP8k/yX/JP8l/yj/Kfh4/5AiWRn+hxCNu1lGW1E1RpFlgncP1g3KdvtuuhDanwxtyvMzTX/X3ain7fAXGnRupDzl9oir"jHtN7BZBGZZW9Vkyv2oBhgfnGhJPxrf7RJ9D4e2AABS0iAuHWWWzs0UZpgwlqMwOZ+w4PIymRYPzCB5q9C9JFVUjdihmqLbP8WICC+0eSFmUO+lM4PYiVprOWgfbwTcNqaYdZSKT3fp2pjNuTJzyvEO/t2Dg1TnCwjoq0veEM1YcRx4polaFw/au+FdceT13SuK8ehmSEHPyLB1H2lUAAAAAAAAAAaBfGjYa5md8lEWEol5mykby0OgcohE0KzMpefR9SiVHFG7sL0r7JrAeot6SRV1x1iWWVBejRscEDQA0gyXKQnrH1P+/cIqNOLFZzHVfcTfCbDASrlauLF5i9eLUEFv289im/BQqPPGkld7iwBlOA5zZz4ysnRYDv8VytH9F9vLqNgpiWqNO0pgr+4Dl9i4vtxgCYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEEH5ttS9etaTCa18br69R/RM6tCIKjxjEULqgaJJQkCBwJxDR9kAsol/Xymr7cFKgJ+0crArSf9IqQ/WgqEAgEtmTqgwA0BkOTT4q2YhAygIak+pZZu654kaBYG+9Hag=="

    the tool converts it to this:

    1: {
      "T2dnUwACAAAAAAAAAABzFQAAAAAAAAAJCzcBE09wdXNIZWFkAQE4AYC7AAAAAABPZ2dTAAAAAAAAAAAA"
      "AHMVAAABAAAAo2rOoQE3T3B1c1RhZ3MPAAAAbGlib3B1cyB1bmtub3duAQAAABQAAABFTkNPREVSPU1v"
      "emlsbGExMjQuME9nZ1MAAMAwAAAAAAAAcxUAAAIAAAD1DNygG//T/yb/KP//CP8h/yT/JP8k/yX/JP8l"
      "/yj/Kfh4/5AiWRn+hxCNu1lGW1E1RpFlgncP1g3KdvtuuhDanwxtyvMzTX/X3ain7fAXGnRupDzl9oir"
      "jHtN7BZBGZZW9Vkyv2oBhgfnGhJPxrf7RJ9D4e2AABS0iAuHWWWzs0UZpgwlqMwOZ+w4PIymRYPzCB5q"
      "9C9JFVUjdihmqLbP8WICC+0eSFmUO+lM4PYiVprOWgfbwTcNqaYdZSKT3fp2pjNuTJzyvEO/t2Dg1TnC"
      "wjoq0veEM1YcRx4polaFw/au+FdceT13SuK8ehmSEHPyLB1H2lUAAAAAAAAAAaBfGjYa5md8lEWEol5m"
      "ykby0OgcohE0KzMpefR9SiVHFG7sL0r7JrAeot6SRV1x1iWWVBejRscEDQA0gyXKQnrH1P+/cIqNOLFZ"
      .
      .
      .
      "zHVfcTfCbDASrlauLF5i9eLUEFv289im/BQqPPGkld7iwBlOA5zZz4ysnRYDv8VytH9F9vLqNgpiWqNO"
      "0pgr+4Dl9i4vtxgCYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEEH5ttS9etaTCa18br69R/R"
      "M6tCIKjxjEULqgaJJQkCBwJxDR9kAsol/Xymr7cFKgJ+0crArSf9IqQ/WgqEAgEtYmTqgwA0BkOTT4q2"
      "YhAygIak+pZZu654kaBYG+9Hag=="
    }

- Note: Do not forget to change the field number. The tool uses field number 1 by default.

## Big String Chunker in gRPC Coder Burp Extension [Chunk]
- Big String
![Big String Chunker in gRPC Coder Burp Extension Chunk](https://github.com/nxenon/grpc-pentest-suite/assets/61124903/023850e2-e8e6-423e-b8fe-8ffe35ad632a)
- Result
![Big String Chunker Result Chunk](https://github.com/nxenon/grpc-pentest-suite/assets/61124903/287208ea-9984-4e56-9bef-d3cc666e1c8e)

### Big String Chunker CLI Usage [Chunk]

    cat bigString.txt | python3 big_string_chunker.py --stdin --chunk
    python3 big_string_chunker.py --file bigString.txt --chunk

## Big String Chunker in gRPC Coder Burp Extension [Un-Chunk]
- Big String
![Big String Chunker in gRPC Coder Burp Extension Un-Chunk](https://github.com/nxenon/grpc-pentest-suite/assets/61124903/f7fa678b-74cb-4149-93a5-2a15375b4f0a)
- Result:
![Big String Chunker Result Un-Chunk](https://github.com/nxenon/grpc-pentest-suite/assets/61124903/aa9268b9-22ab-443c-a17e-3331cf4e766e)


### Big String Chunker CLI Usage [Un-Chunk]

    cat chunkedString.txt | python3 big_string_chunker.py --stdin --un-chunk
    python3 chunkedString.py --file bigString.txt --un-chunk

# gRPC-Scan Usage

[grpc_scan.py](grpc_scan.py)
        
    python3 grpc_scan.py --file main.js
    OR
    cat main.js | python3 grpc_scan.py --stdin

# gRPC-Scan Javascript Files Note

For saving javascript files, you have to open them in browser and save the file or download it directly.

**Do not** copy and paste the javascript content.

ProtoBuf Version Support:
- Version 3 [OK]
- Version 2 [Some Features do not work]


## Requirements


        pip install -r requirements.txt


## gRPC-Scan Help

    python3 grpc_scan.py --help

    python3 grpc_scan.py [INPUT]
    Input Arguments:
      --file      file name of js file
      --stdin     get input from standard input
    Help:
      --help      print help message

## gRPC-Scan Output Example

        
    python3 grpc_scan.py --file main.js

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

# References
This repo uses two other library directly in [lib](libs) directory to remove some dependencies for new burp extension:
- [six](https://github.com/benjaminp/six)
- [blackboxprotobuf](https://github.com/nccgroup/blackboxprotobuf)
