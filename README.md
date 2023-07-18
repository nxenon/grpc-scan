# GRPC-Scan

GRPC-Scan finds GRPC Endpoints, Services, Messages and fields in Javascript files. This is useful when you are pentesting web application which uses grpc-web javascript webpacked files.


# Requirements

    pip3 install -r requirements.txt

# Javascript Files Note

For saving javascript files, you have to open them in browser and save the file or download it directly.

**Do not** copy and paste the javascript content. 

# Usage
        
    python3 grpc-scan.py --file main.js
    OR
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
    +------------+--------------------+------------+
    | Field Name |    Field Number    | Field Type |
    +============+====================+============+
    | Message    | Proto3StringField  | 1          |
    +------------+--------------------+------------+
    | Name       | Proto3StringField  | 2          |
    +------------+--------------------+------------+
    | Age        | Proto3IntField     | 3          |
    +------------+--------------------+------------+
    | IsAdmin    | Proto3BooleanField | 4          |
    +------------+--------------------+------------+
    | Weight     | Proto3FloatField   | 5          |
    +------------+--------------------+------------+
    | Test       | Proto3StringField  | 6          |
    +------------+--------------------+------------+
    | Test2      | Proto3StringField  | 7          |
    +------------+--------------------+------------+
    | Test3      | Proto3StringField  | 16         |
    +------------+--------------------+------------+
    | Test4      | Proto3StringField  | 20         |
    +------------+--------------------+------------+
    
    grpc.gateway.testing.EchoResponse:
    +--------------+--------------------+------------+
    |  Field Name  |    Field Number    | Field Type |
    +==============+====================+============+
    | Message      | Proto3StringField  | 1          |
    +--------------+--------------------+------------+
    | Name         | Proto3StringField  | 2          |
    +--------------+--------------------+------------+
    | Age          | Proto3IntField     | 3          |
    +--------------+--------------------+------------+
    | IsAdmin      | Proto3BooleanField | 4          |
    +--------------+--------------------+------------+
    | Weight       | Proto3FloatField   | 5          |
    +--------------+--------------------+------------+
    | Test         | Proto3StringField  | 6          |
    +--------------+--------------------+------------+
    | Test2        | Proto3StringField  | 7          |
    +--------------+--------------------+------------+
    | Test3        | Proto3StringField  | 16         |
    +--------------+--------------------+------------+
    | Test4        | Proto3StringField  | 20         |
    +--------------+--------------------+------------+
    | MessageCount | Proto3IntField     | 8          |
    +--------------+--------------------+------------+
    
    grpc.gateway.testing.ClientStreamingEchoRequest:
    +------------+-------------------+------------+
    | Field Name |   Field Number    | Field Type |
    +============+===================+============+
    | Message    | Proto3StringField | 1          |
    +------------+-------------------+------------+
    
    grpc.gateway.testing.ClientStreamingEchoResponse:
    +--------------+----------------+------------+
    |  Field Name  |  Field Number  | Field Type |
    +==============+================+============+
    | MessageCount | Proto3IntField | 1          |
    +--------------+----------------+------------+
