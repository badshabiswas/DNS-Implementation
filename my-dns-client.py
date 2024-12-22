import sys
import random
import time
from socket import *


def extract_name(response, index, hostName):
    name = ""
    if response[index:index + 2] == "c0":
        name += hostName
        index += 2
    else:
        name_length = int(response[index:index + 2], 16)
        for _ in range(name_length):
            index += 2
            name += chr(int(response[index:index + 2], 16))
        name += "." + hostName
        index += 2 * name_length
    return name, index


def extract_integer(response, index):
    valueue = int(response[index:index + 8], 16)
    index += 8
    return valueue, index


def answerPrintSOA(hostName, response):
    index = 24
    NAME, index = extract_name(response, index, hostName)
    print("answer.NAME:", NAME)
    TYPE = "SOA"
    print("answer.TYPE:", TYPE)
    CLASS = "IN"
    print("answer.CLASS:", CLASS)
    TTL, index = extract_integer(response, index)
    print("answer.TTL:", TTL)
    RDLENGTH, index = extract_integer(response, index)
    print("answer.RDLENGTH:", RDLENGTH)
    primaryNameServer, index = extract_name(response, index, hostName)
    print("answer.RDATA.Primary name server:", primaryNameServer)
    responsible_authority_mailbox, index = extract_name(response, index, hostName)
    print("answer.RDATA.Responsible authority's mailbox:", responsible_authority_mailbox)
    serial_number, index = extract_integer(response, index)
    print("answer.RDATA.Serial number:", serial_number)
    refresh_intervalue, index = extract_integer(response, index)
    print("answer.RDATA.Refresh intervalue:", refresh_intervalue)
    retry_intervalue, index = extract_integer(response, index)
    print("answer.RDATA.Retry intervalue:", retry_intervalue)
    expire_intervalue, index = extract_integer(response, index)
    print("answer.RDATA.Expire intervalue:", expire_intervalue)
    minimum_ttl, index = extract_integer(response, index)
    print("answer.RDATA.Minimum TTL:", minimum_ttl)
    return index // 2


def responseProcessor(hostName, response):
    print("Processing DNS response..")
    header = response[:24]
    header = responseHeaderProcessor(header)
    print("---------------------------------------------------------------------------")
    print("header.ID = ", header["id"])
    print("header.QR = ", header["flags"]["specifications"]["QR"]["value"])
    print("header.OPCODE = ", header["flags"]["specifications"]["OPCODE"]["value"])
    print("header.AA = ", header["flags"]["specifications"]["AA"]["value"])
    print("header.TC = ", header["flags"]["specifications"]["TC"]["value"])
    print("header.RD = ", header["flags"]["specifications"]["RD"]["value"])
    print("header.RA = ", header["flags"]["specifications"]["RA"]["value"])
    print("header.Z = ", header["flags"]["specifications"]["Z"]["value"])
    print("header.RCODE = ", header["flags"]["specifications"]["RCODE"]["value"])
    print("header.QDCOUNT = ", header["qdcount"])
    print("header.ANCOUNT = ", header["ancount"])
    print("header.NSCOUNT = ", header["nscount"])
    print("header.ARCOUNT = ", header["arcount"])
    index = questionPrinter(response[24:])
    index1 = 0
    for i in range(header["ancount"]):
        j = answerPrinter(hostName, response[24 + index + index1:])
        index1 += j
        print()
    for i in range(header["nscount"]):
        j = answerPrinter(hostName, response[24 + index + index1:])
        index1 += j
        print()
    return


def questionPrinter(response):
    i = 0
    QNAME = ""
    while True:
        length = int(response[i:i + 2], 16)
        i += 2
        if length == 0:
            break
        QNAME += ''.join(chr(int(response[i + j:i + j + 2], 16)) for j in range(0, length * 2, 2))
        i += length * 2
        QNAME += '.'
    print("question.QNAME = ", QNAME)
    QTYPE = "type A"
    print("question.QTYPE = ", QTYPE)
    QCLASS = "IN"
    print("question.QCLASS = ", QCLASS)
    return i + 8


def responseHeaderProcessor(header):
    id = header[:4]
    flags = bin(int(header[4:8], 16))[2:]
    qdcount = int(header[8:12], 16)
    ancount = int(header[12:16], 16)
    nscount = int(header[16:20], 16)
    arcount = int(header[20:24], 16)
    header = {
        "id": id,
        "flags": {
            "valueue": flags,
            "specifications": QRPartProcessor(flags)
        },
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount
    }
    return header


def answerPrinter(hostName, response):
    TYPE = int(response[4:8], 16)
    index = 0
    if TYPE == 5:
        index = answerPrintCNAME(hostName, response)
    if TYPE == 1:
        index = answerPrintA(hostName, response)
    if TYPE == 6:
        print("Authorized nameservers")
        index = answerPrintSOA(hostName, response)
    return index


def answerPrintCNAME(hostName, response):
    NAME = hostName
    print("answer.NAME = ", NAME)
    TYPE = "CNAME"
    print("answer.TYPE = ", TYPE)
    CLASS = "IN"
    print("answer.CLASS = ", CLASS)
    TTL = int(response[12:20], 16)
    print("answer.TTL = ", TTL)
    RDLENGTH = int(response[20:24], 16)
    print("answer.RDLENGTH = ", RDLENGTH)
    RDATA = ""
    if response[24:26] == "c0":
        RDATA += hostName
    else:
        cname_length = int(response[24:26], 16)
        index = 24
        for i in range(cname_length):
            index += 2
            RDATA += chr(int(response[index: index + 2], 16))
        RDATA += hostName[3:]
    print("answer.RDATA = ", RDATA)
    return 24 + (RDLENGTH * 2)


def QRPartProcessor(QRPart):
    QR = int(QRPart[:1], 16)
    OPCODE = int(QRPart[1:5], 16)
    AA = int(QRPart[5:6], 16)
    TC = int(QRPart[6:7], 16)
    RD = int(QRPart[7:8], 16)
    RA = int(QRPart[8:9], 16)
    Z = int(QRPart[9:12], 16)
    RCODE = int(QRPart[12:], 16)
    dict_QRPart = {
        "QR": {"value": QR, "explanation": None},
        "OPCODE": {"value": OPCODE, "explanation": "A perfect query"},
        "AA": {"value": AA, "explanation": None},
        "TC": {"value": TC, "explanation": "Cut Short"},
        "RD": {"value": RD, "explanation": "Should be back"},
        "RA": {"value": RA, "explanation": None},
        "Z": {"value": Z, "explanation": None},
        "RCODE": {"value": RCODE, "explanation": None}}
    dict_QRPart["QR"]["explanation"] = "query" if dict_QRPart["QR"]["value"] == 0 else "reply"
    dict_QRPart["AA"]["explanation"] = "Authorized" if dict_QRPart["AA"]["value"] == 1 else "Unathorized Server"
    dict_QRPart["RA"]["explanation"] = "Recursion Available" if dict_QRPart["RA"][
                                                                    "value"] == 1 else "Not possible to to previous step"
    if (dict_QRPart["RCODE"]["value"] == 0):
        dict_QRPart["RCODE"]["explanation"] = "Everything alright"
    elif (dict_QRPart["RCODE"]["value"] == 1):
        dict_QRPart["RCODE"]["explanation"] = "Formatting Problem"
    elif (dict_QRPart["RCODE"]["value"] == 2):
        dict_QRPart["RCODE"]["explanation"] = "No response from Server"
    elif (dict_QRPart["RCODE"]["value"] == 3):
        dict_QRPart["RCODE"]["explanation"] = "Naming Problem"
    elif (dict_QRPart["RCODE"]["value"] == 4):
        dict_QRPart["RCODE"]["explanation"] = "Out of scope"
    else:
        dict_QRPart["RCODE"]["explanation"] = "No response"
    return dict_QRPart


def answerPrintA(hostName, response):
    NAME = hostName
    print("answer.NAME =", NAME)
    TYPE = "type A"
    print("answer.TYPE = ", TYPE)
    CLASS = "IN"
    print("answer.CLASS = ", CLASS)
    TTL = int(response[12:20], 16)
    print("answer.TTL = ", TTL)
    RDLENGTH = int(response[20:24], 16)
    print("answer.RDLENGTH = ", RDLENGTH)
    IP1 = str(int(response[24:26], 16))
    IP2 = str(int(response[26:28], 16))
    IP3 = str(int(response[28:30], 16))
    IP4 = str(int(response[30:32], 16))
    RDATA = IP1 + "." + IP2 + "." + IP3 + "." + IP4
    print(f"answer.RDATA = {RDATA}    ## resolved IP address ##")
    print("---------------------------------------------------------------------------")
    index = 32
    return index


def headerProcessor(response):
    header_data = response[:24]
    ID = header_data[:4]
    QRPart_hex = header_data[4:8]
    QDCOUNT = int(header_data[8:12], 16)
    ANCOUNT = int(header_data[12:16], 16)
    NSCOUNT = int(header_data[16:20], 16)
    ARCOUNT = int(header_data[20:24], 16)
    QRPart_bin = bin(int(QRPart_hex, 16))[2:].zfill(4)
    QRPart_details = QRPartProcessor(QRPart_bin)

    header = {
        "ID": ID,
        "QRPart": {
            "valueue": QRPart_bin,
            "specifications": QRPart_details
        },
        "QDCOUNT": QDCOUNT,
        "ANCOUNT": ANCOUNT,
        "NSCOUNT": NSCOUNT,
        "ARCOUNT": ARCOUNT
    }
    return header


def queryProcessor(DNSQuery):
    print("Contacting DNS server..")
    serverName = "8.8.8.8"
    serverPort = 53
    clientSocket = socket(AF_INET, SOCK_DGRAM)
    clientSocket.settimeout(5)
    print("Sending DNS Query ..")
    try:
        clientSocket.sendto(bytearray.fromhex(DNSQuery), (serverName, serverPort))
        result, DNSServerAddress = clientSocket.recvfrom(2048)
    except timeout:
        clientSocket.close()
        return None
    except ValueError:
        clientSocket.close()
        time.sleep(5)
        return None
    clientSocket.close()
    finalResult = result.hex()
    return finalResult


def questionBuilder(hostName):
    hostName2URLPart = hostName.strip().split(".")
    QNAME = ""
    for i in hostName2URLPart:
        part_length_hex = format(len(i), '02x')
        ascii_octets_valueue = ''.join(format(ord(char), '02x') for char in i)
        QNAME += part_length_hex + ascii_octets_valueue

    QNAME += "00"
    QTYPE = "0001"
    QCLASS = "0001"
    return QNAME + QTYPE + QCLASS


def headerBuilder():
    ID = format(random.getrandbits(16), '04x')
    header_flags = "0100"
    QDCOUNT = "0001"
    ANCOUNT = "0000"
    NSCOUNT = "0000"
    ARCOUNT = "0000"
    dns_header = ID + header_flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    return dns_header


def main():
    hostName = sys.argv[1].strip()
    header = headerBuilder()
    question = questionBuilder(hostName)
    print("Preparing DNS Query..")
    DNSQuery = header + question
    for i in range(3):
        response = queryProcessor(DNSQuery)

        if response is not None and i != 2:
            print("DNS response received (attempt %d of 3)" % (i + 1))
            responseProcessor(hostName, response)
            break
        elif i == 2:
            print("time out")


if __name__ == "__main__":
    main()
