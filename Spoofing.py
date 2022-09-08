from encodings import utf_8
import socket
from sqlite3 import Row
import string


ip_destination = input('Ingresa la ip que quieres spoofear\n')
hex_destination = ip_destination.split('.')


if len(hex_destination) == 4:
    #print(len(hex_destination))
    for i, item in enumerate(hex_destination):
        #hex_destination[i] = str(hex(int(hex_destination[i])))
        hex_destination[i] = '0x{:02X}'.format(int(hex_destination[i]))
        print(hex_destination[i] )


    #x = '/'
    #nstr = ''.join([x,hex_destination[0],x,hex_destination[1],x, hex_destination[2],x, hex_destination[3]])
    #print(nstr)
    #nstr = nstr.replace('/',"\\")
    #nstr = bytes(nstr, encoding='utf-8')
    #print (nstr)

    print(bytes([int(x,0) for x in hex_destination]))

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("wlp4s0", 0))

    ethernet  = b'\x00\x0c\x29\xd3\xbe\xd6' # MAC Address Destination
    ethernet += b'\x00\x0c\x29\xe0\xc4\xaf' # MAC Address Source
    ethernet += b'\x08\x00'                 # Protocol-Type: IPv4

    ip_header  = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
    ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
    ip_header += b'\x40\x06\xa6\xec'  # TTL, Protocol | Header Checksum
    
    ip_header += bytes([int(x,0) for x in hex_destination])
    #ip_header += bytes(hex_destination)
    #ip_header += b'\x0a\x0a\x0a\x02'  # Source Address
    ip_header += b'\x0a\x0a\x0a\x01'  # Destination Address

    tcp_header  = b'\x30\x39\x00\x50' # Source Port | Destination Port
    tcp_header += b'\x00\x00\x00\x00' # Sequence Number
    tcp_header += b'\x00\x00\x00\x00' # Acknowledgement Number
    tcp_header += b'\x50\x02\x71\x10' # Data Offset, Reserved, Flags | Window Size
    tcp_header += b'\xe6\x32\x00\x00' # Checksum | Urgent Pointer

    packet = ethernet + ip_header + tcp_header
    print(packet)
    #s.send(packet)



else:
    print('ip no valida')