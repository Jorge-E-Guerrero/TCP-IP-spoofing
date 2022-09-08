from encodings import utf_8
import socket
from sqlite3 import Row

ip_destination = input('Ingresa la ip que quieres spoofear\n')
hex_destination = ip_destination.split('.')


while len(hex_destination) != 4:
    print('ip no valida\n')
    ip_destination = input('Ingresa la ip que quieres spoofear\n')
    hex_destination = ip_destination.split('.')
else:
    #print(len(hex_destination))
    for i, item in enumerate(hex_destination):
        #hex_destination[i] = str(hex(int(hex_destination[i])))
        hex_destination[i] = '0x{:02X}'.format(int(hex_destination[i]))
        #print(hex_destination[i] )

    ip_source = input('Ingresa la ip desde la que quieres spoofear\n')
    hex_source = ip_destination.split('.')
    
    while len(hex_destination) != 4:
        print('ip no valida\n')
        ip_source = input('Ingresa la ip desde la que quieres spoofear\n')
        hex_source = ip_source.split('.')
    else:
        for i, item in enumerate(hex_source):
        #hex_destination[i] = str(hex(int(hex_destination[i])))
            hex_source[i] = '0x{:02X}'.format(int(hex_source[i]))
            print(hex_source[i] )



        #x = '/'
        #nstr = ''.join([x,hex_destination[0],x,hex_destination[1],x, hex_destination[2],x, hex_destination[3]])
        #print(nstr)
        #nstr = nstr.replace('/',"\\")
        #nstr = bytes(nstr, encoding='utf-8')
        #print (nstr)
        print(hex_destination)
        print(hex_source)

        #print(bytes([int(x,0) for x in hex_destination]))

        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind(("wlp4s0", 0))

        #ethernet header

        ethernet  = b'\x00\x0c\x29\xd3\xbe\xd6' # MAC Address Destination
        ethernet += b'\x00\x0c\x29\xe0\xc4\xaf' # MAC Address Source
        ethernet += b'\x08\x00'                 # Protocol-Type: IPv4


        #ip Header

        hex_ip_header_1 = ['0x45','0x00','0x00','0x28']
        #ip_header  = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
        ip_header = bytes([int(x,0) for x in hex_ip_header_1]) # Version, IHL, Type of Service | Total Length
        
        hex_ip_header_2 = ['0xab','0xcd','0x00','0x00']
        #ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
        ip_header += bytes([int(x,0) for x in hex_ip_header_2]) # Identification | Flags, Fragment Offset
        
        hex_ip_header_3 = ['0x40','0x06','0x00','0x00']
        ip_header += b'\x40\x06\xa6\xec'  # TTL, Protocol | Header Checksum
        
        checksum_ip = int('0x0000',0) #0xffff = 65535

        ip_byte_1 = '0x' + hex_ip_header_1[0].replace('0x','') + hex_ip_header_1[1].replace('0x','')
        ip_byte_2 = '0x' + hex_ip_header_1[2].replace('0x','') + hex_ip_header_1[3].replace('0x','')
        ip_byte_3 = '0x' + hex_ip_header_2[0].replace('0x','') + hex_ip_header_2[1].replace('0x','')
        ip_byte_4 = '0x' + hex_ip_header_2[2].replace('0x','') + hex_ip_header_2[3].replace('0x','')
        ip_byte_5 = '0x' + hex_ip_header_3[0].replace('0x','') + hex_ip_header_3[1].replace('0x','')
        ip_byte_6 = '0x' + hex_ip_header_3[2].replace('0x','') + hex_ip_header_3[3].replace('0x','')
        ip_byte_7 = '0x' + hex_source[0].replace('0x','') + hex_source[1].replace('0x','')
        ip_byte_8 = '0x' + hex_source[2].replace('0x','') + hex_source[3].replace('0x','')
        ip_byte_9 = '0x' + hex_destination[0].replace('0x','') + hex_destination[1].replace('0x','')
        ip_byte_10 = '0x' + hex_destination[2].replace('0x','') + hex_destination[3].replace('0x','')
        
        checksum_ip += int(ip_byte_1,0)
        checksum_ip += int(ip_byte_2,0)
        checksum_ip += int(ip_byte_3,0)
        checksum_ip += int(ip_byte_4,0)
        checksum_ip += int(ip_byte_5,0)
        checksum_ip += int(ip_byte_6,0)
        checksum_ip += int(ip_byte_7,0)
        checksum_ip += int(ip_byte_8,0)
        checksum_ip += int(ip_byte_9,0)
        checksum_ip += int(ip_byte_10,0)
        #for x in hex_ip_header_1:
            #checksum_ip += int(x,0)
        print(checksum_ip)
        
        
        ip_header += bytes([int(x,0) for x in hex_source]) # Source Address
        #ip_header += b'\x0a\x0a\x0a\x02'  # Source Address
        ip_header += bytes([int(x,0) for x in hex_destination]) #Destination Address
        #ip_header += b'\x0a\x0a\x0a\x01'  # Destination Address

        tcp_header  = b'\x30\x39\x00\x50' # Source Port | Destination Port
        tcp_header += b'\x00\x00\x00\x00' # Sequence Number
        tcp_header += b'\x00\x00\x00\x00' # Acknowledgement Number
        tcp_header += b'\x50\x02\x71\x10' # Data Offset, Reserved, Flags | Window Size
        tcp_header += b'\xe6\x32\x00\x00' # Checksum | Urgent Pointer

        packet = ethernet + ip_header + tcp_header
        #print(packet)
        #s.send(packet)




    



