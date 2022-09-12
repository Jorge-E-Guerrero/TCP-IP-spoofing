import socket
import string

#Funcion que valida si la ipv6 ingresada es valida

def validate_ipv6(arreglo):
    validacion = True

    for x in arreglo:
        if all(c in string.hexdigits for c in x) == False:
            validacion = False
        else:
            if int(x,16) > 65535:
                validacion = False
            print(int(x,16))

    return validacion

#Input inicial de la ip de destino y se divide en un areglo cuando encuentra el "."
ip_destination = input('Ingresa la ipv6 que quieres spoofear\n')
hex_destination = ip_destination.split(':')

#Se valida que existan 4 elementos en el arreglo
while len(hex_destination) != 8 or validate_ipv6(hex_destination) == False:
    print('ip no valida\n')
    ip_destination = input('Ingresa la ipv6 que quieres spoofear\n')
    hex_destination = ip_destination.split(':')
else:

    #Arreglo que va a contener los bytes individuales de las direcciones ipv6
    ipv6_bytes_destination = []

    #Se transforma la direccion a hex de 2 digitos
    for x in hex_destination:
        x = '{:04X}'.format(int(x,16))
        ipv6_bytes_destination.append('0x' + x[:2])
        ipv6_bytes_destination.append('0x' + x[2:])

    #Se realiza el mismo procedimiento con la ip de origen
    ip_source = input('Ingresa la ipv6 desde la que quieres spoofear\n')
    hex_source = ip_source.split(':')
    
    while len(hex_source) != 8 or validate_ipv6(hex_source) == False:
        print('ip no valida\n')
        ip_source = input('Ingresa la ip desde la que quieres spoofear\n')
        hex_source = ip_source.split(':')
    else:
        
        #Arreglo que va a contener los bytes individuales de las direcciones ipv6
        ipv6_bytes_source = []

        #Se transforma la direccion a hex de 2 digitos
        for x in hex_source:
            x = '{:04X}'.format(int(x,16))
            ipv6_bytes_source.append('0x' + x[:2])
            ipv6_bytes_source.append('0x' + x[2:])

        print(hex_destination)
        print(hex_source)


        #Se creal el socket el cual enviara el packete
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        #Se indica la interfaz por la cual se va enviar el paquete
        s.bind(("wlp4s0", 0))


        #Se arma una cadena de bytes con la cual se formara el paquete

        #ethernet header

        ethernet  = b'\x00\x0c\x29\xd3\xbe\xd6' # MAC Address Destination
        ethernet += b'\x00\x0c\x29\xe0\xc4\xaf' # MAC Address Source
        ethernet += b'\x86\xdd'                 # Protocol-Type: IPv6


        #IPv6 Header


        ipv6_header = b'\x60\x00\x00\x00'  # Version | Traffic Class | Flow Label
        ipv6_header += b'\x00\x14\x06\x40' # Payload Lenght | Next Header (TCP) | Hop Limit 

        ipv6_header += bytes([int(x,0) for x in ipv6_bytes_source])
        ipv6_header += bytes([int(x,0) for x in ipv6_bytes_destination])
        
        
        
        #TCP Header

        hex_tcp_header_1 = ['0x30','0x39','0x00','0x50'] # Source Port | Destination Port
        tcp_header  = b'\x30\x39\x00\x50' # Source Port | Destination Port
        
        tcp_header += b'\x00\x00\x00\x00' # Sequence Number
        tcp_header += b'\x00\x00\x00\x00' # Acknowledgement Number | SYN Flag

        hex_tcp_header_2 = ['0x50','0x02','0x71','0x10'] # Sequence Number        
        tcp_header += b'\x50\x02\x71\x10' # Data Offset, Reserved, Flags | Window Size
        

        hex_tcp_header_3 = ['0x00','0x00','0x00','0x00'] # Sequence Number
        
        
        #Se repite el proceso del checksum IP
        
        checksum_tcp = int('0x0000',0) #0xffff = 65535

        #Se fusionan nuevamente los pares de bytes

        tcp_byte_1 = '0x' + hex_tcp_header_1[0].replace('0x','') + hex_tcp_header_1[1].replace('0x','')
        tcp_byte_2 = '0x' + hex_tcp_header_1[2].replace('0x','') + hex_tcp_header_1[3].replace('0x','')
        tcp_byte_3 = '0x' + hex_tcp_header_2[0].replace('0x','') + hex_tcp_header_2[1].replace('0x','')
        tcp_byte_4 = '0x' + hex_tcp_header_2[2].replace('0x','') + hex_tcp_header_2[3].replace('0x','')
        
        checksum_tcp += int(tcp_byte_1,0)
        checksum_tcp += int(tcp_byte_2,0)
        checksum_tcp += int(tcp_byte_3,0)
        checksum_tcp += int(tcp_byte_4,0)

        #Se utilizan nuevamente las direcciones de origen y destino

        for x in hex_destination:
            checksum_tcp +=(int(x,16))

        for x in hex_source:
            checksum_tcp +=(int(x,16))
        


        checksum_tcp += int('0x1a',0) # Protocol 0x06 (TCP) + TCP lenght 0x14 = 0x1a

        print('\nSubtotal TCP: '+ str(checksum_tcp))

        #Se aplica la operacion modulo

        while checksum_tcp > 65535:
            checksum_tcp = checksum_tcp - 65535

        checksum_tcp = hex(65535 - checksum_tcp)

        #Se verifica el largo del hex

        if len(checksum_tcp) < 6:
            checksum_tcp = '0x{:04X}'.format(int(checksum_tcp,16))
            checksum_tcp = str(checksum_tcp)
            #print(checksum_tcp)
        
        
        #Se divide el hex y se agrega al arreglo

        checksum_tcp = checksum_tcp[2:]
        

        print('Checksum TCP: ' + str(checksum_tcp))
        checksum_tcp_byte_1 = '0x' + checksum_tcp[:2]
        checksum_tcp_byte_2 = '0x' + checksum_tcp[2:]
        
        hex_tcp_header_3[0] = checksum_tcp_byte_1
        hex_tcp_header_3[1] = checksum_tcp_byte_2

        print(hex_tcp_header_3)
        print('\n')
        
        #Se ingresa el hex con el nuevo checksum a la cadena de bytes

        tcp_header += bytes([int(x,0) for x in hex_tcp_header_3]) # Checksum | Urgent Pointer
        #tcp_header += b'\xe6\x32\x00\x00'

        packet = ethernet + ipv6_header + tcp_header
        #print(packet)
        s.send(packet)



#0x0e4a 0xfe59