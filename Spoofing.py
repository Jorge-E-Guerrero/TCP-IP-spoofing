import socket
import string

def validate_ip(arreglo):
    validacion = True
    for x in arreglo:
        if all(c in string.digits for c in x) == False:
            validacion = False
        else:
            if int(x) >255:
                validacion = False
    return validacion


#Input inicial de la ip de destino y se divide en un areglo cuando encuentra el "."
ip_destination = input('Ingresa la ip que quieres spoofear\n')
hex_destination = ip_destination.split('.')

#Se valida que existan 4 elementos en el arreglo
while len(hex_destination) != 4 or validate_ip(hex_destination) == False:
    print('ip no valida\n')
    ip_destination = input('Ingresa la ip que quieres spoofear\n')
    hex_destination = ip_destination.split('.')
else:

    #Se transforma la direccion a hex de 2 digitos
    for i, item in enumerate(hex_destination):
        hex_destination[i] = '0x{:02X}'.format(int(hex_destination[i]))


    #Se realiza el mismo procedimiento con la ip de origen
    ip_source = input('Ingresa la ip desde la que quieres spoofear\n')
    hex_source = ip_source.split('.')
    
    while len(hex_source) != 4 or validate_ip(hex_source) == False:
        print('ip no valida\n')
        ip_source = input('Ingresa la ip desde la que quieres spoofear\n')
        hex_source = ip_source.split('.')
    else:
        for i, item in enumerate(hex_source):
            hex_source[i] = '0x{:02X}'.format(int(hex_source[i]))


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
        ethernet += b'\x08\x00'                 # Protocol-Type: IPv4


        #IP Header

        hex_ip_header_1 = ['0x45','0x00','0x00','0x28'] # Version, IHL, Type of Service | Total Length
        #ip_header  = b'\x45\x00\x00\x28'  
        ip_header = bytes([int(x,0) for x in hex_ip_header_1])
        
        hex_ip_header_2 = ['0xab','0xcd','0x00','0x00'] # Identification | Flags, Fragment Offset
        #ip_header += b'\xab\xcd\x00\x00'  
        ip_header += bytes([int(x,0) for x in hex_ip_header_2])
        
        hex_ip_header_3 = ['0x40','0x06','0x00','0x00'] # TTL, Protocol | Header Checksum
        #ip_header += b'\x40\x06\xa6\xec'  
        
        #Iniciamos un checksum en 0 bits
        checksum_ip = int('0x0000',0) #0xffff = 65535 maximo tamaño del checksum

        #El checksum opera de 2 Bytes en 2 Bytes, por lo que se juntan todos los pares de hex para formar hex de 2 Bytes

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
        
        
        #Transformamos los pares de Bytes a ints para realizar la suma
        
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


        print('\nSubtotal IP: '+ str(checksum_ip))


        #El checksum no puede superar los 2 Bytes por lo que luego de pasar el limite se reinicia el contador
        #Se aplica la operacion modulo a la suma total

        while checksum_ip > 65535:
            checksum_ip = checksum_ip - 65535

        checksum_ip = hex(65535 - checksum_ip)

        #Si el hex resultante es menor de 4 digitos se formatea el hex para que aparezcan los ceros

        if len(checksum_ip) < 6:
            checksum_ip = '0x{:04X}'.format(int(checksum_ip,16))
            checksum_ip = str(checksum_ip)


        #El paquete se envia por Bytes individuales por lo que hay que separar el checksum

        checksum_ip = checksum_ip[2:]
        print('Checksum IP: ' + str(checksum_ip))
        checksum_ip_byte_1 = '0x' + checksum_ip[:2]
        checksum_ip_byte_2 = '0x' + checksum_ip[2:]

        #Cambiamos el valor del arreglo con el hex del checksum en cero
        
        hex_ip_header_3[2] = checksum_ip_byte_1
        hex_ip_header_3[3] = checksum_ip_byte_2

        print(hex_ip_header_3)
        print('\n')

        #Se agrega la cadena de bytes con el checksum calculado a la cadena de bytes

        ip_header += bytes([int(x,0) for x in hex_ip_header_3])
        
        
        #Se toman los arreglos de las direcciones IP de origen y destino y se suman a la cadena de bytes

        ip_header += bytes([int(x,0) for x in hex_source]) # Source Address
        #ip_header += b'\x0a\x0a\x0a\x02'  
        ip_header += bytes([int(x,0) for x in hex_destination]) #Destination Address
        #ip_header += b'\x0a\x0a\x0a\x01'  

        
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
        
        checksum_tcp += int(ip_byte_7,0)
        checksum_tcp += int(ip_byte_8,0)
        checksum_tcp += int(ip_byte_9,0)
        checksum_tcp += int(ip_byte_10,0)

        checksum_tcp += int('0x1a',0) # Protocol 0x06 + TCP lenght 0x14 = 0x1a

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

        packet = ethernet + ip_header + tcp_header
        #print(packet)
        s.send(packet)



