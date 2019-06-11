import asyncio
import socket
import struct
from asyncio import Transport, AbstractEventLoop

ADD_RTYPE_IPV4 = 1
ADD_RTYPE_DOMAIN = 3
ADD_RTYPE_IPV6 = 4

CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP_ASSOCIATE = 3
CMD_REG_SURVIVOR = 250

RSP_SOCKET5_VERSION = b'\x05\x00'
RSP_SUCCESS = b'\x05\x00\x00\x01'
RSP_CONNECTION_REFUSED = b'\x05\x05\x00\x01'
RSP_COMMAND_NOT_SUPPORTED = b'\x05\x07\x00\x01'
RSP_ADDRESS_TYPE_NOT_SUPPORTED = b'\x05\x08\x00\x01'


class EchoClientProtocol(asyncio.Protocol):
    transport = None
    local_transport = None

    def __init__(self, transport: Transport):
        self.local_transport = transport

    def connection_made(self, transport: Transport):
        self.transport = transport
        print('Remote server connect successful.')

    def data_received(self, data):
        self.local_transport.write(data)
        print('Remote data: ', data)

    def connection_lost(self, exc):
        self.local_transport.close()
        print('Remote server closed the connection')


class EchoServerProtocol(asyncio.Protocol):
    socket5_flag = False
    transport = None
    remote_transport = None

    def __init__(self, loop: AbstractEventLoop):
        self.loop = loop

    def connection_made(self, transport: Transport):
        peername = transport.get_extra_info('peername')
        print('Connection from local {}'.format(peername))
        self.transport = transport

    def data_received(self, data):
        if self.socket5_flag:
            self.socket5_flag = False
            if len(data) < 4:
                return self.transport.close()
            data = bytearray(data)
            tpm_data = data[0:4]
            del data[0:4]
            mode = tpm_data[1]
            if mode == CMD_CONNECT:  # 1. Tcp connect
                atyp = tpm_data[3]
                if atyp == ADD_RTYPE_IPV4:  # IPv4
                    addr = socket.inet_ntoa(data[0:4])
                    del data[0:4]
                elif atyp == ADD_RTYPE_DOMAIN:  # Domain name
                    addr = data[1:1 + data[0]]  # self.rfile.read(sock.recv(1)[0])
                    del data[0:1 + data[4]]
                else:
                    print('RSP_ADDRESS_TYPE_NOT_SUPPORTED')
                    return self.transport.write(RSP_ADDRESS_TYPE_NOT_SUPPORTED)
                port = struct.unpack('>H', data[0:2])
                del data[0:2]
                return self.loop.create_task(connect_remote(self, addr, port[0]))
            else:
                print('RSP_COMMAND_NOT_SUPPORTED')
                return self.transport.write(RSP_COMMAND_NOT_SUPPORTED)
        elif data == b'\x05\x01\x00':
            self.socket5_flag = True
            return self.transport.write(RSP_SOCKET5_VERSION)
        elif self.remote_transport:
            print('Local data: ', data)
            return self.remote_transport.write(data)
        print('Unknown data: ', data)


async def connect_remote(server: EchoServerProtocol, addr, port):
    transport, protocol = await server.loop.create_connection(
        lambda: EchoClientProtocol(server.transport),
        addr, port)
    remote = transport.get_extra_info('sockname')
    reply = RSP_SUCCESS + socket.inet_aton(remote[0]) + struct.pack('>H', remote[1])
    server.remote_transport = transport
    server.transport.write(reply)


async def main():
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    server = await loop.create_server(
        lambda: EchoServerProtocol(loop),
        '0.0.0.0', 1080)

    async with server:
        await server.serve_forever()


asyncio.run(main())
