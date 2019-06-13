import asyncio
import socket
import struct
from asyncio import Transport

ADD_RTYPE_IPV4 = 1
ADD_RTYPE_DOMAIN = 3
ADD_RTYPE_IPV6 = 4

CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP_ASSOCIATE = 3
CMD_REG_SURVIVOR = 250

RSP_RESCUER = b'\xff\x53\x53'
RSP_SOCKET5_VERSION = b'\x05\x00'
RSP_SUCCESS = b'\x05\x00\x00\x01'
RSP_CONNECTION_REFUSED = b'\x05\x05\x00\x01'
RSP_COMMAND_NOT_SUPPORTED = b'\x05\x07\x00\x01'
RSP_ADDRESS_TYPE_NOT_SUPPORTED = b'\x05\x08\x00\x01'

rescuer_protocols = []


class RemoteClientProtocol(asyncio.Protocol):
    transport = None
    survivor_transport = None

    def __init__(self, transport: Transport):
        self.survivor_transport = transport

    def connection_made(self, transport: Transport):
        self.transport = transport
        print('Remote server connect successful.')

    def data_received(self, data):
        self.survivor_transport.write(data)
        print('Remote data: ', data)

    def connection_lost(self, exc):
        self.survivor_transport.close()
        print('Remote server closed the connection')


class SurvivorClientProtocol(asyncio.Protocol):
    socket5_flag = False
    transport = None
    remote_transport = None

    def __init__(self, loop, addr, port):
        self.loop = loop
        self.addr = addr
        self.port = port

    def connection_made(self, transport: Transport):
        self.transport = transport
        self.transport.write(RSP_RESCUER)
        print('Survivor connect successful.')

    def data_received(self, data):
        print('Survivor data: ', data)
        data = bytearray(data)

        if self.remote_transport:
            return self.remote_transport.write(data)
        elif data[0:3] == b'\x05\x01\x00':
            del data[0:3]
            self.socket5_flag = True

        if self.socket5_flag:
            if len(data) < 4:
                print('No socket5 bytes')
                return self.transport.write(RSP_SOCKET5_VERSION)
            self.socket5_flag = False
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
            elif mode == CMD_UDP_ASSOCIATE:
                print('No supported CMD_UDP_ASSOCIATE')
            else:
                print('RSP_COMMAND_NOT_SUPPORTED')
                return self.transport.write(RSP_COMMAND_NOT_SUPPORTED)
        else:
            print('Unknown')

    def connection_lost(self, exc):
        if self.remote_transport:
            self.remote_transport.close()
        self.loop.create_task(connect_survivor(self.loop, self.addr, self.port))
        print('Survivor closed the connection')


async def connect_survivor(loop, addr, port):
    await loop.create_connection(
        lambda: SurvivorClientProtocol(loop, addr, port),
        addr, port)


async def connect_remote(local: SurvivorClientProtocol, addr, port):
    transport, protocol = await local.loop.create_connection(
        lambda: RemoteClientProtocol(local.transport),
        addr, port)
    remote = transport.get_extra_info('sockname')
    reply = RSP_SUCCESS + socket.inet_aton(remote[0]) + struct.pack('>H', remote[1])
    local.remote_transport = transport
    local.transport.write(reply)
    print('Local send: ', reply)


async def main():
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    on_con_lost = loop.create_future()
    addr, port = '127.0.0.1', 1080
    transport, protocol = await loop.create_connection(
        lambda: SurvivorClientProtocol(loop, addr, port),
        addr, port)
    for i in range(9):
        loop.create_task(connect_survivor(loop, addr, port))
    try:
        await on_con_lost
    finally:
        transport.close()


asyncio.run(main())
