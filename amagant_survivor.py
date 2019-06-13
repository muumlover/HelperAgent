import asyncio
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

rescuer_protocols = []


class SurvivorServerProtocol(asyncio.Protocol):
    is_rescuer = False
    socket5_flag = False
    transport = None
    other_transport = None

    def __init__(self, loop: AbstractEventLoop):
        self.loop = loop

    def connection_made(self, transport: Transport):
        peername = transport.get_extra_info('peername')
        print('Connection from local {}'.format(peername))
        self.transport = transport
        self.transport.write(RSP_SOCKET5_VERSION)

    def data_received(self, data):
        if self.is_rescuer:
            print('Rescuer data: ', data)
            if self.other_transport:
                return self.other_transport.write(data)
        else:
            print('Local data: ', data)
            if self.other_transport:
                return self.other_transport.write(data)
            elif data[0:3] == b'\x05\x01\x00':
                if rescuer_protocols:
                    other = rescuer_protocols.pop(-1)
                    self.other_transport = other.transport
                    other.other_transport = self.transport
                    print('Local send data: ', data)
                    self.other_transport.write(data)
                else:
                    print('rescuer list is null')
            elif data[0:3] == b'\xff\x53\x53':
                self.is_rescuer = True
                print('new rescuer added. ')
                rescuer_protocols.append(self)
                pass

    def connection_lost(self, exc):
        if self.other_transport:
            self.other_transport.close()
        if self.is_rescuer:
            if self in rescuer_protocols:
                rescuer_protocols.remove(self)
            print('Rescuer closed the connection')
        else:
            print('Local client closed the connection')


async def main():
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    server = await loop.create_server(
        lambda: SurvivorServerProtocol(loop),
        '0.0.0.0', 1080)

    async with server:
        await server.serve_forever()


asyncio.run(main())
