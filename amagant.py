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

RSP_RESCUER = b'\xff\x53\x53'
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
        print('connection from client {}'.format(peername))
        self.transport = transport
        # print('Survivor send data: ', RSP_SOCKET5_VERSION)
        # self.transport.write(RSP_SOCKET5_VERSION)

    def data_received(self, data):
        if self.is_rescuer:
            print('recv from rescuer: ', data)
            if self.other_transport:
                self.other_transport.write(data)
                print('send to local: ', data)
        else:
            if self.other_transport:
                print('recv from local: ', data)
                self.other_transport.write(data)
                print('send to rescuer: ', RSP_SOCKET5_VERSION)
            elif data[0] == 5 or data[0:7] == b'CONNECT':
                print('recv from local: ', data)
                if rescuer_protocols:
                    other = rescuer_protocols.pop(-1)
                    self.other_transport = other.transport
                    other.other_transport = self.transport
                    self.other_transport.write(data)
                    print('send to rescuer: ', data)
                else:
                    print('rescuer list is null')
            elif data[0:3] == b'\xff\x53\x53':
                print('recv from rescuer: ', data)
                self.is_rescuer = True
                rescuer_protocols.append(self)
                print('new rescuer added.')
            else:
                print('recv from client: ', data)
                print('unknown data.')

    def connection_lost(self, exc):
        if self.other_transport:
            self.other_transport.close()
        if self.is_rescuer:
            if self in rescuer_protocols:
                rescuer_protocols.remove(self)
            print('rescuer client closed the connection')
        else:
            print('local client closed the connection')


class RemoteClientProtocol(asyncio.Protocol):
    transport = None
    survivor_transport = None

    def __init__(self, transport: Transport):
        self.survivor_transport = transport

    def connection_made(self, transport: Transport):
        self.transport = transport
        print('connect to remote server successful.')

    def data_received(self, data):
        print('recv from remote: ', data)
        self.survivor_transport.write(data)
        print('send to survivor: ', data)

    def connection_lost(self, exc):
        self.survivor_transport.close()
        print('remote server connection closed.')


class RescuerClientProtocol(asyncio.Protocol):
    socket5_flag = False
    http_flag = False
    transport = None
    remote_transport = None

    def __init__(self, loop, addr, port):
        self.loop = loop
        self.addr = addr
        self.port = port

    def connection_made(self, transport: Transport):
        self.transport = transport
        self.transport.write(RSP_RESCUER)
        print('connect to survivor server successful.')

    def data_received(self, data):
        print('recv from survivor: ', data)
        data = bytearray(data)

        if self.remote_transport:
            self.remote_transport.write(data)
            print('send to remote: ', data)
            return
        elif data[0] == 5:
            self.socket5_flag = True
        elif len(data) > 8 and data[0:7] == b'CONNECT':
            self.http_flag = True

        if self.socket5_flag:
            self.socket5_flag = False

            if len(data) >= 2 and (data[1] + 2 == len(data) or (len(data) > data[1] + 2 and data[data[1] + 2] == 5)):
                del data[0:data[1] + 2]
                self.transport.write(RSP_SOCKET5_VERSION)
                print('send to survivor: ', RSP_SOCKET5_VERSION)

            if len(data) < 4:
                return
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
                    self.transport.write(RSP_ADDRESS_TYPE_NOT_SUPPORTED)
                    print('send to survivor : ', RSP_ADDRESS_TYPE_NOT_SUPPORTED)
                    print('RSP_ADDRESS_TYPE_NOT_SUPPORTED')
                    return
                port = struct.unpack('>H', data[0:2])
                del data[0:2]

                def callback(transport, protocol):
                    remote = transport.get_extra_info('sockname')
                    reply = RSP_SUCCESS + socket.inet_aton(remote[0]) + struct.pack('>H', remote[1])
                    self.remote_transport = transport
                    self.transport.write(reply)
                    print('send to survivor: ', reply)

                return self.loop.create_task(connect_remote(self, addr, port[0], callback))
            elif mode == CMD_BIND:
                print('unsupported CMD_BIND')
            elif mode == CMD_UDP_ASSOCIATE:
                print('unsupported CMD_UDP_ASSOCIATE')
            else:
                self.transport.write(RSP_COMMAND_NOT_SUPPORTED)
                print('send to survivor: ', RSP_COMMAND_NOT_SUPPORTED)
                print('RSP_COMMAND_NOT_SUPPORTED')
                return
        elif self.http_flag:
            data_str = data.decode()
            _, remote, _ = data_str.split(' ')
            addr, port = remote.split(':')

            def callback(transport, protocol):
                remote = transport.get_extra_info('sockname')
                reply = b'HTTP/1.0 200 Connection established\r\n\r\n'
                self.remote_transport = transport
                self.transport.write(reply)
                print('send to survivor: ', reply)

            return self.loop.create_task(connect_remote(self, addr, port, callback))
            pass
        else:
            print('unknown data.')

    def connection_lost(self, exc):
        if self.remote_transport:
            self.remote_transport.close()
        self.loop.create_task(connect_survivor(self.loop, self.addr, self.port))
        print('survivor server connection closed.')


async def connect_survivor(loop, addr, port):
    await loop.create_connection(
        lambda: RescuerClientProtocol(loop, addr, port),
        addr, port)


async def connect_remote(local: RescuerClientProtocol, addr, port, callback):
    transport, protocol = await local.loop.create_connection(
        lambda: RemoteClientProtocol(local.transport),
        addr, port)
    callback(transport, protocol)


def survivor(port):
    loop = asyncio.get_event_loop()
    # Each client connection will create a new protocol instance
    coro = loop.create_server(
        lambda: SurvivorServerProtocol(loop),
        '0.0.0.0', port)
    server = loop.run_until_complete(coro)

    # Serve requests until Ctrl+C is pressed
    print('serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


def rescuer(addr, port):
    loop = asyncio.get_event_loop()
    coro = loop.create_connection(
        lambda: RescuerClientProtocol(loop, addr, port),
        addr, port)
    print('connect to {}:{}'.format(addr, port))
    for i in range(10):
        loop.create_task(connect_survivor(loop, addr, port))
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()


if __name__ == '__main__':
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-s", "--survivor", action="store_true",
                      dest="survivor",
                      default=False,
                      help="Access its network resources by connecting to local rescuers")
    parser.add_option("-r", "--rescuers", action="store_true",
                      dest="rescuers",
                      default=False,
                      help="Help target computers access the Internet")
    parser.add_option("-t", "--target", action="store", type="string",
                      dest="target",
                      default='0.0.0.0',
                      help="target host")
    parser.add_option("-p", "--port", action="store", type="int",
                      dest="port",
                      default='1080',
                      help="target/listen port")

    (options, args) = parser.parse_args()

    if options.survivor:
        survivor(options.port)

    if options.rescuers:
        rescuer(options.target, options.port)
