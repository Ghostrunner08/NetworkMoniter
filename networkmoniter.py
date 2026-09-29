import pyshark
import socket
import psutil
import time
from datetime import datetime
from datetime import timedelta

# Init global variables
device_name = socket.gethostname()
connections = {}

# define networkInterface to scan, use "tshark -D" to find all available interfaces
networkInterface = '6'

# print current status
print("Network Moniter starting...")
print("Init ReverseDNS...")

# define re-usable modules.
def reverseDNS(ip_address): # reverseDNS returns the Domain Name of an IP address
    try:
        # Performs a reverse DNS lookup
        domain_name, alias, addresslist = socket.gethostbyaddr(ip_address)
        return domain_name
    except socket.herror:
        return "Error: No Domain Name"

print("Init psutil...")

def find_process(src_ip, src_port, dst_ip, dst_port): # find_process is the Process Attribution module.
    for conn in psutil.net_connections(kind="inet"):
        if not conn.pid:
            continue

        if not conn.laddr:
            continue

        # Outgoing connection
        if (
            conn.laddr.ip == src_ip
            and conn.laddr.port == int(src_port)
            and conn.raddr
            and conn.raddr.ip == dst_ip
            and conn.raddr.port == int(dst_port)
        ):
            try:
                return conn.pid, psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return conn.pid, "Unknown"

    return None, "Unknown"

print("Listening for packets...\n┌──────────────────────────────────────────────────────┐")

capture = pyshark.LiveCapture(interface= networkInterface)

try: # Starts scanning the network interface for packets and reads info from them.
    for packet in capture.sniff_continuously():
        try:
            timestamp = packet.sniff_time.strftime("%H:%M:%S")
            packet_time = packet.sniff_time

            if hasattr(packet, 'ip'):
                source = packet.ip.src
                srcName = reverseDNS(source)
                destination = packet.ip.dst
                dstName = reverseDNS(destination)

                if hasattr(packet, 'transport_layer'):
                    protocol = packet.transport_layer

                    if protocol == 'TCP':
                        source_port = packet.tcp.srcport
                        destination_port = packet.tcp.dstport
                    elif protocol == 'UDP':
                        source_port = packet.udp.srcport
                        destination_port = packet.udp.dstport
                    else:
                        source_port = "?"
                        destination_port = "?"

                    if srcName == device_name:
                        packetStatus = "Sending"
                    elif dstName == device_name:
                        packetStatus = "Receiving"

                    if packetStatus == "Sending":
                        process = find_process(source, source_port, destination, destination_port)
                    else:
                        process = "N/A"

                    packet_size = int(packet.length)

                    if packetStatus == "Sending":
                        localIp = source
                        localPort = source_port
                        remoteIp = destination
                        remotePort = destination_port
                    else:
                        localIp = destination
                        localPort = destination_port
                        remoteIp = source
                        remotePort = source_port
                    connection_key = (localIp, localPort, remoteIp, remotePort, protocol)                    

                    if connection_key not in connections: # Add connection_key's to connections table if a new connection occurs
                        connections[connection_key] = {
                            "Process": process,
                            "LocalIP": localIp,
                            "Protocal": protocol,
                            "FirstSeen": packet_time,
                            "LastSeen": packet_time,
                            "DataIn": 0,
                            "DataOut": 0,
                            "PacketsIn": 0,
                            "PacketsOut": 0,
                        }
                    connection = connections[connection_key]
                    connection["LastSeen"] = packet_time

                    if packetStatus == "Receiving":
                        connection["PacketsIn"] += 1
                        connection["DataIn"] += packet_size
                    elif packetStatus == "Sending":
                        connection["PacketsOut"] += 1
                        connection["DataOut"] += packet_size

                    if srcName == "Error: No Domain Name" or dstName == "Error: No Domain Name": # Prints the packets info, may highlight if source or destination is unknown.
                        print("\033[33m")
                    print(
                        f"| [{timestamp}] |"
                        f" [{process}] |"
                        f" [{srcName}]: "
                        f"{source}:{source_port} → "
                        f"[{dstName}]: "
                        f"{destination}:{destination_port} | "
                        f"[{protocol}] | "
                        f"[{packetStatus}]"
                    )
                    if srcName == "Error: No Domain Name" or dstName == "Error: No Domain Name":
                        print("\033[0m")

                    # Connection logging/warning logic
                    CONNECTION_TIMEOUT = timedelta(seconds=300)
                    currentTime = datetime.now()

                    for key, connection in list(connections.items()):
                        if currentTime - connection["LastSeen"] > CONNECTION_TIMEOUT:
                            del connections[key]

                    for connection in connections.values():
                        if connection["PacketsIn"] > 1000:
                            print(
                                f"\033[31mWARNING: "
                                f"{connection["LocalIP"]} "
                                f"is sending EXCESSIVE packets (1000+)\033[0m"
                            )
                        elif connection["DataIn"] > 100000000:
                            print(
                                f"\033[33mWARNING: "
                                f"{connection["LocalIP"]} "
                                f"is sending EXCESSIVE data (100 MBs+)\033[0m"
                            )
                        elif connection["DataIn"] > 1024000000:
                            print(
                                f"\033[31mWARNING: "
                                f"{connection["LocalIP"]} "
                                f"is sending EXCESSIVE data (1 GB+)\033[0m"
                            )

        except AttributeError:
            pass

except KeyboardInterrupt:
    print("\n└──────────────────────────────────────────────────────┘\nNetwork Monitor stopped.")