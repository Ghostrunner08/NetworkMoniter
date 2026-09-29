# NetworkMoniter
Network Traffic Moniter using PyShark (Tshark wrapper for Python)

Output should look like this:

[12:34:56] | [Process] | [Source Name]: SourceIP:SourcePort > [Destination Name]: DestinationIP:DestinationPort | Protocal | [Sending/Receiving]

The moniter will log connections, highlighting unknown connections in orange

Moniter will print a warning for the following triggers:

Excess packets sent/received (1000+ in 300s) - Red Highlight
Large Data Transfers (1+ GBs) - Red Highlight

Medium Data Transfers (100+ MBs) - Yellow Highlight
Unknown Host Name - Yellow Highlight

## Requirements

Windows 10/11
Python 3.X
WireShark / Tshark 4.6.9
npcap

# DISCLAIMER
You will need to manually modify the file to use the desired network interface.
just modify the "networkInterface" variable on line 11
Using Tshark you can find the numeric assignments of your network interfaces
## Utilize Tshark to list network interfaces
```tshark -D```

## Install the required Python Packages:
```python -m pip install pyshark psutil```



