import scapy.all as scapy

def scan(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    request = broadcast / arp_request
    answered = scapy.srp(request, timeout=2, verbose=False)[0]

    devices = []

    for element in answered:
        devices.append({
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        })

    return devices


def display(devices):
    print("IP Address\t\tMAC Address")
    print("-" * 40)
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")


if __name__ == "__main__":
    target = input("Enter IP range (example 192.168.1.1/24): ")
    result = scan(target)
    display(result)
