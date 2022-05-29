
with open('./forwarding_table.txt', 'r') as f:
    lines = f.readlines()
for line in lines:
    ip_address, subnet, next_hop, interface = line.strip().split()
    print(ip_address + ' ' + subnet + ' ' + next_hop + ' ' + interface)
