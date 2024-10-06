import logging

class StatefulFirewall:
    def __init__(self):
        self.state_table = {}
        self.allowed_ports = {80, 443}  # HTTP and HTTPS ports
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(filename='firewall.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def log(self, message):
        logging.info(message)

    def packet_in(self, src_ip, dest_ip, dest_port, connection_state):
        if connection_state == 'new':
            self.handle_new_connection(src_ip, dest_ip, dest_port)
        elif connection_state == 'established':
            self.allow_packet(src_ip, dest_ip, dest_port)
        elif connection_state == 'close':
            self.close_connection(src_ip, dest_ip)
        self.display_state_table()

    def handle_new_connection(self, src_ip, dest_ip, dest_port):
        if dest_port in self.allowed_ports:
            self.state_table[(src_ip, dest_ip, dest_port)] = 'established'
            self.log(f"New connection established: {src_ip} -> {dest_ip}:{dest_port}")
            print(f"Packet allowed: {src_ip} -> {dest_ip}:{dest_port} (New connection)")
        else:
            self.log(f"Connection attempt denied: {src_ip} -> {dest_ip}:{dest_port}")
            print(f"Packet denied: {src_ip} -> {dest_ip}:{dest_port} (Port not allowed)")

    def allow_packet(self, src_ip, dest_ip, dest_port):
        if (src_ip, dest_ip, dest_port) in self.state_table and \
           self.state_table[(src_ip, dest_ip, dest_port)] == 'established':
            self.log(f"Packet allowed: {src_ip} -> {dest_ip}:{dest_port}")
            print(f"Packet allowed: {src_ip} -> {dest_ip}:{dest_port} (Connection established)")
        else:
            self.log(f"Packet dropped: {src_ip} -> {dest_ip}:{dest_port} (No established connection)")
            print(f"Packet dropped: {src_ip} -> {dest_ip}:{dest_port} (No established connection)")

    def close_connection(self, src_ip, dest_ip):
        to_remove = [key for key in self.state_table if key[0] == src_ip and key[1] == dest_ip]
        for key in to_remove:
            del self.state_table[key]
            self.log(f"Connection closed: {src_ip} -> {dest_ip}")
            print(f"Connection closed: {src_ip} -> {dest_ip}")

    def display_state_table(self):
        print("\nCurrent State Table:")
        print("-" * 40)
        for (src_ip, dest_ip, dest_port), state in self.state_table.items():
            print(f"Source: {src_ip}, Destination: {dest_ip}:{dest_port}, State: {state}")
        print("-" * 40)

if __name__ == "__main__":
    firewall = StatefulFirewall()
    print("Stateful Firewall is running...")
    while True:
        src_ip = input("Enter source IP: ")
        dest_ip = input("Enter destination IP: ")
        dest_port = int(input("Enter destination port: "))
        connection_state = input("Enter connection state (new/established/close): ")
        firewall.packet_in(src_ip, dest_ip, dest_port, connection_state)
