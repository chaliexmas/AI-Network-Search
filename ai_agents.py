from ipaddress import ip_network
from pythonping import ping
import socket
from speedyibl import Agent
import random
from collections import defaultdict
import heapq
import time


def is_host_live(ip):
    try:
        #print(f"Attempting to ping {ip}...")  # Print before pinging
        response = ping(ip, count=1, timeout=1)
        if response.success():
            #Sprint(f"{ip} is active.")  # Print if the ping is successful
            return True
        else:
            #print(f"Failure: {ip} did not respond.")  # Print if the ping fails
            return False
    except Exception as e:
        #print(f"Failed to ping {ip}: {str(e)}")  # Print the exception if an error occurs
        return False

def scan_port(ip, port):
    socket.setdefaulttimeout(1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = s.connect_ex((ip, port))
    s.close()
    return result == 0  # True if port is open, False otherwise
    
def q_learning(live_ips, ports, trials=50):
    start_time = time.time()
    print("Behavior 3: Q-learning aka Confirmation heuristic for port scanning...")
    Q = {port: 0 for port in ports}
    alpha = 0.5
    gamma = 0.8

    for trial in range(trials):
        for ip in live_ips:
            for port in ports:
                if scan_port(ip, port):
                    reward = 1
                else:
                    reward = -1
                old_value = Q[port]
                next_max = max(Q.values())
                new_value = (1 - alpha) * old_value + alpha * (reward + gamma * next_max)
                Q[port] = new_value

    top_ports = sorted(Q, key=Q.get, reverse=True)[:10]
    print(f"Top 10 Ports to Attempt Based on Q-learning: {top_ports}")
    
    end_time = time.time()
    duration = end_time - start_time
    print(f"Time taken: {duration:.2f} seconds")
    print(f"Scanned {len(live_ips) * len(ports) * trials} total port checks.")


def monte_carlo_port_scan(live_ips, ports, num_scans=500):
    start_time = time.time()  # Start timing
    print("Behavior 2: Monte Carlo aka confirmation heuristic for port scanning...")
    port_results = {port: 0 for port in ports}  # Dictionary to store results
    total_scans = 0

    for _ in range(num_scans):
        ip = random.choice(live_ips)  # Randomly select an IP
        port = random.choice(ports)   # Randomly select a port
        if scan_port(ip, port):
            port_results[port] += 1  # Increment count if the port is open
        total_scans += 1

    # Calculate the probability of each port being open
    port_probabilities = {port: port_results[port] / num_scans for port in ports}
    # Sort ports by probability and select the top 10
    top_ports = sorted(port_probabilities, key=port_probabilities.get, reverse=True)[:10]
    print("Top 10 Ports by Monte Carlo:", top_ports)

    end_time = time.time()  # End timing
    duration = end_time - start_time
    print(f"Time taken: {duration:.2f} seconds")
    print(f"Total port scans performed: {total_scans}")
    print(f"Efficiency: {len([p for p in port_results if port_results[p] > 0]) / len(ports) * 100:.2f}% open")
    #return port_probabilities

def speedy_ibl_behavior(live_ips, ports):
    start_time = time.time()  # Start timing
    if not ports:
        print("No ports provided for scanning.")
        return

    agent = Agent(default_utility=5.0)  
    print("Behavior 1: Instance based learning aka availability heuristic for port scanning...")
    memory = {port: [] for port in ports} 

    for ip in live_ips:
        for port in ports:
            if scan_port(ip, port):
                reward = 10
            else:
                reward = -5
            memory[port].append(reward)

    utilities = {}
    for port, rewards in memory.items():
        if rewards:
            average_utility = sum(rewards) / len(rewards)
            agent.populate_at(port, average_utility, len(rewards))
            utilities[port] = average_utility 

    if utilities:
        top_ports = sorted(utilities, key=utilities.get, reverse=True)[:10]
        print(f"Top 10 Ports to Attempt Based on IBL: {top_ports}")
    else:
        print("No successful data gathered to make a decision.")

    end_time = time.time()  # End timing
    duration = end_time - start_time
    print(f"Time taken: {duration:.2f} seconds")
    print(f"Scanned {len(live_ips) * len(ports)} ports.")


def astar_search(live_ips, ports):
    start_time = time.time()  # Start timing
    print("Behavior 4: A* Learning for port scanning aka optimism heuristic...")

    # Example heuristic: inverse of port number modulus 10 (simplified example)
    heuristic = {port: 10 - (port % 10) for port in ports}

    # Priority queue for A* search, initialized with all ports
    pq = [(heuristic[port], port) for port in ports]
    heapq.heapify(pq)  # Organizes the list into heap order

    results = []
    attempts = defaultdict(int)
    scan_attempts = 0

    while pq:
        _, port = heapq.heappop(pq)  # Pops the port with the lowest heuristic value
        for ip in live_ips:
            if scan_port(ip, port):
                results.append(port)
            attempts[port] += 1
            scan_attempts += 1
            # Update f(n) = g(n) + h(n)
            g_n = attempts[port]
            f_n = g_n + heuristic[port]
            heapq.heappush(pq, (f_n, port))  # Pushes the updated value back into the priority queue
        
        if len(results) >= 10:  # Stop if 10 open ports are found
            break

    end_time = time.time()  # End timing
    duration = end_time - start_time
    print(f"Top ports found open using A*: {results[:10]}")
    print(f"Time taken: {duration:.2f} seconds")
    print(f"Total scan attempts: {scan_attempts}")
    print(f"Efficiency: {len(results) / scan_attempts * 100:.2f}% open")

# Define additional behaviors similarly
def behavior_selector(behavior_id, live_ips):

    #
    ports = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5900,
    8080, 20, 70, 81, 118, 443, 465, 587, 990, 992, 993, 4949, 6665, 6666, 6667, 6668, 6669, 6697, 7000,
    8083, 8086, 8087, 8443, 8888, 9418, 1080, 3128, 3333, 4000, 5000, 5800, 6080, 6379, 6443, 6660, 7001,
    8000, 8008, 8009, 8081, 8084, 8085, 8088, 8443, 8880, 9000, 9043, 9060, 9080, 9090, 9443, 9444, 9999,
    11211, 27017, 27018, 27019, 28017, 2049, 135, 514, 1194, 1433, 1701, 1723, 500, 1080, 4444, 5060,
    5061, 5080, 1248, 123, 636, 853, 3269, 5986, 1119, 4001, 5555, 9001, 9030, 9100, 9675, 10000, 10050,
    10051, 14000, 137, 138, 465, 548, 873, 993, 995, 1167, 5222, 5269, 8010, 32764, 81, 554, 8001, 8081,
    102, 111, 119, 143, 465, 554, 587, 749, 873, 902, 912, 992, 1194, 1234, 1433, 1521, 1645, 1646, 1701,
    1723, 2000, 2049, 3225, 3260, 3269, 3306, 3389, 3493, 3659, 3869, 4000, 4001, 4002, 4100, 4111, 4200,
    4242, 4369, 4569, 4659, 5000, 5001, 5060, 5061, 5222, 5223, 5432, 5555, 5800, 5801, 5802, 5900, 5901,
    5984, 6000, 6001, 6379, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6670, 6671, 6672,
    6673, 6674, 6675, 6676, 6677, 6678, 6679, 6680, 6681, 6682, 6683, 6684, 6685, 6686, 6687, 6688, 6689,
    6690, 6691, 6692, 6693, 6694, 6695, 6696, 6697, 6698, 6699, 6700, 6701, 6702, 6703, 6704, 6705, 6706,
    6707, 6708, 6709, 6710, 6711, 6712, 6713, 6714, 6715, 6716, 6717, 6718, 6719, 6720, 6721, 6722, 6723,
    6724, 6725, 6726, 6727, 6728, 6729, 6730, 6731, 6732, 6733, 6734, 6735, 6736, 6737, 6738, 6739, 6740 ]
    
    if behavior_id == 1:
        speedy_ibl_behavior(live_ips, ports) 
    elif behavior_id == 2:
        monte_carlo_port_scan(live_ips, ports, 500) 
    elif behavior_id == 3:
        q_learning(live_ips, ports)
    elif behavior_id == 4:
        astar_search(live_ips, ports)
    #elif behavior_id == 5:
    #    print("Behavior 5: Description of behavior...")
    #elif behavior_id == 6:
    #    print("Behavior 6: Description of behavior...")
    #elif behavior_id == 7:
    #    print("Behavior 7: Description of behavior...")
    #elif behavior_id == 8:
    #    print("Behavior 8: Description of behavior...")
    #elif behavior_id == 9:
    #    print("Behavior 9: Description of behavior...")
    #elif behavior_id == 10:
    #    print("Behavior 10: Description of behavior...")
    else:
        print("Invalid behavior number.")

def main():
    ip_range = input("Enter the IP range (e.g., 192.168.1.0/24): ")
    behavior_id = int(input("Enter the behavior number (1-4): "))
    network = ip_network(ip_range)
    live_ips = [str(ip) for ip in network.hosts() if is_host_live(str(ip))]
    
    print("Live IPs:", live_ips)
    behavior_selector(behavior_id, live_ips)

if __name__ == "__main__":
    main()