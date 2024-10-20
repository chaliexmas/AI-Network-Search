# AI Network Search

This Python script performs network port scanning using multiple heuristic algorithms, including Q-learning, Monte Carlo simulation, Instance-Based Learning (IBL), and A* search. It identifies live IPs within a given subnet and scans a wide range of ports to rank them based on their likelihood of being open.

## Features

1. **Live IP Detection**: Pings IP addresses within a given range to identify active hosts.
2. **Port Scanning**: Scans the identified live hosts for open ports using different heuristic behaviors.
3. **Heuristic Behaviors**:
   - **Instance-Based Learning (IBL)**: Uses past port scan results to inform future scans.
   - **Monte Carlo Simulation**: Randomized port scans to estimate probabilities of open ports.
   - **Q-learning**: Reinforcement learning approach to prioritize ports based on past rewards.
   - **A* Search**: Uses a priority-based heuristic to guide port scanning.

## Requirements

- Python 3.7+
- Libraries: `ipaddress`, `pythonping`, `socket`, `speedyibl`, `random`, `collections`, `heapq`, `time`

Install the required libraries with:

```bash
pip install pythonping speedyibl
```

## Usage

1. **Run the script**:
   ```bash
   python <script_name>.py
   ```
2. **Input Parameters**:
   - **IP Range**: Enter a subnet range (e.g., `192.168.1.0/24`).
   - **Behavior ID**: Choose from 1 to 4 to select a heuristic behavior:
     - `1` = Instance-Based Learning
     - `2` = Monte Carlo Simulation
     - `3` = Q-learning
     - `4` = A* Search

## Example

```
Enter the IP range (e.g., 192.168.1.0/24): 192.168.1.0/24
Enter the behavior number (1-4): 1
```

## Notes

- **Adjustable Parameters**: You can modify the number of trials, scan attempts, or learning parameters directly in the functions.
- **Security**: This tool is for educational purposes. Ensure you have permission before scanning any network.
