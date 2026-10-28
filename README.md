#IoT-Sim is a lightweight, modular, and open-source tool designed to create, configure, and test attack detection models for Internet of Things (IoT) networks. It provides an interactive, client-side simulation environment that runs entirely in your browser, with no dedicated backend server required.

This platform was developed to address the lack of flexible, accessible simulation environments that allow researchers and students to replicate IoT scenarios and evaluate machine learning models under controlled, realistic conditions.

## Key Features

- **Visual Network Design:** Interactively create and configure IoT network topologies. Add, edit, connect, and remove nodes like **Routers**, **IoT Devices**, and **PC Attackers**.
- **Traffic Simulation:** Simulate benign network traffic flows between connected devices.
- **Attack Generation:** Inject controlled cyberattacks, such as **Denial of Service (DoS)**, to test network resilience and detection models.
- **AI-Based Intrusion Detection:** Load your own pre-trained **TensorFlow.js** models to analyze network traffic in real-time and visualize intrusion detections.
- **Configurable Network Conditions:** Introduce network variability, such as **latency** and **bandwidth limitations**, to evaluate model performance under realistic conditions.
- **Client-Side Architecture:** Runs entirely in the user's browser, making it highly accessible and eliminating the need for expensive hardware or complex server deployments.
- **Extensible:** Users can import external scripts to add new custom commands or attack types, extending the simulator's capabilities.

## Technical Stack

The simulator is built using the following technologies:

- **Core Framework:** Angular
- **Languages:** TypeScript, HTML, CSS
- **AI Models:** TensorFlow / TensorFlow.js
- **UI Styling:** Tailwind CSS , Spartan UI
- **Build System:** Node.js, npm, Angular CLI

To prepare your own AI models, you will need a separate environment with Python (>= 3.10, < 3.12) and TensorFlow (>= 2.15.0). Models must be converted to TensorFlow.js format (>= 4.22.0) using the tensorflowjs converter tool to be compatible with the simulator.

## Citation

If you use **IoT-Sim** in your research or professional work, please cite our paper published in *SoftwareX*:
# CyberTwin
