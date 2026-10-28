/**
 * Function without any prefix is a "private" function.
 *
 * @param  {...any} args - Arguments that are going to be used in the function
 * @returns {void}
 */
function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

/**
 * Function without any prefix is a "private" function.
 *
 * @param  {...any} args - Arguments that are going to be used in the function
 * @returns {void}
 */
function randomString(size) {
    const chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";

    for (let i = 0; i < size; i++)
        result += chars[randomInt(0, chars.length - 1)];
    return result;
}

/**
 * This function with intcp name or intcp_ prefix is used to intercept packets when the device receives them.
 * It can be used to log the packets or modify them before they are sent to the target.
 * It can be possible to set different interceptors for different devices:
 *      - intcp: intercept packets from all devices
 *      - intcp_router: intercept packets from routers
 *      - intcp_iot: intercept packets from IoT devices
 *      - intcp_computer: intercept packets from computers
 *
 * @param {Object} self - The interceptor device
 * @param {string} self.mac - MAC address of the interceptor device
 * @param {string} self.ip - IP address of the interceptor device
 * @param {string} self.name - Name of the interceptor device
 * @param {string} self.type - Type of the interceptor device
 * @param {function(Object) => void} self.send - Function to send a packet
 * @param {Object} packet - The packet that is being intercepted
 * @param {string} packet.srcIP - Source IP address of the packet
 * @param {number} [packet.srcPort] - Source port of the packet
 * @param {string} packet.dstIP - Destination IP address of the packet
 * @param {number} [packet.dstPort] - Destination port of the packet
 * @param {number} packet.transportProtocol - Transport protocol of the packet
 * @param {number} [packet.applicationProtocol] - Application protocol of the packet
 * @param {string} [packet.payload] - Payload of the packet
 * @param {number} packet.totalBytes - Total bytes of the packet
 * @param {number} packet.headerSize - Header size of the packet
 * @param {number} packet.payloadSize - Payload size of the packet
 * @param {Date} packet.timestamp - Timestamp of the packet
 * @param {number} packet.ttl - Time to live of the packet
 * @param {number} packet.type - ICMP message type (ECHO_REPLY = 0, ECHO_REQUEST = 8)
 * @param {number} packet.code - ICMP message code (0 = no code)
 * @param {number} packet.identifier - ICMP message identifier
 * @param {number} packet.sequence - ICMP message sequence number
 * @param {number} packet.tcpFlags - TCP flags (FIN = 1, SYN = 2, RST = 4, PSH = 8, ACK = 16, URG = 32)
 * @return {void} - If you don't want to run the default interceptor of the simulator, return null or other value
 */
function intcp(self, packet) {}

/**
 * This function with cmd_ prefix is used to simulate a command, in the simulator it will show as "Stream Video"
 *
 * @param {Object} self - The executor device
 * @param {string} self.mac - MAC address of the executor device
 * @param {string} self.ip - IP address of the executor device
 * @param {string} self.name - Name of the executor device
 * @param {string} self.type - Type of the executor device
 * @param {function(packet) => void} self.send - Function to send a packet
 * @param {string} target - IP addresses of the target device
 * @returns {void}
 */
function cmd_Stream_Video(self, target) {
    // Flow parameters
    const duration = 2 * 1000; // Flow duration in milliseconds
    const minInterval = 150; // Min interval between packets (ms)
    const maxInterval = 250; // Max interval between packets (ms)
    const endTime = Date.now() + duration;
    // Packet parameters
    const headerSize = 20;
    let sequenceNumber = 0;
    let ackNumber = 0;
    const srcPort = randomInt(1024, 65535);
    const dstPort = 443;
    const sendVideo = () => {
        if (Date.now() > endTime) return;

        const payload = randomString(randomInt(512, 2056));
        const payloadSize = new TextEncoder().encode(payload).length;

        const packet = {
            srcIP: self.ip,
            dstIP: target,
            srcPort,
            dstPort,
            transportProtocol: 6,
            payload,
            totalBytes: headerSize + payloadSize,
            headerSize,
            payloadSize,
            timestamp: new Date(),
            ttl: 64,
            tcpFlags: 16, // ACK flag
            sequence: sequenceNumber,
            ack: ackNumber,
        };

        self.send(packet);

        sequenceNumber += payloadSize;
        ackNumber += payloadSize;

        // Send the next packet
        setTimeout(sendVideo, randomInt(minInterval, maxInterval));
    };

    // Start sending video packets
    sendVideo();
}

/**
 * This function with atk_ prefix is used to attack a device, in the simulator it will show as "DoS UDP"
 *
 * @param {Object} self - The attacker device
 * @param {string} self.mac - MAC address of the attacker device
 * @param {string} self.ip - IP address of the attacker device
 * @param {string} self.name - Name of the attacker device
 * @param {string} self.type - Type of the attacker device
 * @param {function(packet) => void} self.send - Function to send a packet
 * @param {...string} targets - IP addresses of the target devices
 * @returns {void}
 */
function atk_DoS_UDP(self, ...targets) {
    const portProtocol = 53; // DNS protocol and destination port
    const ttlRange = [32, 128]; // Range of TTL values
    const packetNum = 200; // Number of packets to send
    const headerSize = 8;

    for (let i = 0; i < packetNum; i++) {
        for (let j = 0; j < targets.length; j++) {
            const payload = randomString(128); // Random payload of 128 characters
            const payloadSize = new TextEncoder().encode(payload).length; // Calculate payload size in bytes
            const packet = {
                srcIP: self.ip,
                dstIP: targets[j],
                srcPort: randomInt(1024, 65535),
                dstPort: portProtocol,
                transportProtocol: 17,
                applicationProtocol: portProtocol,
                payload,
                totalBytes: headerSize + payloadSize,
                headerSize,
                payloadSize,
                timestamp: new Date(),
                ttl: randomInt(ttlRange[0], ttlRange[1]),
            };

            self.send(packet);
        }
    }
}
