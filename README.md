**📌 Wireshark Flow Analysis: Full Reference Summary**

Efficient Tracking of DNS, TCP, TLS, and HTTPS Using Targeted Filtering

**Objective:** This structured methodology provides an efficient and repeatable approach to analyzing secure web traffic, minimizing unnecessary data and refining filtering to obtain only pertinent results. This ensures a clear, systematic method that avoids defaulting to general or inefficient filtering.

**🔹 Step 1: Identifying the Initial Connection Attempt**

Purpose:

To determine whether the connection was made via IPv4 (A record) or IPv6 (AAAA record), and whether it used QUIC (UDP) or traditional TLS over TCP.

Filter Applied:
tcp.flags.syn == 1 or udp.port == 443
Why?
Filters only SYN packets (starting a TCP handshake) and UDP packets on port 443 (possible QUIC).

Immediately reveals whether the connection is TCP/TLS or UDP/QUIC.

Also indicates whether IPv4 (A record) or IPv6 (AAAA record) was used.

Findings:
✅ The website used IPv4 (A record) over TCP, confirming TLS-based HTTPS rather than QUIC.
✅ The first connection attempt was to 23.227.38.65 (Reebok’s IPv4 address).

**🔹 Step 2: Analyzing the TCP Handshake**
Purpose:
To confirm that the 3-way TCP handshake (SYN, SYN-ACK, ACK) was successful, ensuring a stable connection was established.

Filter Applied:

(ip.addr == 23.227.38.65) and (tcp.flags.syn == 1 or tcp.flags.ack == 1)
Why?
Filters out irrelevant traffic, keeping only TCP handshake packets related to Reebok’s IP.

Ensures the entire 3-way handshake process can be observed.

Findings:
✅ SYN, SYN-ACK, and ACK were present, confirming a complete handshake.
✅ Connection was established on port 443 (HTTPS).

**🔹 Step 3: Verifying the TLS Handshake & Encryption**

Purpose:
To confirm TLS 1.3 is being used, identify the cipher suite, and verify encryption activation.

Filter Applied:
(ip.addr == 23.227.38.65)

(No need for a more restrictive filter as the TLS handshake packets were already visible.)

Why?
The TLS handshake packets were already within our previously filtered dataset.

We located Client Hello (Frame 64) and Server Hello (Frame 73) manually without extra filtering.

Findings:
✅ TLS 1.3 (0x0304) was confirmed as the encryption protocol.
✅ Cipher Suite Selected: TLS_AES_128_GCM_SHA256 (Provides authenticated encryption and Perfect Forward Secrecy).
✅ Key Exchange: Server Hello contained a Key Share extension, confirming ephemeral key exchange (likely X25519).

**🔹 Step 4: Confirming the Transition to HTTPS Encryption**
Purpose:
To verify that encryption was fully activated and that the connection transitioned to encrypted HTTPS traffic.

Filter Applied:
(No additional filter was needed—this was visible from previous filtering.)

Key Packet:
✅ Frame 77 contained:

Change Cipher Spec message (indicating encryption activation).

Application Data (meaning all further communication is now encrypted).

Findings:
✅ TLS 1.3 handshake was complete; encryption is active.
✅ All further data is encrypted HTTPS traffic and cannot be analyzed without decryption keys.

**🔹 Step 5: Verifying DNS Resolution**

Purpose:
To confirm how Reebok’s domain (reebok.com) was resolved to an IP address (23.227.38.65).

Filter Applied:
dns and dns.flags.response == 1 and dns.qry.name contains "reebok.com" and dns.qry.type == 1
Why?
Filters only actual DNS responses (not queries).

Filters only DNS responses related to reebok.com.

Filters only IPv4 (A record) responses, excluding unnecessary IPv6 (AAAA) records.


**📌 Understanding How the DNS Response Filter Works**

This section explains two key filtering behaviors in Wireshark that are essential for accurately analyzing DNS resolution. These clarifications ensure that filtering remains precise and efficient, avoiding unnecessary packet noise.

**🔹 Question 1: Why Are Queries Not Included If dns.qry.name Is in the Filter?**

📌 Key Takeaways:

The filter we used includes dns.flags.response == 1, which ensures that only DNS responses are displayed and that queries are automatically excluded.

Even though dns.qry.name exists in both DNS queries and responses, this does not override dns.flags.response == 1.

Result: This filter only displays DNS responses that contain reebok.com, ensuring that all unrelated DNS queries are removed.

📌 Rule to Remember:
✅ If dns.flags.response == 1 is in the filter, DNS queries (dns.flags.response == 0) are always excluded.

**🔹 Question 2: How Does This Filter Exclude IPv6 (AAAA) Records?**
📌 Key Takeaways:

DNS query types are assigned specific numbers:

IPv4 (A) = 1

IPv6 (AAAA) = 28

The filter contains dns.qry.type == 1, which means only IPv4 (A) records are shown and all IPv6 (AAAA) records are excluded.

Even though dns.qry.type == 1 appears in both queries and responses, queries are already removed by dns.flags.response == 1.

📌 Rule to Remember:
✅ If dns.qry.type == 1 is in the filter, only IPv4 (A) records will appear, and IPv6 (AAAA) records will be automatically excluded.

🚀 Final Summary: The Complete DNS Filter Logic

dns.flags.response == 1 and dns.qry.name contains "reebok.com" and dns.qry.type == 1
✅ dns.flags.response == 1 → Ensures that only responses (not queries) are displayed.
✅ dns.qry.name contains "reebok.com" → Ensures that only responses related to reebok.com appear.
✅ dns.qry.type == 1 → Ensures that only IPv4 (A) records appear, excluding IPv6 (AAAA).

🚀 By combining these three conditions, this filter precisely captures the DNS resolution response for reebok.com, removing all unnecessary traffic.





**Findings:**
✅ Reebok.com was resolved to 23.227.38.65.
✅ The DNS request was handled by a local resolver (dsldevice6.attlocal.net).
✅ Resolution time: 0.079555000 seconds (likely cached).

**🔹 Conclusion: The Full Network Flow (DNS ➝ TCP ➝ TLS ➝ HTTPS)**

✅ DNS Query: reebok.com was resolved to 23.227.38.65
✅ Connection Type: IPv4, TCP-based (not QUIC)
✅ TCP Handshake: SYN, SYN-ACK, ACK confirmed
✅ TLS Handshake: TLS 1.3, TLS_AES_128_GCM_SHA256 cipher suite, Perfect Forward Secrecy
✅ Encryption Activation: TLS handshake completed, Change Cipher Spec and encrypted HTTPS traffic confirmed

**🔹 Strategy Overview: Why This Approach Works**

📌 Why Not Start With DNS?

We first verified that an actual connection was established before checking DNS.

If we had started with DNS, we would have captured all DNS responses (not just the relevant one).

By filtering only after confirming the IP used, we reduced noise and unnecessary steps.

📌 Why Use These Filters Instead of Broad Queries?

Filtering at each layer (DNS, TCP, TLS) ensures minimal irrelevant traffic.

More precise filtering leads to more efficient analysis and eliminates manual searching.

📌 How This Improves Over Traditional Network Analysis

Traditional Wireshark analysis often follows a broad, chronological approach.

This structured method narrows the scope at each step, ensuring only relevant packets are analyzed.


**📌 Summary: A Repeatable, Optimized Approach**
✅ Use filtering to analyze secure network traffic efficiently.

✅ Avoid broad captures; target specific records to eliminate noise.

✅ Follow the network flow in a logical sequence to confirm each stage.

🚀 This structured approach provides a clear, repeatable process for analyzing web traffic efficiently in Wireshark.
