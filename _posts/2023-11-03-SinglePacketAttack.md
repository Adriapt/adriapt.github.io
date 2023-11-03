---
title: "Single-packet Attack"
author: Adrià Pagès Torruella
date: 2023-11-03 17:30:00 +0800
categories: [Web Vulnerabilities]
tags: [Web,HTTP,Race Condition]
math: true
render_with_liquid: false
---

# Single-packet attack

A single-packet attack is a methodology used to exploit race conditions.  A race condition vulnerability is a flaw in a system that arises when multiple processes access and manipulate shared data concurrently, leading to unpredictable or unintended outcomes.

To exploit a race condition, you need the server to execute requests almost at the same time in a concurrent way. This is difficult to achieve because there are external factors that are not controlable by the attacker (such as network latency, jitter, etc.)  that could impact the time that a packet reaches the server. 

However, the single-packet attack allows the attacker to ensure that several requests will be executed almost at the same time. But… how does it work? Let’s explain the fundamentals. 

## HTTP/2

Web applications communicate with servers using the HTTP protocol.  HTTP traffic is packaged into TCP segments which are sent within IP packets. A server will process a request once the whole HTTP data has been read from the TCP connection.   

HTTP/2 introduces “streams” used to identify different HTTP requests an responses. Hence, you can send several HTTP connections within the same TCP connection because each of them will be using a different “stream” 

![Untitled](/img/posts/Single-packet/Untitled.jpeg)

All HTTP/2 requests start with a *HEADERS* frame, followed by 0 or more *CONTINUATION* or *DATA* frames. 


>**HEADERS Frame**: The HEADERS frame is used to carry a complete set of header fields for a single stream, such as request or response headers. It is used to open a new stream or re-open an existing one.
**CONTINUATION Frame**: The *CONTINUATION* frame is used to continue a sequence of header block fragments. When the compressed size of the header block is too large to fit within a single HEADERS frame.
**DATA Frame**: The *DATA* frame is used to carry the actual payload of an HTTP message, such as the body of a request or response. It allows for the transmission of message content in both directions, enabling the exchange of data between the client and the server.
{: .prompt-info}

All frames have their own “frame headers” which contain information about that frame, stream, etc. Do not  mix up with the HEADER frame, that contains the headers of the HTTP request. 

![Untitled](/img/posts/Single-packet/Untitled.webp)

Once the HTTP server that is receiving the data gets a frame that contains the `END_STREAM` flag, the server knows that the whole HTTP packet has been sent and can process it. 

## Back to the attack

Now that we have explained some basic concepts about HTTP/2, we can explain how we can use this to trigger the execution of different requests at the same time. 

What we have to do is send all the headers but without sending the `END_STREAM` (if it has body data, we will also withhold the last byte). If we do this with all the requests and wait a bit, the server will receive all the requests but it will still be waiting for all of them to finish because it hasn’t received a single `END_STREAM` packet. 


> Some server implementations may use the content-length header to decide when a message is complete, that’s te reason why we also withhold the last byte of data if the request has a body
{: .prompt-info}

Finally, we will send all the frames that contain the `END_STREAM` flag. They should be able to fit in a single TCP packet, so when the server receives this packet and processes it, it will finish the streams for all the pending requests and process them simultaneously, increasing the chances of dettecting and exploiting a race condition. 

![Single-packet attack.gif](/img/posts/Single-packet/Single-packet_attack.gif)


> The content on this post is based on this James Kettle’s whitepaper [https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local](https://portswigger.net/research/smashing-the-state-machine#single-packet-attack)
{: .prompt-info}
