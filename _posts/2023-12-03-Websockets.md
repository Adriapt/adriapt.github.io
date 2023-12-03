---
title: "Websockets"
author: "Adria Pages Torruella"
date: 2023-12-03 17:30:00 +0800
categories: [Web Vulnerabilities]
tags: [Web,Websockets]
math: true
render_with_liquid: false
---

WebSockets is a communication protocol that provides full-duplex communication channels over a single, long-lived connection. It is designed to work over the same ports as HTTP and HTTPS (ports 80 and 443, respectively) and uses a similar handshake process to establish a connection. However, unlike traditional HTTP, which follows a request-response model, WebSockets enable bidirectional communication, allowing both the server and the client to send messages independently at any time.

![Untitled](/img/post/Websockets/Untitled.webp)

WebSockets are particularly useful in situations where low-latency or server-initiated messages are required, such as real-time feeds of financial data.

To initiate a websocket connection client pages use JavaScript like this one:  

`var ws = new WebSocket("wss://normal-website.com/chat");` 

Note that instead of `http` or `https` protocols we are using `wss` (we could also use `ws` but it will create an unencrypted connection)

Then, the websocket handshake is initiated over HTTP. 

**Client Sends a WebSocket Handshake Request:**

```jsx
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```

- The client is initiating the WebSocket handshake by sending an HTTP request to the server with the necessary headers.
- `Sec-WebSocket-Version: 13` indicates that the client is using WebSocket protocol version 13.
- `Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==` is a randomly generated base64-encoded key that the server will use to compute the `Sec-WebSocket-Accept` response header.
- `Connection: keep-alive, Upgrade` indicates that the client wants to keep the connection alive and is requesting an upgrade to the WebSocket protocol.
- `Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2` includes a session cookie, which is useful for maintaining user sessions even after the upgrade to WebSocket.
- `Upgrade: websocket` signals the server that the client wants to upgrade the connection to the WebSocket protocol.

**Server Responds with a WebSocket Handshake Acceptance:**

```jsx
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: qWbr4URh6RyC8Qkp8Xm3IrSKGLQ=
```

- `HTTP/1.1 101 Switching Protocols` indicates a successful upgrade to the WebSocket protocol.
- `Upgrade: websocket` and `Connection: Upgrade` confirm the protocol upgrade.
- `Sec-WebSocket-Accept: qWbr4URh6RyC8Qkp8Xm3IrSKGLQ=` is computed by the server using the received `Sec-WebSocket-Key` (wDqumtseNBJdhkihL6PW7w==) .

Now that the websocket connection has been established,  message between two sides can be sent by just doing this: 
`ws.send("Hello world");`

In principle, WebSocket messages can contain any content or data format. In modern applications, it is common for JSON to be used to send structured data within WebSocket messages.

## Websocket vulnerabilities

It’s not like websockets present vulnerabilities itself, but it is another channel that can be used to exploit other common vulnerabilities, such as XSS, CSRF, SQLi, etc. 

To test for them you will need to intercept the websocket message and change the content, for example to exploit a XSS attack: 

![Untitled](/img/post/Websockets/Untitled.png)

To exploit some vulnerabilities, you may need to intercept and manipulate the websocket handshake. For example there may be restrictions on the IP (you have been blocked by the server), so you could use the `X-Forwarded-For` header in the initial handshake to spoof the IP.

Last but not least, we have the cross-site WebSocket hijacking attack, that involves exploiting a CSRF on a WebSocket handshake. It arises when the WebSocket handshake request relies solely on HTTP cookies for session handling and does not contain any CSRF tokens or other unpredictable values.

An attacker can create a malicious web page on their own domain which establishes a cross-site WebSocket connection to the vulnerable application. The application will handle the connection in the context of the victim user's session with the application.

The attacker's page can then send arbitrary messages to the server via the connection and read the contents of messages that are received back from the server. This means that, unlike regular CSRF, the attacker gains two-way interaction with the compromised application.

The attack might involve:

- Sending WebSocket messages to perform unauthorized actions on behalf of the victim user.
- Sending WebSocket messages to retrieve sensitive data.
- Sometimes, just waiting for incoming messages to arrive containing sensitive data.
