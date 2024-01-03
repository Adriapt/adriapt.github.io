---
title: "Clickjacking"
author: "Adria Pages Torruella"
date: 2023-12-03 17:30:00 +0800
categories: [Web Vulnerabilities]
tags: [Web,Clickjacking]
math: true
render_with_liquid: false
---

![Untitled](/img/posts/Clickjacking/Clickjacking%20portada.jpg)

Clickjacking is a type of attack where a malicious website tricks a user into clicking something different from what the user perceives. The attacker overlays or hides the actual elements of a webpage with transparent or opaque layers containing deceptive content. This can lead the user to unwittingly interact with the hidden elements, often performing actions they did not intend to perform.

>This attack differs from a CSRF attack in that the user is required to perform an action such as a button click whereas a CSRF attack depends upon forging an entire request without the user's knowledge or input.
{: .prompt-info}

CSRF uses tokens to avoid the vulnerability, however, if we are talking about clickjacking, this is not mitigated because a real session is established and the content is loaded from the authentic website (even it may be invisible because of a hidden iframe), with a valid token included.  

Clickjacking works by using CSS to manipulate layers. The attacker adds using an iframe the vulnerable website on top of the decoy website, using an appropriate width and height. 

Absolute and relative position values are used to ensure that the target website accurately overlaps the decoy regardless of screen size, browser type and platform. 

The `z-index` in CSS determines the stacking order of the iframe and website layers and the `opacity` is used to make the vulnerable website transparent. 

This is an example of a decoy website doing a Clickjacking attack: 

```html
<head>
	<style>
		#target_website {
			position:relative;
			width:128px;
			height:128px;
			opacity:0.00001;
			z-index:2;
			}
		#decoy_website {
			position:absolute;
			top:30px;
			left:40px;
			z-index:1;
			}
	</style>
</head>
...
<body>
	<div id="decoy_website">
	...decoy web content here...
	</div>
	<iframe id="target_website" src="https://vulnerable-website.com">
	</iframe>
</body>
```

Let’s do a real example. Using Portswigger’s academy, we will build a decoy website. I will first add the opacity to 0,5 so we can see what’s happening. The vulnerable web page with a “Delete account” button is added in a iframe, but in the decoy webpage we create a “Click here” text and try to place it in the same position of the Delete account: 

![Untitled](/img/posts/Clickjacking/Untitled.png)

```xml
<head>
	<style>
		#target_website {
			position:relative;
			width:700px;
			height:600px;
			opacity:0.5;
			z-index:1;
			}
		#decoy_website {
			position:absolute;
			top:500px;
			left:60px;
			z-index:0;
			}
	</style>
</head>
...
<body>
	<div id="decoy_website">
Click Here
	</div>
	<iframe id="target_website" src="https://0ad0007e037aa9b7813e39e500f700c0.web-security-academy.net/my-account">
	</iframe>
</body>
```

Now I will reduce the opacity to 0.0001. As you can see, the top frame (the iframe with the vulnerable website) is invisible: 

![Untitled](/img/posts/Clickjacking/Untitled%201.png)

Even though it is invisible, it the top frame, so if the victim goes to the “click here” text and clicks, it will be interacting with the “Delete account” button instead.

If the request needs some data to be filled, an attacker could directly fill it specifying the parameters in the URL: 

![Untitled](/img/posts/Clickjacking/Untitled%202.png)

![Untitled](/img/posts/Clickjacking/Untitled%203.png)

## Frame Buster

A common protection that web applications use is “frame busting”. It consists of scripts in the web page that check if application is in the main or top window. If not, they try to avoid being framed.  

>Don’t confuse being in the top window with being in the top of the stack using the `z-index` . Since the vulnerable application is being framed, it is not the top window.
{: .prompt-info}

However, this technique can be easily circumvented by attackers by using sandboxed `iframe`. 

The `sandbox` attribute is used to specify certain  restrictions on the capabilities of the embedded content. When an iframe is sandboxed, it creates a security boundary that can limit various 
actions and behaviors of the embedded content. You can use the `sandbox` attribute to specify what it is allowed, such as `allow-forms` or `allow-scripts` . If we don’t allow scripts, the frame busting script that the webapp implements wont be executed since it will be inside the sandboxed `iframe`, bypassing the security check that the developers used. 

We can use another example to show this behavior. If we try the previous attack, we see that we get a message error saying that the page can’t be framed. 

![Untitled](/img/posts/Clickjacking/Untitled%204.png)

Checking the source code of the HTML page, we can see that it is using a frame boosting script that replaces all the content if the page is being framed. 

![Untitled](/img/posts/Clickjacking/Untitled%205.png)

To avoid bypass this protection, in the wep app developed by the attacker, we just have to add the `sandbox="allow-forms"` attribute and that script won’t get executed. 

![Untitled](/img/posts/Clickjacking/Untitled%206.png)

![Untitled](/img/posts/Clickjacking/Untitled.png)

## Avoid Clickjacking attacks

We have seen that frame-busting scripts can try to avoid clickjacking attacks, however they are easy to bypass. Two other mechanisms that can be implemented server side are: 

- **X-Frame-Options Header:**
    - Set the `X-Frame-Options` header in HTTP responses to control whether a browser should be allowed to render a page in a frame or iframe.
    - The header can have three values: `deny` , `sameorigin`, `allow-from ...` . `deny` won’t allow the web page to be in a iframe, `sameorigin` will allow framing only to the same origin or you can use `allow-from` to whitelist origins that can frame your webpage.
- **Content Security Policy (CSP):**
    - The CSP provides the client browser with information about permitted sources of web resources that the browser can apply to the detection and interception of malicious behaviors.
    - Utilize the `frame-ancestors` directive to specify which origins are permitted to embed the current page. The possible values are `none`, `self` , or specific websites.
    - Example: `Content-Security-Policy: frame-ancestors 'self';`
