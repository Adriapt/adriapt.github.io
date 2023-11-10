---
title: "Race Conditions"
author: Adrià Pagès Torruella
date: 2023-11-10 17:30:00 +0800
categories: [Web Vulnerabilities]
tags: [Web,HTTP,Race Condition]
math: true
render_with_liquid: false
---

# Race Conditions

When a website has to handle concurrent requests at the same time, they use different threads so they can execute them in parallel. These threads interact with the same database and if the code isn’t developed thinking about concurrency risks, race conditions arise. 

A race condition exploits the time-gap between a security check and the action taken. To exemplify this situation, imagine the usage of a discount code. 

When you use the discount, the application will first check if you have already used this discount, then, if you didn’t, it will apply the discount and then invalidate that code so you can’t use it again. 

```
if discount_applied == false{ //The value is checked here
	apply_discount()
	discount_applied = true //But it is changed here. The time between is the "race window"
}
```

The time between the first check and when the account is invalidated is known as a **race window** and is when a **race condition** can take place. Once the first check is valid and the app procedes to use the discount, the discount hasn’t been invalidated yet, so if a concurrent thread handling the same request with the same discount code, when checking if the code has been used the answer will be “no” and it will lead to the discount code being applied two times. 

However, these race windows may be really small, so sending two different TCP packets to exploit this may be difficult due to latency and jitter. The “Single-packet attack” can deal with this situation by adding the two or more requests in the same TCP packet. I strongly recommend to read [THIS](https://adriapt.github.io/posts/SinglePacketAttack/) other post where I explain how a single-packet attack works (it takes just 3 minutes). 

Lets use WebSecurityAcademy’s labs to examplify it. 

This website allows us to use the `PROMO20` discount code. If we try to use it more than one time, we get an error message: 

![Untitled](/img/posts/RaceCondition/Untitled.png)

So let’s assume that the web app controls somehow whether the coupon has been used or not. But, what if we could send two or more concurrent requests at the same time (within the **race window** span time)? 

Let’s use Burp Suite for this. We will use the proxy and capture the `POST` request that is triggered when trying to apply the coupon. Then we will send it to the Repeater several times (7 in my example). In the Repeater we will create a group (clicking on the `+` icon) and we will add all the requests in the same group. 

![Untitled](/img/posts/Untitled%201.png)

Burp Suite makes sending the packets in parallel super easy. We just need to click on de arrow next to the “Send” and use the “Send group in parallel”. It will try to use the single-packet attack if the connection is using HTTP/2. 

![Untitled](/img/posts/Untitled%202.png)

If we check the response for each request, we can see that the coupon has been applied more than one time, implying that we have been able to exploit this race condition vulnerability: 

![Untitled](/img/posts/Untitled%203.png)

![Untitled](/img/posts/Untitled%204.png)

If pause the proxy and go back to the webpage, we can see that now the moni reduced is much higher than when we applied just one coupon (To solve the lab i had to repeat the attack using more concurrent requests to get a higher discount). 

![Untitled](/img/posts/ntitled%205.png)


> If you want to do a more complex attack or send more requests, you can use the Turbo Intruder extension with [this](https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py) python script
{: .prompt-info]

## **Multi-endpoint race condition**

In the previous example we saw how we could abuse race conditions by attacking a single endpoint. However, most race conditions vulnerabilities exists when you interact with different endpoints at the same time. 

Let’s use another lab as an example (it uses the same shopping webpage): 

Here we can see that we have some credit (100$), a Cart with a value total value of 10$ and the option to add a coupon (we won’t interact with coupons for this lab) or proceed with the payment.

![Untitled](/img/posts/Untitled%206.png)

The expected flow should be something like this: 

1. The user “places the order” to proceed with the payment
2. The server checks the total price of the cart
3. The server executes the order, buying all objects in the cart
4. The server deduces that amount of money from the Store credit

>Steps 3 and 4 could be swapped, but with this example the “race window” is bigger and easier to exemplify.
{: .prompt-info]

In low code, the vulnerable implementation could be similar to this one: 

```
function place_order(){
	get store credit
	get cart_price //1. Here we read the cart price
	if(cart_price <= store_credit){ //2. here we use the cart price value to decide if we have enough money
		process_order() //3. Here the server buys every object in the cart 
		store_credit = store_credit - cart_price
	}
}
```

Can you identify the possible race condition? If we are able to add new items in the cart between the pint 1 and 3, the server will use the initial (low) cart price to decide if we have enough money to buy it, but then, when processing the order in the `process_order()` function, the server will add the extra items without considering their price. 

However, if we want to add a new item in the cart, we need to use another endpoint. In conclusion, we the “**add item**” endpoint to get executed within the “**race window**” that the “**place order**” endpoint has. 

This means that we have to capture the requests that adds an item to the cart and the request that requests the server to process the order. We want to do this with a initial cart with a low price, so when the server checks if we have enough money, it returns true. Lets do it!

1. I have a Cart with items that I can afford, so I click to the “Place order” and capture the request. I will send it to Burp Repeater (Ctrl + R) and drop de request, since I don’t want the server to process the order yet. 

![Untitled](/img/posts/Untitled%207.png)

1. Now I will go to the shop and “Add to cart” a expensive item that I can’t afford. I will also capture the request, send it to repeater and drop it. It is important to drop the request since otherwise it will be added to the cart now and we need it to be added inside the “race window”

![Untitled](/img/posts/Untitled%208.png)

1. In the repeater tab, I duplicated the requests so the chances that one of them is executed within the race window from the other are higher. As explained in the previous example, we will group all these requests and send them in parallel.  
    
    ![Untitled](/img/posts/Untitled%209.png)
    
2. Now that the attack has been executed, lets check the responses and search for 200 response codes. 
    
    ![Untitled](/img/posts/Untitled%2010.png)
    
3. If we analyze this answer in the browser, we can see that we have been able to add to the cart 3 Jackets within the race window, so we exploited a multi endpoint race condition!

![Untitled](/img/posts/Untitled%2011.png)
