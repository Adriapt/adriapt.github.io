---
title: "Prototype Pollution"
author: "Adria Pages Torruella"
date: 2024-02-11 17:30:00 +0800
categories: [Web Vulnerabilities]
tags: [Web,XSS]
math: true
render_with_liquid: false
---
![prototype pollution.jpg](/img/posts/ProtoPoll/prototype_pollution.jpg)
# Prototype Pollution
## JavaScript prototypes and inheritance

JavaScript is a language model that uses prototypal inheritance. A JavaScritp object is a collection of `key:value` pairs (or properties). These properties can be data  or functions (also known as “methods”)

For example, this object has some properties such as `username: "wiener"` and methods such as the `exampleMethod`: 

```
const user =  {
    username: "wiener",
    userId: 01234,
    exampleMethod: function(){
        // do something
    }
}
```

This `user` object is a literal because it has been created using curly brace syntax to declare its properties. 

In JavaScript, almost everything everything is an object and every object is linked to another object (its prototype). For example, every `string` is assigned by default to the `String.prototype` object. An object inherits all the properties of their prototype unless they overwrite some properties using the same “key”. The `String.prototype` object has the `toLowerCase()` method, so every string that you define in JavaScript can use this method. 

 When you try to access a property or method of an object, the engine first tries to access the object itself, then, if he doesn’t have a matching property, it references its property object. If you define `myObject` with only propertyC, you can access propertyA because its inherits it from the prototype. 

![Untitled](/img/posts/ProtoPoll/Untitled.svg)

Since everything is a prototype of another object, this leads to the top-level object: `Object.prototype` , whose prototype is `null`. 

Every object has the `__proto__` property that you can use to access its prototype and also change it in case you want to change the prototype of the object. 

You can also modify built-in prototypes by referencing them and creating new methods or properties. It is considered a bad practice, but if you create a custom function for the `String.prototype`, then all strings will have this prototype. 

```
String.prototype.customFunction = function(){
    // do whatever I want
}
```

## Prototype Pollution

This vulnerability occurs when the application processes input from the user and constructs objects based on that input. If this input is not validated, an attacker could manipulate the prototype of an object and, as a result, modify the behavior of the application. 

Imagine that an attacker provides this URL to a vulnerable server: `https://vulnerable-website.com/?__proto__[evilProperty]=payload`

If the application merges this parameter to an object like this: 
`targetObject.__proto__.evilProperty = 'payload';` it won’t be adding the payload to the object directly, but its property. After this assignment, all the objects with the same prototype as `targetObject` will have the `evilProperty`. This doesn’t have any effect unless the attacker uses properties used in the application. 

## Client-side prototype pollution

To find a vulnerability manually you need to try to add arbritary properties to the `Object.prototype` until you find one. You can use the browser console to validate that the property has been inserted by inspecting the `Object.prototype`. 

In this example, if we directly add a parameter in the get url:

![Untitled](/img/posts/ProtoPoll/Untitled.png)

And then check the Object.prototype object in the Console, we can see that the `test` property has been added, so we identified a source to add properties. 

![Untitled](/img/posts/ProtoPoll/Untitled%201.png)

Once you have found a source that allows you to add a property, you need to find a gadget that you can use to craft an exploit. You can inspect the source code and search for used properties. 

In this specific example, we can see in the JavaScript is the `transport_url`property from the `config`object and appending it to the DOM. This can be a potential XSS: 

![Untitled](/img/posts/ProtoPoll/Untitled%202.png)

Let’s try to add a new param to the object prototype, instead of `test` we will use `transport_url` :

![Untitled](/img/posts/ProtoPoll/Untitled%203.png)

If we inspect the DOM, we can see that there is a script tag with the src equal to “test”: 

![Untitled](/img/posts/ProtoPoll/Untitled%204.png)

So if we add another payload, such as `data:,alert(1);`, we can trigger a XSS vulnerability. 

![Untitled](/img/posts/ProtoPoll/Untitled%205.png)


>The general structure of a data URI is:
```
data:[<mediatype>][;base64],<data>
```
- `<mediatype>` is optional and specifies the media type of the data.
- `;base64` is optional and is used if the data is base64 encoded.
- `<data>` is the actual content of the data.
In the provided example (`data:,alert(1);`), no media type is specified, and base64 encoding is not used. After the comma, there is the JavaScript code `alert(1);`, which will execute in the browser context when the script is loaded.
{: .prompt-info}

This can be a hard task to do manually, so you can use the DOM Invader functionality that exists in BurpSuite browser that automatically checks for prototype pollution as you browse.

To do this, you need to open the Burp browser: 

![Untitled](/img/posts/ProtoPoll/Untitled%206.png)

And then go to the web app you want to analyze, in this case the lab and activate the DOM Invader prototype pollution: 

![Untitled](/img/posts/ProtoPoll/Untitled%207.png)

If we reload the page we see source that have been detected by the extension. The source we discovered manually has been detected automatically: 

![Untitled](/img/posts/ProtoPoll/Untitled%208.png)

We can use the “scan for gadgets” option to find exploits that could be used. 

![Untitled](/img/posts/ProtoPoll/Untitled%209.png)

And successfully exploit the XSS: 

![Untitled](/img/posts/ProtoPoll/Untitled%2010.png)

## Prototype pollution via the constructor

There are other ways to reference the prototype than just `__proto__` property.  Unless its prototype is set to `null`, every object has a `constructor` property, which is a function used to create the object. Functions are also objects and constructor functions have a property named `prototype` which points to the prototype that will be assigned to the object they create, hence, instead of the prototype using `myObject.__proto__` you can do  `myObject.constructor.prototype` to obtain the same result. 

## Server-side prototype pollution

Since there are backends like Node.js that use JavaScript, is also possible to find prototype pollutions at the server side. 

Server-side prototype pollution is challenging to detect compared to its client-side counterpart for several reasons:

**1. No Source Code Access**: Accessing vulnerable JavaScript code in server-side environments is typically impossible, posing challenges in identifying sinks and potential gadget properties.
**2. Lack of Developer Tools:** The absence of runtime object inspection in server-side environments, unlike client-side debugging with browser DevTools, makes it difficult to detect successful prototype pollution unless it visibly impacts the website's behavior.
**3. The DoS Problem:** Polluting objects in server-side environments risks breaking application functionality or causing a denial-of-service (DoS) issue.
**4. Pollution Persistence:** In contrast to browser testing, where changes can be easily reversed by refreshing the page, server-side prototype pollution changes endure throughout the entire lifetime of the Node process.

`POST` or `PUT` requests that submit JSON data to  an application or API are prime candidates for this kind of behavior as it's common for servers to respond with a JSON representation of the new or updated object.

If there is no response that allows you to confirm a successful pollution, you can try to overwrite configuration properties that can cause a different behavior in the application: 

- **Status code override:** Error messages can be customized by developers by using the `status` or `statusCode` property. If you find a way to override this property and generate an error and the error status code changed, you can confirm the pollution.
- **JSON space override:** The `json spaces` property defines what is the indent of JSON data in responses . If you can override this value, you can confirm its pollution by checking if the indentation has changed.

## Preventing Prototype Pollution

An effective way is to use a whitelist of permitted keys before merging them into objects. However, this may not be feasible then blacklist should be used. 

Another way is to prevent prototypes from being changed. You can do this by invoking the `Object.freeze()` method on an object, so you can freeze objects by doing: `Object.freeze(Object.prototype);`
