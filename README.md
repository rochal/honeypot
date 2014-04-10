honeypot
=========

Node.js implementation of the Project Honeypot (Http:BL) API. Because we all hate spam.

  - Utilizes Http:BL from known and loved https://www.projecthoneypot.org/
  - Uses built-in node dns.resolve4 to get response from the DNS API
  - No Unicorns were harmed during development

Installation
--------------

```sh
npm install honeypot
```

Usage
----
```javascript
var honeypot = require('honeypot');

var pot = new honeypot('your_api_key');

pot.query('127.0.0.1', function(err, response){
    if (!response) {
        console.log("IP not found in honeypot, we're all good!");
    } else {
        console.log("Oh no, it's a spammer mate! Kil it with fire!");
        console.log(response.getFormattedResponse());
        // Suspiious, Comment Spammer
        // Threat Rating: 58 / 255
        // Recency: 1 / 255
    }
});
```

Example within Express
----

```javascript
var honeypot = require('honeypot');

var pot = new honeypot('your_api_key');

// example route for POST /comment/
create: function(req, res) {

    pot.query(req.ip, function(err, response){
      if (!response) {
        console.log("IP not found in honeypot, we're all good!");
        // do some commentary magic
        res.send({ msg: 'we hate spam!' });
      } else {
        console.log("Die!");
        res.send(null);
      }
    });
}
```

Kudos
----

Based on this sweet PHP gist https://gist.github.com/smithweb/7773373.


License
----

MIT

**Free Software, Hell Yeah!**
