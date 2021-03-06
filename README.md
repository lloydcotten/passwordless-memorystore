# Passwordless-MemoryStore

This module provides token storage for [Passwordless](https://github.com/florianheinemann/passwordless), a node.js module for express that allows website authentication without password using verification through email or other means. Visit the project's website https://passwordless.net for more details.

Tokens are stored in memory and are hashed and salted using [bcryptjs](https://github.com/dcodeIO/bcrypt.js).  As such, tokens will not survive a restart of your application.  This implementation is mainly meant for example, proof-of-concepts or perhaps unit testing.

## Usage

First, install the module:

`$ npm install passwordless-memorystore --save`

Afterwards, follow the guide for [Passwordless](https://github.com/florianheinemann/passwordless). A typical implementation may look like this:

```javascript
var passwordless = require('passwordless');
var MemoryStore = require('passwordless-memorystore');

passwordless.init(new MemoryStore());

passwordless.addDelivery(
    function(tokenToSend, uidToSend, recipient, callback) {
        // Send out a token
    });
    
app.use(passwordless.sessionSupport());
app.use(passwordless.acceptToken());
```

## Initialization

```javascript
new MemoryStore();
```

Example:
```javascript
passwordless.init(new MemoryStore());
```

## Hash and salt
As the tokens are equivalent to passwords (even though they do have the security advantage of only being valid for a limited time) they have to be protected in the same way. passwordless-memorystore uses [bcryptjs](https://github.com/dcodeIO/bcrypt.js) with automatically created random salts. To generate the salt 10 rounds are used.

## Tests

`$ npm test`

## License

[MIT License](http://opensource.org/licenses/MIT)

## Author
Lloyd Cotten