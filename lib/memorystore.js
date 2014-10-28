'use strict';

var util = require('util');
var bcrypt = require('bcryptjs');
var TokenStore = require('passwordless-tokenstore');

function MemoryStore() {
  TokenStore.call(this);
  
  this._cache = {};
}

util.inherits(MemoryStore, TokenStore);

MemoryStore.prototype.authenticate = function(token, uid, callback) {
  if (!token || !uid || !callback) {
    throw new Error('TokenStore:authenticate called with invalid parameters');
  }
  
  var item = this._cache[uid];
  if (!item) {
    return callback(null, false, null);
  }
  
  this._validateToken(token, item, function(err, res) {
    if (err) {
      return callback(err, false, null);
    }
    
    if (res) {
      return callback(null, true, item.originUrl);
    }
    
    return callback(null, false, null);
  });
};

MemoryStore.prototype.storeOrUpdate = function(token, uid, msToLive, originUrl, callback) {
  if (!token || !uid || !msToLive || !callback) {
    throw new Error('TokenStore:storeOrUpdate called with invalid parameters');
  }
  
  bcrypt.hash(token, 10, function(err, hashedToken) {
    
    if (err) {
      return callback(err);
    }
  
    var newRecord = {
      hashedToken: hashedToken,
      uid: uid,
      ttl: new Date(Date.now() + msToLive),
      originUrl: originUrl
    };

    this._cache[uid] = newRecord;  
    callback();
    
  }.bind(this));
};

MemoryStore.prototype.invalidateUser = function(uid, callback) {
  if (!uid || !callback) {
    throw new Error('TokenStore:invalidateUser called with invalid parameters');
  }
  
  delete this._cache[uid];
  callback();
};

MemoryStore.prototype.clear = function(callback) {
  if (!callback) {
    throw new Error('TokenStore:clear called with invalid parameters');
  }
  
  delete this._cache;
  this._cache = {};
  callback();
};

MemoryStore.prototype.length = function(callback) {
  callback(null, Object.keys(this._cache).length);
};

MemoryStore.prototype._validateToken = function(token, storedItem, callback) {
  if (storedItem && storedItem.ttl > new Date()) {
    bcrypt.compare(token, storedItem.hashedToken, function(err, res) {
      if (err) {
        return callback(err, false, null);
      }
      
      if (res) {
        return callback(null, true, storedItem.originUrl);
      }
      
      callback(null, false, null);
    });
  } else {
    callback(null, false, null);
  }
};

module.exports = MemoryStore;