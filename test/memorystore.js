'use strict';

var expect = require('chai').expect;
var uuid = require('node-uuid');
var chance = new require('chance')();

var MemoryStore = require('../');
var TokenStore = require('passwordless-tokenstore');

var standardTests = require('passwordless-tokenstore-test');

function TokenStoreFactory() {
  return new MemoryStore();
}

function beforeEachTest(done) {
  done();
}

function afterEachTest(done) { 
  done();
}

standardTests(TokenStoreFactory, beforeEachTest, afterEachTest);

describe('Specific tests', function() {
  
  beforeEach(beforeEachTest);
  afterEach(afterEachTest);
  
  it('should allow proper instantiation', function() {
    expect(function() { TokenStoreFactory() }).to.not.throw;
  });
  
  it('should store tokens only in their hashed form', function(done) {
    var store = TokenStoreFactory();
    var token = uuid.v4();
    var uid = chance.email();
    var ttl = 1000*60;
    var originUrl = 'http://' + chance.domain() + '/page.html';
    
    store.storeOrUpdate(token, uid, ttl, originUrl, function() {
      var item = store._cache[uid];
      expect(item.uid).to.equal(uid);
      expect(item.hashedToken).to.not.equal(token);
      done();
    });
  });
  
  it('should store tokens not only hashed but also salted', function(done) {
    var store = TokenStoreFactory();
    var token = uuid.v4();
    var uid = chance.email();
    var ttl = 1000*60;
    var originUrl = 'http://' + chance.domain() + '/page.html';
    
    store.storeOrUpdate(token, uid, ttl, originUrl, function() {
      var hashedToken1 = store._cache[uid].hashedToken;
      store.clear(function() {
        
        store.storeOrUpdate(token, uid, ttl, originUrl, function() {
          var hashedToken2 = store._cache[uid].hashedToken;
          expect(hashedToken2).to.not.equal(hashedToken1);
          done();
        });
        
      });
    });
    
  });
  
});
