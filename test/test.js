"use strict";

var chai = require("chai");
var expect = chai.expect;
var cc_cryptutils = require("./../index");
var crypto = require("crypto");

describe("Encryption", function() {

    it("encrypts a string", function(done) {

        var cc_crypt = cc_cryptutils();
        var key = crypto.randomBytes(20).toString("hex");
        var str = "123";

        cc_crypt.setEncryptionKey(key);

        var cryptStr = cc_crypt.encrypt(str);
        expect(cryptStr).to.not.equal(str);
        expect(cryptStr).to.be.a("string");

        var decryptStr = cc_crypt.decrypt(cryptStr);
        expect(decryptStr).to.equal(str);

        done();
    });

    it("encrypts a number", function(done) {

        var cc_crypt = cc_cryptutils();
        var key = crypto.randomBytes(20).toString("hex");
        var num = 123;

        cc_crypt.setEncryptionKey(key);

        var cryptNum = cc_crypt.encrypt(num);
        expect(cryptNum).to.not.equal(num);
        expect(cryptNum).to.be.a("string");

        var decryptNum = cc_crypt.decrypt(cryptNum);
        expect(num).to.equal(decryptNum);

        done();
    });

    it("encrypts an array", function(done) {

        var cc_crypt = cc_cryptutils();
        var key = crypto.randomBytes(20).toString("hex");
        var arr = [123, "456"];

        cc_crypt.setEncryptionKey(key);

        var cryptArr = cc_crypt.encrypt(arr);
        expect(cryptArr).to.not.equal(arr);
        expect(cryptArr).to.be.a("string");

        var decryptArr = cc_crypt.decrypt(cryptArr);
        expect(decryptArr).to.deep.equal(arr);

        done();
    });

    it("encrypts an object", function(done) {

        var cc_crypt = cc_cryptutils();
        var key = crypto.randomBytes(20).toString("hex");
        var obj = {"123": 456};

        cc_crypt.setEncryptionKey(key);

        var cryptObj = cc_crypt.encrypt(obj);
        expect(cryptObj).to.not.equal(obj);
        expect(cryptObj).to.be.a("string");

        var decryptObj = cc_crypt.decrypt(cryptObj);
        expect(decryptObj).to.deep.equal(obj);

        done();
    });

    it(".encrypt() throws an error without an encryption key", function(done) {

        var cc_crypt = cc_cryptutils();
        var num = 123;

        expect( cc_crypt.encrypt.bind(null, num) ).to.throw("missing encryption key. This can be set using 'setEncryptionKey()'");

        done();
    });

    it(".encrypt() throws an error without an encryption key", function(done) {

        var cc_crypt = cc_cryptutils();
        var cryptStr = "123";

        expect( cc_crypt.encrypt.bind(null, cryptStr) ).to.throw("missing encryption key. This can be set using 'setEncryptionKey()'");

        done();
    });



    it(".decrypt() throws an error when input isn't a string", function(done) {

        var cc_crypt = cc_cryptutils();
        var key = crypto.randomBytes(20).toString("hex");
        cc_crypt.setEncryptionKey(key);

        var num = 123;

        expect( cc_crypt.decrypt.bind(null, num) ).to.throw("Input must be a string");

        done();
    });
});
