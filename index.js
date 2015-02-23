"use strict";
//
// encryption/decryption package for node.js
//

var crypto = require("crypto");
var _ = require("lodash");

var ENCODINGS_ENUM = ["ascii", "utf8", "utf16le", "ucs2", "base64", "binary", "hex"];


/**
 *
 * @param {String} key
 * @returns {{setInputEncoding: setInputEncoding, setOutputEncoding: setOutputEncoding, setEncryptionKey: setEncryptionKey, setCipherAlgorithm: setCipherAlgorithm, encrypt: encrypt, decrypt: decrypt}}
 */
module.exports = function(key) {

    var _inputEncoding = "utf8";
    var _outputEncoding = "hex";
    var _encryptionKey = key || undefined;
    var _algo = "aes-256-cbc";

    return {
        setInputEncoding: setInputEncoding,
        setOutputEncoding: setOutputEncoding,
        setEncryptionKey: setEncryptionKey,
        setCipherAlgorithm: setCipherAlgorithm,
        encrypt: encrypt,
        decrypt: decrypt
    };


    /**
     *
     * @param {String} [encoding=utf8]
     */
    function setInputEncoding(encoding) {

        if (!encoding) {
            _inputEncoding = "utf8";
        }
        else if (_.indexOf(ENCODINGS_ENUM, encoding) === -1) {
            throw new Error("Illegal encoding: " + encoding + ". \n" +
                "acceptable options are: " + ENCODINGS_ENUM.join(", "));
        }
        else {
            _inputEncoding = encoding;
        }
    }


    /**
     *
     * @param {String} encoding
     */
    function setOutputEncoding(encoding) {

        if (!encoding) {
            _outputEncoding = "hex";
        }
        else if (_.indexOf(ENCODINGS_ENUM, encoding) === -1) {
            throw new Error("Illegal encoding: " + encoding + ". \n" +
                "acceptable options are: " + ENCODINGS_ENUM.join(", "));
        }
        else {
            _outputEncoding = encoding;
        }
    }


    /**
     *
     * @param {String} algo
     */
    function setCipherAlgorithm(algo) {

        var availableCiphers = crypto.getCiphers();

        if(_.indexOf(availableCiphers, algo) === -1) {
            throw new Error("Illegal algorithm: " + algo + ".\n" +
                "Acceptable options are: " + availableCiphers.join(", "));
        }
        else {
            _algo = algo;
        }
    }


    /**
     *
     * @param {String} key
     */
    function setEncryptionKey (key) {

        _encryptionKey = key;
    }


    /**
     *
     * @param {*} value
     * @returns {String}
     */
    function encrypt(value) {

        if (!_encryptionKey) {
            throw new Error("missing encryption key. This can be set using 'setEncryptionKey()'")
        }

        var text = JSON.stringify(value);
        var textBuffer = new Buffer(text, _inputEncoding);
        var cipher = crypto.createCipher(_algo, _encryptionKey);
        cipher.write(textBuffer);
        cipher.end();
        return cipher.read().toString(_outputEncoding);
    }


    /**
     *
     * @param {String} string
     * @returns {*}
     */
    function decrypt(string) {

        if (!_encryptionKey) {
            throw new Error("missing encryption key. This can be set using 'setEncryptionKey()'")
        }

        if ( !string ) {
            return string;
        }
        var buff = new Buffer(string, _outputEncoding);
        var decipher = crypto.createDecipher(_algo, _encryptionKey);
        decipher.write(buff);
        decipher.end();
        var value = decipher.read().toString(_inputEncoding);
        return JSON.parse(value);
    }
};
