
describe("Crypt.Asymmetric", function () {

  var namespace = epdRoot.Crypt.Asymmetric;

  describe("#generateKeyPair", function () {

    var keyPair;

    beforeEach(function () {
      if (!keyPair) {
        keyPair = namespace.generateKeyPair();
      }
    });

    it("should return a key pair with a public key", function () {
      expect(keyPair.publicKey).toBeOfType("rsaKey");
    });

    it("should return a key pair with a private key", function () {
      expect(keyPair.privateKey).toBeOfType("rsaKey");
    });

  });

  describe("#encrypt", function () {

    it("should return the encrypted version of the given message using the given key", function () {
      var encryptedMessage = namespace.encrypt(fixtures.message(), fixtures.keyPair().publicKey);
      expect(encryptedMessage).toBeOfType("rsaEncryptedData");
    });

  });

  describe("#decrypt", function () {

    it("should return the decrypted version of the given encrypted message using the given key", function () {
      var encryptedMessage = namespace.encrypt(fixtures.message(), fixtures.keyPair().publicKey),
          decryptedMessage = namespace.decrypt(encryptedMessage, fixtures.keyPair().publicKey, fixtures.keyPair().privateKey);
      expect(decryptedMessage).toEqual(fixtures.message());
    });

  });

  describe("#encryptSymmetric", function () {

    it("should return the encrypted version of the given large message", function () {
      var encryptedMessage = namespace.encryptSymmetric(fixtures.largeMessage(), fixtures.keyPair().publicKey);
      expect(encryptedMessage).toBeOfType("rsaAesEncryptedData");
    });

  });

  describe("#decryptSymmetric", function () {

    it("should return the decrypted version of the given encrypted message using the given key", function () {
      var encryptedMessage = namespace.encryptSymmetric(fixtures.largeMessage(), fixtures.keyPair().publicKey),
          decryptedMessage = namespace.decryptSymmetric(encryptedMessage, fixtures.keyPair().publicKey, fixtures.keyPair().privateKey);
      expect(decryptedMessage).toEqual(fixtures.largeMessage());
    });

  });

  describe("#sign", function () {

    it("should return the signature for the given string created with the given key", function () {
      var signature = namespace.sign(fixtures.message(), fixtures.keyPair().publicKey, fixtures.keyPair().privateKey);
      expect(signature).toBeOfType("rsaSignature");
    });

  });

  describe("#verify", function () {

    it("should return true if the given signature matches to given message", function () {
      var result = namespace.verify(fixtures.message(), fixtures.messageSignature(), fixtures.keyPair().publicKey);
      expect(result).toBeTruthy();
    });

    it("should return false if the given signature not matches to given message", function () {
      var result = namespace.verify("invalid", fixtures.messageSignature(), fixtures.keyPair().publicKey);
      expect(result).toBeFalsy();
    });

  });

});
