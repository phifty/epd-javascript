
describe("Crypt.Asymmetric.Object", function () {

  var namespace = epdRoot.Crypt.Asymmetric.Object;

  describe("#encrypt", function () {

    it("should return a string with the encrypted object", function () {
      var encrypted = namespace.encrypt(fixtures.object(), fixtures.keyPair().publicKey);
      expect(encrypted).toBeOfType("rsaAesEncryptedData");
    });

  });

  describe("#decrypt", function () {

    it("should return the decrypted object", function () {
      var encrypted = namespace.encrypt(fixtures.object(), fixtures.keyPair().publicKey),
          decrypted = namespace.decrypt(encrypted, fixtures.keyPair().publicKey, fixtures.keyPair().privateKey);
      expect(decrypted).toEqual(fixtures.object());
    });

  });

});
