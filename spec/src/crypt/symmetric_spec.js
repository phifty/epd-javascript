
describe("Crypt.Symmetric", function () {

  var namespace = epdRoot.Crypt.Symmetric;

  describe("#generateKey", function () {

    it("should return a valid key", function () {
      var key = namespace.generateKey();
      expect(key).toBeOfType("aesKey");
    });

  });

  describe("#encrypt", function () {

    it("should return the encrypted version of the given message using the given key", function () {
      var encrypted = namespace.encrypt(fixtures.message(), fixtures.key());
      expect(encrypted).toBeOfType("aesEncryptedData");
    });

  });

  describe("#decrypt", function () {

    it("should return the decrypted version of the given encrypted message using the given key", function () {
      var decrypted = namespace.decrypt(fixtures.encryptedMessage(), fixtures.key());
      expect(decrypted).toEqual(fixtures.message());
    });

  });

});
