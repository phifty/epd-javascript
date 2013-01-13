
describe("Crypt.Symmetric.Object", function () {

  var namespace = epdRoot.Crypt.Symmetric.Object;

  describe("#encrypt", function () {

    it("should return the encrypted object", function () {
      var encrypted = namespace.encrypt(fixtures.object(), fixtures.key());
      expect(encrypted).toBeOfType("aesEncryptedData");
    });

  });

  describe("#decrypt", function () {

    it("should return the decrypted object", function () {
      var decrypted = namespace.decrypt(fixtures.encryptedObject(), fixtures.key());
      expect(decrypted).toEqual(fixtures.object());
    });

  });

});
