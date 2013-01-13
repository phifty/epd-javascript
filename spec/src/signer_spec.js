
describe("Signer", function () {

  var namespace = epdRoot.Signer
    , signature;

  beforeEach(function () {
    if (!signature) {
      signature = namespace.sign(fixtures.lockedProfile(), fixtures.profile().publicKey, fixtures.profile().privateKey);
    }
  });

  describe("#sign", function () {

    it("should return the signature for the profile", function () {
      expect(signature).toBeOfType("rsaSignature");
    });

    it("should return the same signature if signed a second time", function () {
      var secondSignature = namespace.sign(fixtures.lockedProfile(), fixtures.profile().publicKey, fixtures.profile().privateKey);
      expect(secondSignature).toEqual(signature);
    });

  });

  describe("#verify", function () {

    it("should return true if the signature fits the profile", function () {
      var result = namespace.verify(fixtures.lockedProfile(), signature, fixtures.profile().publicKey);
      expect(result).toBeTruthy();
    });

    it("should return false if the signature does not fit the profile", function () {
      var profile = epdRoot.Object.clone(fixtures.lockedProfile());
      profile.contacts.test = "value";
      expect(namespace.verify(profile, signature, fixtures.profile().publicKey)).toBeFalsy();
    });

  });

});
