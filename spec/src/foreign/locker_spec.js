
describe("Foreign.Locker", function () {

  var namespace = epdRoot.Foreign.Locker;

  describe("#unlock", function () {

    var profile;

    beforeEach(function () {
      if (!profile) {
        profile = namespace.unlock(fixtures.lockedProfile(), fixtures.anotherProfile());
      }
    });

    it("should return a profile where the public key is decoded", function () {
      expect(profile.publicKey).toBeOfType("rsaKey");
    });

    it("should return a profile without a private key", function () {
      expect(profile.privateKey).toBeUndefined();
    });

    it("should decrypt the keys of the own profile's contact", function () {
      expect(typeof(profile.contacts[ fixtures.anotherProfile().id ].keys)).toEqual("object");
    });

    it("should strip down contacts that cannot be decrypted", function () {
      var otherProfile = epdRoot.Generator.generate()
        , unlockProfile = namespace.unlock(fixtures.lockedProfile(), otherProfile);

      expect(unlockProfile.contacts[ fixtures.anotherProfile().id ]).toEqual({ publicKey: fixtures.anotherProfile().publicKey });
    });

    it("should return a profile where the right keys are unlocked", function () {
      expect(epdRoot.Contacts.keyForContactIdAndSectionId(profile, fixtures.anotherProfile().id, "test")).toBeOfType("aesKey");
    });

    it("should return a profile without keys for the fixed sections", function () {
      expect(epdRoot.Contacts.keyForContactIdAndSectionId(profile, fixtures.anotherProfile().id, "open")).toBeUndefined();
      expect(epdRoot.Contacts.keyForContactIdAndSectionId(profile, fixtures.anotherProfile().id, "closed")).toBeUndefined();
    });

    it("should return a profile where the right sections are unlocked", function () {
      expect(epdRoot.Sections.byId(profile, "test")).toEqual({ title: "Test", modules: { } });
    });

    it("should return a profile where the open sections are unlocked", function () {
      expect(epdRoot.Sections.byId(profile, "open")).toEqual(fixtures.openSection());
    });

    it("should return a profile without closed section", function () {
      expect(epdRoot.Sections.byId(profile, "closed")).toBeUndefined();
    });

    it("should decode the profile only if no current profile is given", function () {
      var unlockedProfile = namespace.unlock(fixtures.lockedProfile(), undefined);
      expect(unlockedProfile.publicKey).toBeOfType("rsaKey");
    });

  });

});
