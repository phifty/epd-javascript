
describe("Locker", function () {

  var namespace = epdRoot.Locker;

  describe("#lock", function () {

    var lockedProfile;

    beforeEach(function () {
      if (!lockedProfile) {
        lockedProfile = namespace.lock(fixtures.profile(), fixtures.password());
      }
    });

    it("should encrypt the closed section", function () {
      expect(epdRoot.Sections.byId(lockedProfile, "closed")).toBeOfEncodedType("aesEncryptedData");
    });

    it("should not encrypt the open section", function () {
      expect(epdRoot.Sections.byId(lockedProfile, "open")).toEqual(fixtures.openSection());
    });

    it("should encrypt each contact sections array", function () {
      expect(lockedProfile.contacts[ fixtures.anotherProfile().id ].sections).toBeOfEncodedType("aesEncryptedData");
    });

    it("should encrypt the section keys for the profile's id", function () {
      expect(epdRoot.Contacts.keysForContactId(lockedProfile, lockedProfile.id)).toBeOfEncodedType("rsaAesEncryptedData");
    });

    it("should encrypt the private keys with the given password", function () {
      expect(lockedProfile.privateKey.encrypted).toBeOfEncodedType("aesEncryptedData");
    });

    it("should store the password parameters in the profile", function () {
      expect(lockedProfile.privateKey.salt).toBeOfEncodedType("salt");
      expect(lockedProfile.privateKey.keySize).not.toBeNull();
      expect(lockedProfile.privateKey.iterations).not.toBeNull();
    });

    it("should add a signature to the profile", function () {
      expect(lockedProfile.signature).toBeOfEncodedType("rsaSignature");
    });

  });

  describe("#unlock", function () {

    var unlockedProfile;

    beforeEach(function () {
      if (!unlockedProfile) {
        unlockedProfile = namespace.unlock(fixtures.lockedProfile(), fixtures.password());
      }
    });

    it("should throw an error if no signature is given", function () {
      var profile = epdRoot.Object.clone(fixtures.lockedProfile());
      profile.signature = undefined;
      expect(function () {
        namespace.unlock(profile, fixtures.password());
      }).toThrow("missing profile signature");
    });

    it("should throw an error if the signature can't be verified", function () {
      var profile = epdRoot.Object.clone(fixtures.lockedProfile());
      profile.contacts.test = "value";
      expect(function () {
        namespace.unlock(profile, fixtures.password());
      }).toThrow("invalid profile signature");
    });

    it("should throw an error if the password is invalid", function () {
      expect(function () {
        namespace.unlock(fixtures.lockedProfile(), fixtures.invalidPassword());
      }).toThrow("invalid password");
    });

    it("should decrypt the private keys with the given password", function () {
      expect(unlockedProfile.privateKey).toBeOfType("rsaKey");
    });

    it("should decrypt the section keys for the profile's id", function () {
      expect(epdRoot.Contacts.keyForContactIdAndSectionId(unlockedProfile, fixtures.profile().id, "closed")).toBeOfType("aesKey");
    });

    it("should decrypt each contact sections array", function () {
      expect(unlockedProfile.contacts[ fixtures.anotherProfile().id ].sections).toContain("test");
    });

    it("should not decrypt the open section", function () {
      expect(epdRoot.Sections.byId(unlockedProfile, "open")).toEqual(fixtures.openSection());
    });

    it("should decrypt the closed section", function () {
      expect(epdRoot.Sections.byId(unlockedProfile, "closed")).toEqual({ modules: { } });
    });

    it("should decode each contact public key", function () {
      expect(epdRoot.Contacts.publicKeyForContactId(unlockedProfile, fixtures.anotherProfile().id)).toBeOfType("rsaKey");
    });

    it("should reconstruct each contact keys", function () {
      expect(epdRoot.Contacts.keyForContactIdAndSectionId(unlockedProfile, fixtures.anotherProfile().id, "test")).toBeOfType("aesKey");
    });

    it("should throw an error if the wrong password is used", function () {
      expect(function () {
        namespace.unlock(fixtures.lockedProfile(), fixtures.invalidPassword());
      }).toThrow("invalid password");
    });

  });

});
