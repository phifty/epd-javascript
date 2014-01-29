
describe("Contacts", function () {

  var namespace = epdRoot.Contacts
    , profile
    , otherProfile;

  beforeEach(function () {
    profile = epdRoot.Object.clone(fixtures.profile());

    if (!otherProfile) {
      otherProfile = epdRoot.Generator.generate();
    }
  });

  describe("#ids", function () {

    it("should return an array including all contact ids", function () {
      var ids = namespace.ids(profile);
      expect(ids).toEqual([ fixtures.anotherProfile().id ]);
    });

  });

  describe("#idsBySectionId", function () {

    it("should return the full profiles of all contacts assigned to the given section", function () {
      var ids = namespace.idsBySectionId(profile, "test");
      expect(ids).toEqual([ fixtures.anotherProfile().id ]);
    });

  });

  describe("#keysForContactId", function () {

    it("should return the keys for the given contact", function () {
      var keys = namespace.keysForContactId(profile, fixtures.anotherProfile().id);
      expect(keys.test).toBeOfType("aesKey");
    });

  });

  describe("#keyForContactIdAndSectionId", function () {

    it("should return the key for the given contact and the given section id", function () {
      var key = namespace.keyForContactIdAndSectionId(profile, fixtures.anotherProfile().id, "test");
      expect(key).toBeOfType("aesKey");
    });

  });

  describe("#add", function () {

    it("should add the given profile to the contacts", function () {
      profile = namespace.add(profile, otherProfile.id);
      expect(namespace.ids(profile)).toContain(otherProfile.id);
    });

    it("should do nothing if the contact has been added before", function () {
      profile = namespace.add(profile, fixtures.anotherProfile().id);
      expect(namespace.ids(profile)).toEqual([ fixtures.anotherProfile().id ]);
    });

    it("should not add a sections key if the contact is the profile owner", function () {
      profile = namespace.add(profile, profile.id);
      expect(profile.contacts[ profile.id ].sections).toBeUndefined();
    });

  });

  describe("#remove", function () {

    it("should remove the given profile to the contacts", function () {
      profile = namespace.remove(profile, fixtures.anotherProfile().id);
      expect(namespace.ids(profile)).not.toContain(fixtures.anotherProfile().id);
    });

  });

  describe("#ensureAdded", function () {

    it("should add the given contact if missing", function () {
      profile = namespace.ensureAdded(profile, [ otherProfile.id ]);
      expect(namespace.ids(profile)).toContain(otherProfile.id);
    });

  });

  describe("#ensureRemoved", function () {

    it("should remove the given contact if existing", function () {
      profile = namespace.ensureRemoved(profile, [ fixtures.anotherProfile().id ]);
      expect(namespace.ids(profile)).not.toContain(fixtures.anotherProfile().id);
    });

  });

});
