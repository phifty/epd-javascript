
describe("Sections", function () {

  var namespace = epdRoot.Sections
    , profile;

  beforeEach(function () {
    if (!profile) {
      profile = epdRoot.Object.clone(fixtures.profile());
    }
  });

  describe("#ids", function () {

    it("should return an array with all section ids", function () {
      var sectionIds = namespace.ids(profile);
      expect(sectionIds.length).toBeGreaterThan(0);
    });

  });

  describe("#exists", function () {

    it("should return true if the given section is existing", function () {
      var result = namespace.exists(profile, "open");
      expect(result).toBeTruthy();
    });

    it("should return false if the given section is missing", function () {
      var result = namespace.exists(profile, "missing");
      expect(result).toBeFalsy();
    });

  });

  describe("#byId", function () {

    it("should return fitting section for the given id", function () {
      var ids = namespace.ids(profile)
        , section = namespace.byId(profile, ids[0]);
      expect(section).toEqual({ title: "Test", modules: { } });
    });

  });

  describe("#add", function () {

    it("should add a section with the given title to the profile", function () {
      var sectionId = namespace.add(profile, "New test section");
      expect(namespace.ids(profile)).toContain(sectionId);
    });

    it("should generate a section id only if none is given", function () {
      namespace.add(profile, "New test section", "new_test");
      expect(namespace.ids(profile)).toContain("new_test");
    });

    it("should throw an error is the given id already exists", function () {
      expect(function () {
        namespace.add(profile, "New test section", "open");
      }).toThrow("the section open is already existing");
    });

    it("should guarantee that the profile owner has access to the added section", function () {
      var sectionId = namespace.add(profile, "New test section");
      expect(namespace.isMember(profile, profile.id, sectionId)).toBeTruthy();
    });

  });

  describe("#remove", function () {

    var sectionId;

    beforeEach(function () {
      sectionId = namespace.add(profile, "New test section");
    });

    it("should remove the section with the given id from the profile", function () {
      profile = namespace.remove(profile, sectionId);
      expect(namespace.ids(profile)).not.toContain(sectionId);
    });

    it("should remove the allowed state for all profile ids", function () {
      profile = namespace.remove(profile, sectionId);
      expect(namespace.isMember(profile, profile.id, sectionId)).toBeFalsy();
    });

  });

  describe("#memberIds", function () {

    it("should return an array with all contact ids that are allowed for the given hang out id", function () {
      var memberIds = namespace.memberIds(profile, "test");
      expect(memberIds).toEqual([ fixtures.anotherProfile().id ]);
    });

  });

  describe("#addMember", function () {

    var sectionId;

    beforeEach(function () {
      sectionId = namespace.add(profile, "New test section");
    });

    it("should grant the given profile access to the given section", function () {
      profile = namespace.addMember(profile, fixtures.anotherProfile().id, sectionId);
      expect(namespace.isMember(profile, fixtures.anotherProfile().id, sectionId)).toBeTruthy();
    });

    it("should shadow the section association in the contact sections", function () {
      profile = namespace.addMember(profile, fixtures.anotherProfile().id, sectionId);
      expect(profile.contacts[ fixtures.anotherProfile().id ].sections).toContain(sectionId);
    });

    it("should use the same key to grant access for a second profile id", function () {
      var profileOne = fixtures.anotherProfile()
        , profileTwo = epdRoot.Generator.generate();

      epdRoot.Contacts.add(profile, profileTwo.id, profileTwo.publicKey);

      profile = namespace.addMember(profile, profileOne.id, sectionId);
      profile = namespace.addMember(profile, profileTwo.id, sectionId);

      expect(epdRoot.Contacts.keyForContactIdAndSectionId(profile, profileOne.id, sectionId)).toEqual(
        epdRoot.Contacts.keyForContactIdAndSectionId(profile, profileTwo.id, sectionId));
    });

  });

  describe("#removeMember", function () {

    it("should remove the given profile allowance for the given section id", function () {
      profile = namespace.removeMember(profile, fixtures.anotherProfile().id, "test");
      expect(namespace.isMember(profile, fixtures.anotherProfile().id, "test")).toBeFalsy();
    });

    it("should remove the contact sections shadow entry", function () {
      profile = namespace.removeMember(profile, fixtures.anotherProfile().id, "test");
      expect(profile.contacts[ fixtures.anotherProfile().id ].sections).not.toContain("test");
    });

  });

  describe("#addMembers", function () {

    var sectionId;

    beforeEach(function () {
      sectionId = namespace.add(profile, "New test section");
    });

    it("should add the given list of contact ids as members", function () {
      profile = namespace.addMembers(profile, [ fixtures.anotherProfile().id ], sectionId);
      expect(namespace.isMember(profile, fixtures.anotherProfile().id, sectionId)).toBeTruthy();
    });

  });

  describe("#removeAllMembers", function () {

    it("should remove all profile allowance for the given section id", function () {
      profile = namespace.removeAllMembers(profile, "test");
      expect(namespace.isMember(profile, fixtures.anotherProfile().id, "test")).toBeFalsy();
    });

  });

  describe("#removeMembers", function () {

    it("should ensure that the given list of contact ids is removed", function () {
      profile = namespace.removeMembers(profile, [ fixtures.anotherProfile().id ], "test");
      expect(namespace.isMember(profile, fixtures.anotherProfile().id, "test")).toBeFalsy();
    });

  });

  describe("#ensureOnlyMembers", function () {

    var sectionId;

    beforeEach(function () {
      sectionId = namespace.add(profile, "New test section");
    });

    it("should add all member ids from the given list that are not allowed yet", function () {
      profile = namespace.ensureOnlyMembers(profile, [ fixtures.anotherProfile().id ], sectionId);
      expect(namespace.isMember(profile, fixtures.anotherProfile().id, sectionId)).toBeTruthy();
    });

    it("should remove all member ids that are not on the given list", function () {
      profile = namespace.ensureOnlyMembers(profile, [ fixtures.anotherProfile().id ], sectionId);
      profile = namespace.ensureOnlyMembers(profile, [ ], sectionId);
      expect(namespace.isMember(profile, fixtures.anotherProfile().id, sectionId)).toBeFalsy();
    });

  });

});
