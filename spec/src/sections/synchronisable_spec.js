
describe("Sections.Synchronisable", function () {

  var namespace = epdRoot.Sections.Synchronisable
    , profile
    , testId;

  beforeEach(function () {
    if (!profile) {
      profile = epdRoot.Object.clone(fixtures.profile());
      testId = namespace.add(profile, "Test section", "test_section");
    }
  });

  describe("#ids", function () {

    it("should return an array with all synchronisable section ids", function () {
      var hangOutIds = namespace.ids(profile);
      expect(hangOutIds).toEqual([ testId ]);
    });

  });

  describe("#isSynchronisable", function () {

    it("should return true if given section id belongs to a synchronisable section", function () {
      var result = namespace.isSynchronisable(profile, testId);
      expect(result).toBeTruthy();
    });

  });

  describe("#add", function () {

    it("should add a synchronisable section with the given title to the profile", function () {
      var id = namespace.add(profile, "New test section");
      expect(namespace.ids(profile)).toContain(id);
    });

  });

  describe("#memberIds", function () {

    beforeEach(function () {
      namespace.addMember(profile, fixtures.anotherProfile().id, testId);
    });

    it("should return an array with all member ids that are allowed for the given synchronisable section id", function () {
      var memberIds = namespace.memberIds(profile, testId);
      expect(memberIds).toEqual([ fixtures.anotherProfile().id ]);
    });

  });

  describe("#addMember", function () {

    it("should should allow the given contact to access the given synchronisable section", function () {
      namespace.addMember(profile, fixtures.anotherProfile().id, testId);
      expect(namespace.isMember(profile, fixtures.anotherProfile().id, testId)).toBeTruthy();
      expect(namespace.byId(profile, testId).members).toContain(fixtures.anotherProfile().id);
    });

  });

  describe("#removeMember", function () {

    beforeEach(function () {
      namespace.addMember(profile, fixtures.anotherProfile().id, testId);
    });

    it("should remove the given profile allowance for the given synchronisable section id", function () {
      profile = namespace.removeMember(profile, fixtures.anotherProfile().id, testId);
      expect(namespace.isMember(profile, fixtures.anotherProfile().id, testId)).toBeFalsy();
      expect(namespace.byId(profile, testId).members).not.toContain(fixtures.anotherProfile().id);
    });

  });

  describe("#addMembers", function () {

    it("should ensure that the given list of contact ids is added", function () {
      profile = namespace.addMembers(profile, [ fixtures.anotherProfile().id ], testId);
      expect(namespace.isMember(profile, fixtures.anotherProfile().id, testId)).toBeTruthy();
    });

  });

  describe("#removeMembers", function () {

    beforeEach(function () {
      profile = namespace.addMember(profile, fixtures.anotherProfile().id, testId);
    });

    it("should ensure that the given list of contact ids is removed", function () {
      profile = namespace.removeMembers(profile, [ fixtures.anotherProfile().id ], testId);
      expect(namespace.isMember(profile, fixtures.anotherProfile().id, testId)).toBeFalsy();
    });

  });

  describe("#ensureOnlyMembers", function () {

    it("should add all contact ids from the given list that are not allowed yet", function () {
      profile = namespace.ensureOnlyMembers(profile, [ fixtures.anotherProfile().id ], testId);
      expect(namespace.isMember(profile, fixtures.anotherProfile().id, testId)).toBeTruthy();
    });

    it("should remove all contact ids that are not on the given list", function () {
      profile = namespace.ensureOnlyMembers(profile, [ fixtures.anotherProfile().id ], testId);
      profile = namespace.ensureOnlyMembers(profile, [ ], testId);
      expect(namespace.isMember(profile, fixtures.anotherProfile().id, testId)).toBeFalsy();
    });

  });

  describe("#delegateTo", function () {

    beforeEach(function () {
      profile = namespace.addMember(profile, fixtures.anotherProfile().id, testId);
      profile = namespace.delegateTo(profile, fixtures.anotherProfile().id, testId);
    });

    it("should set the delegation", function () {
      expect(namespace.isDelegated(profile, testId)).toBeTruthy();
    });

    it("should set the delegation to the right member id", function () {
      expect(namespace.delegatedTo(profile, testId)).toEqual(fixtures.anotherProfile().id);
    });

  });

  describe("#removeDelegation", function () {

    beforeEach(function () {
      profile = namespace.addMember(profile, fixtures.anotherProfile().id, testId);
      profile = namespace.delegateTo(profile, fixtures.anotherProfile().id, testId);
      profile = namespace.removeDelegation(profile, testId);
    });

    it("should remove the delegation", function () {
      expect(namespace.isDelegated(profile, testId)).toBeFalsy();
    });

    it("should set the delegation to undefined", function () {
      expect(namespace.delegatedTo(profile, testId)).toBeUndefined();
    });

  });

  describe("#followDelegation", function () {

    var anotherProfile
      , yetAnotherProfile
      , profileGetFunction = function (id) {
          if (anotherProfile && anotherProfile.id === id) { return anotherProfile; }
          if (yetAnotherProfile && yetAnotherProfile.id === id) { return yetAnotherProfile; }
          return undefined;
        };

    beforeEach(function () {
      if (!anotherProfile) {
        anotherProfile = epdRoot.Object.clone(fixtures.anotherProfile());
        yetAnotherProfile = epdRoot.Generator.generate();

        namespace.add(anotherProfile, "New test hang out", testId);

        epdRoot.Contacts.add(profile, yetAnotherProfile.id, yetAnotherProfile.publicKey);
        epdRoot.Contacts.add(anotherProfile, profile.id, profile.publicKey);
        epdRoot.Contacts.add(anotherProfile, yetAnotherProfile.id, yetAnotherProfile.publicKey);
      }

      namespace.addMember(profile, anotherProfile.id, testId);
      namespace.addMember(anotherProfile, profile.id, testId);

      namespace.delegateTo(profile, anotherProfile.id, testId);
    });

    it("should return an empty hash if nothing has changed", function () {
      var changes = namespace.followDelegation(profile, testId, profileGetFunction);
      expect(changes).toEqual({ });
    });

    it("should return the new member ids if the delegation target has added a member", function () {
      namespace.addMember(anotherProfile, yetAnotherProfile.id, testId);

      var changes = namespace.followDelegation(profile, testId, profileGetFunction);

      expect(changes.addMembers).toEqual([ yetAnotherProfile.id ]);
    });

    it("should return the new module ids if the delegation target has added a module", function () {
      epdRoot.Modules.add(anotherProfile, testId, "build_in:com.anyaku.Forum");

      var changes = namespace.followDelegation(profile, testId, profileGetFunction);

      expect(changes.addModules).toEqual([ "build_in:com.anyaku.Forum" ]);
    });

    it("should set a new delegation if the delegation target is delegated itself", function () {
      testId = namespace.add(yetAnotherProfile, "New test hang out", testId);
      namespace.addMember(profile, yetAnotherProfile.id, testId);
      namespace.addMember(anotherProfile, yetAnotherProfile.id, testId);
      namespace.delegateTo(anotherProfile, yetAnotherProfile.id, testId);

      namespace.followDelegation(profile, testId, profileGetFunction);

      expect(namespace.delegatedTo(profile, testId)).toEqual(yetAnotherProfile.id);
    });

    it("should keep the delegation if the delegation target can't be fetched", function () {
      namespace.delegateTo(anotherProfile, yetAnotherProfile.id, testId);

      var save = yetAnotherProfile;
      yetAnotherProfile = undefined;
      namespace.followDelegation(profile, testId, profileGetFunction);
      yetAnotherProfile = save;

      expect(namespace.delegatedTo(profile, testId)).toEqual(anotherProfile.id);
    });

    it("should remove the delegation if the path goes back to the own profile", function () {
      namespace.delegateTo(anotherProfile, profile.id, testId);

      namespace.followDelegation(profile, testId, profileGetFunction);

      expect(namespace.isDelegated(profile, testId)).toBeFalsy();
    });

    it("should do nothing if no delegation is declared for this hang out", function () {
      namespace.addMember(anotherProfile, yetAnotherProfile.id, testId);
      namespace.removeDelegation(profile, testId);

      var changes = namespace.followDelegation(profile, testId, profileGetFunction);

      expect(changes).toEqual({ });
    });

    it("should remove the delegation if the foreign profile is missing", function () {
      namespace.followDelegation(profile, testId, function () { return undefined; });

      expect(namespace.isDelegated(profile, testId)).toBeFalsy();
    });

    it("should remove the delegation if the profile where the delegation goes to removed the hang out", function () {
      namespace.remove(anotherProfile, testId);

      namespace.followDelegation(profile, testId, profileGetFunction);

      expect(namespace.isDelegated(profile, testId)).toBeFalsy();
    });

  });

});
