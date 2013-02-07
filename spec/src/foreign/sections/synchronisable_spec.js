
describe("Foreign.Sections.Synchronisable", function () {

  var namespace = epdRoot.Foreign.Sections.Synchronisable
    , profile
    , anotherProfile
    , hangOutId
    , profileGetFunction = function (id) {
        return anotherProfile && anotherProfile.id === id ? anotherProfile : undefined;
      };

  beforeEach(function () {
    profile = epdRoot.Object.clone(fixtures.profile());
    anotherProfile = epdRoot.Object.clone(fixtures.anotherProfile());
    anotherProfile = epdRoot.Contacts.add(anotherProfile, profile.id, profile.publicKey);

    hangOutId = epdRoot.Sections.Synchronisable.add(anotherProfile, "Test hang out");
    epdRoot.Modules.add(anotherProfile, hangOutId, "build_in:com.anyaku.Forum");
    anotherProfile = epdRoot.Sections.Synchronisable.addMember(anotherProfile, profile.id, hangOutId);
  });

  describe("#ids", function () {

    it("should return all hang out ids from unlocked hang outs", function () {
      var ids = namespace.ids(anotherProfile);
      expect(ids).toContain(hangOutId);
    });

  });

  describe("#byId", function () {

    it("should return the hang out for the given id", function () {
      var hangOut = namespace.byId(anotherProfile, hangOutId);
      expect(hangOut.title).toEqual("Test hang out");
    });

  });

  describe("#offered", function () {

    it("should return all hang outs of contacts where the given profile has been added to", function () {
      var hangOuts = namespace.offered(profile, profileGetFunction)
        , expectedHangOuts = { };

      expectedHangOuts[ hangOutId ] = { title: "Test hang out", contactId: anotherProfile.id };

      expect(hangOuts).toEqual(expectedHangOuts);
    });

    it("should not return hang outs that are already imported", function () {
      epdRoot.Sections.Synchronisable.add(profile, "Test hang out", hangOutId);
      var hangOuts = namespace.offered(profile, profileGetFunction);
      expect(hangOuts).toEqual({ });
    });

  });

  describe("#differences", function () {

    var yetAnotherProfile;

    beforeEach(function () {
      if (!yetAnotherProfile) {
        yetAnotherProfile = epdRoot.Generator.generate();
      }
      epdRoot.Contacts.add(profile, yetAnotherProfile.id, yetAnotherProfile.publicKey);

      epdRoot.Sections.Synchronisable.add(profile, "Test hang out", hangOutId);
      epdRoot.Sections.Synchronisable.addMember(profile, anotherProfile.id, hangOutId);
      epdRoot.Modules.add(profile, hangOutId, "build_in:com.anyaku.Forum");
    });

    it("should return an empty hash if the hang outs are synchronized", function () {
      var differences = namespace.differences(profile, hangOutId, profileGetFunction);
      expect(differences).toEqual([ ]);
    });

    it("should return an indication if there is a member currently not participating", function () {
      epdRoot.Sections.Synchronisable.remove(anotherProfile, hangOutId);
      var differences = namespace.differences(profile, hangOutId, profileGetFunction);
      expect(differences).toEqual([
        { type: "not_participating", id: anotherProfile.id, by: [ profile.id ] }
      ]);
    });

    it("should return an indication if there is a member too much in the local hang out", function () {
      epdRoot.Sections.Synchronisable.addMember(profile, yetAnotherProfile.id, hangOutId);
      var differences = namespace.differences(profile, hangOutId, profileGetFunction);
      expect(differences).toEqual([
        { type: "remove_member", id: yetAnotherProfile.id, by: [ anotherProfile.id ] }
      ]);
    });

    it("should return an indication if there is a missing module in the local hang out", function () {
      epdRoot.Modules.remove(profile, hangOutId, "build_in:com.anyaku.Forum");
      var differences = namespace.differences(profile, hangOutId, profileGetFunction);
      expect(differences).toEqual([
        { type: "add_module", id: "build_in:com.anyaku.Forum", by: [ anotherProfile.id ] }
      ]);
    });

    it("should ignore members that have delegated to administration to someone else", function () {
      epdRoot.Modules.remove(anotherProfile, hangOutId, "build_in:com.anyaku.Forum");
      epdRoot.Sections.Synchronisable.delegateTo(anotherProfile, profile.id, hangOutId);
      var differences = namespace.differences(profile, hangOutId, profileGetFunction);
      expect(differences).toEqual({ });
    });

  });

});
