
describe("Foreign.Modules", function () {

  var namespace = epdRoot.Foreign.Modules
    , profile
    , anotherProfile
    , profiles = { }
    , hangOutId;

  beforeEach(function () {
    if (!profile) {
      profile = epdRoot.Object.clone(fixtures.profile());
      anotherProfile = epdRoot.Object.clone(fixtures.anotherProfile());

      hangOutId = epdRoot.Sections.Synchronisable.add(profile, "Test hang out");
      epdRoot.Sections.Synchronisable.addMember(profile, anotherProfile.id, hangOutId);
      epdRoot.Modules.add(profile, hangOutId, "build_in:com.anyaku.Forum");

      epdRoot.Contacts.add(anotherProfile, profile.id, profile.publicKey);
      epdRoot.Sections.Synchronisable.add(anotherProfile, "Test hang out", hangOutId);
      epdRoot.Sections.Synchronisable.addMember(anotherProfile, profile.id, hangOutId);
      epdRoot.Modules.add(anotherProfile, hangOutId, "build_in:com.anyaku.Forum");

      epdRoot.Modules.byId(anotherProfile, hangOutId, "build_in:com.anyaku.Forum").content = { test: "value" };

      profiles[ anotherProfile.id ] = anotherProfile;
    }
  });

  describe("#ids", function () {

    it("should return all module ids for the given section", function () {
      var ids = namespace.ids(anotherProfile, "open");
      expect(ids).toEqual([ "build_in:com.anyaku.Basic" ]);
    });

  });

  describe("#contents", function () {

    it("should return an object with the module contents of all contacts of the given profile", function () {
      var contents = namespace.contents(profile, "build_in:com.anyaku.Forum", profiles);
      expect(contents[ anotherProfile.id ][ hangOutId ]).toEqual({ test: "value" });
    });

    it("should return an empty object if the module id could not be found", function () {
      var contents = namespace.contents(profile, "missing", profiles);
      expect(contents).toEqual({ });
    });

  });

  describe("#contentsForSection", function () {

    it("should return an object with the module contents of all contacts of the given profile", function () {
      var contents = namespace.contentsForSection(profile, hangOutId, "build_in:com.anyaku.Forum", profiles)
        , expectedContents = { };
      expectedContents[ anotherProfile.id ] = { test: "value" };
      expect(contents).toEqual(expectedContents);
    });

    it("should return an empty object if the section id could not be found", function () {
      var contents = namespace.contentsForSection(profile, "missing", "build_in:com.anyaku.Forum", profiles);
      expect(contents).toEqual({ });
    });

    it("should return an empty object if the module id could not be found", function () {
      var contents = namespace.contentsForSection(profile, hangOutId, "missing", profiles);
      expect(contents).toEqual({ });
    });

  });

});
