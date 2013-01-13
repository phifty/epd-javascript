
describe("Generator", function () {

  var namespace = epdRoot.Generator;

  describe("#generate", function () {

    var profile;

    beforeEach(function () {
      if (!profile) {
        profile = namespace.generate();
      }
    });

    it("should return a profile with an id", function () {
      expect(profile.id).toMatch(hexRegexp);
    });

    it("should return a profile with a public key", function () {
      expect(profile.publicKey).toBeOfType("rsaKey");
    });

    it("should return a profile with a private key", function () {
      expect(profile.privateKey).toBeOfType("rsaKey");
    });

    it("should return a profile with version one", function () {
      expect(profile.version).toEqual(1);
    });

    it("should return a profile with a public section", function () {
      expect(epdRoot.Sections.exists(profile, "open")).toBeTruthy();
    });

    it("should return a profile with a private section", function () {
      expect(epdRoot.Sections.exists(profile, "closed")).toBeTruthy();
    });

    it("should return a profile with a contact of the profile itself that holds a key for the closed area", function () {
      expect(profile.contacts[profile.id].keys.closed).toBeOfType("aesKey");
    });

    it("should return a profile with a contact of the profile itself that holds no key for the open area", function () {
      expect(profile.contacts[profile.id].keys.open).toBeUndefined();
    });

    it("should return a profile with an open section that has a basic information module with empty content", function () {
      var module = epdRoot.Modules.byId(profile, "open", "build_in:com.anyaku.Basic");
      expect(module).toEqual({ content: { } });
    });

    it("should return a profile with a closed section that has no modules", function () {
      expect(epdRoot.Sections.byId(profile, "closed")).toEqual({ modules: { } });
    });

  });

});
