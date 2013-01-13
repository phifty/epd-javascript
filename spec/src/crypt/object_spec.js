
xdescribe("Crypt.Object", function () {

  var namespace = epdRoot.Crypt.Object;

  describe("#generateId", function () {

    it("should return a hex id", function () {
      var id = namespace.generateId();
      expect(id).toMatch(hexRegexp);
      expect(id.length).toEqual(32);
    });

  });

});
