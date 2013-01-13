
var hexRegexp = /^[0-9a-f]+$/;

beforeEach(function () {
  this.addMatchers({

    toBeOfType: function (expectedType) {
      var actual = this.actual
        , isNot = this.isNot;

      this.message = function () {
        return "Excepted " + JSON.stringify(actual) + (isNot ? " not" : "") + " to be of type " + expectedType + "!"
      };

      return actual && actual.type === expectedType;
    },

    toBeOfEncodedType: function (expectedType) {
      var actual = this.actual
        , isNot = this.isNot;

      this.message = function () {
        return "Excepted " + JSON.stringify(actual) + (isNot ? " not" : "") + " to be of encoded type " + expectedType + "!"
      };

      return typeof(actual) === "string" &&
             epdRoot.Crypt.Coder.typeForLetter(actual[0]) === expectedType;
    }

  });
});
