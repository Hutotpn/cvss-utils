const { calculateCVSS } = require("../src/index.js");

describe("CVSS Calculator", () => {
  it("should return 9.8 for a high severity config", () => {
    const score = calculateCVSS({
      attackVector: "N",
      attackComplexity: "L",
      privilegesRequired: "N",
      userInteraction: "N",
      scope: "U",
      confidentiality: "H",
      integrity: "H",
      availability: "H",
    });
    expect(score).toBe(9.8);
  });

  it("should throw an error if a required field is missing", () => {
    expect(() => {
      calculateCVSS({
        attackVector: "N",
        attackComplexity: "L",
        // Missing privilegesRequired
        userInteraction: "N",
        scope: "U",
        confidentiality: "H",
        integrity: "H",
        availability: "H",
      });
    }).toThrow();
  });
});
