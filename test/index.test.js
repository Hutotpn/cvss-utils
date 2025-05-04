const { CVSSv3, CVSSv4 } = require("../src/index");

describe("CVSS v3.1 Calculator", () => {
  it("calculates correct base score for a typical case", () => {
    const score = CVSSv3({
      attackVector: "N", // Network
      attackComplexity: "L", // Low
      privilegesRequired: "N", // None
      userInteraction: "N", // None
      scope: "U", // Unchanged
      confidentiality: "H", // High
      integrity: "H", // High
      availability: "H", // High
    });

    expect(score).toBeCloseTo(9.8, 1); // Expected value based on known CVSSv3 calculation
  });

  it("throws an error when metrics are missing", () => {
    expect(() =>
      CVSSv3({
        attackVector: "N",
        attackComplexity: "L",
        privilegesRequired: "N",
        // Missing userInteraction and others
      })
    ).toThrow("All CVSS v3.1 base metrics must be provided and valid.");
  });
});

describe("CVSS v4.0 Calculator", () => {
  it("calculates correct base score for a typical v4 case", () => {
    const score = CVSSv4({
      attackVector: "N", // Network
      attackComplexity: "L", // Low
      attackRequirements: "N", // None
      privilegesRequired: "N", // None
      userInteraction: "N", // None
      scope: "U",
      confidentiality: "H", // High
      integrity: "H", // High
      availability: "H", // High
      safetyConfidentiality: "N",
      safetyIntegrity: "N",
      safetyAvailability: "N",
    });

    expect(score).toBeCloseTo(9.8, 1);
  });

  it("throws an error when metrics are missing", () => {
    expect(() =>
      CVSSv4({
        attackVector: "N",
        attackComplexity: "L",
        attackRequirements: "N",
        privilegesRequired: "N",
        userInteraction: "N",
        // Missing scope and impact/safety metrics
      })
    ).toThrow(
      "All required CVSS v4.0 base metrics must be provided and valid."
    );
  });
});
