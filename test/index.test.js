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
    ).toThrow("All CVSS v3.1 base metrics must be provided.");
  });
});

describe("CVSS v4.0 Calculator", () => {
  it("calculates correct base score for a basic set of metrics", () => {
    const score = CVSSv4({
      attackVector: "N", // Network
      attackComplexity: "L", // Low
      attackRequirements: "N", // None
      privilegesRequired: "N", // None
      userInteraction: "N", // None
      vulnerabilityResponseEffort: "L", // Low
      providerUrgency: "H", // High
      systemRecovery: "H", // High
      confidentiality: "H", // High
      integrity: "H", // High
      availability: "H", // High
    });

    // Placeholder: Replace with correct expected score once logic is complete
    expect(score).toBeGreaterThan(0); // Placeholder check for now
  });

  it("throws an error if any metric is missing", () => {
    // Test case for missing multiple metrics
    expect(() =>
      CVSSv4({
        attackVector: "N",
        attackComplexity: "L",
        // Missing all other required fields
      })
    ).toThrow("All required CVSS v4.0 metrics must be provided.");
  });

  it("throws an error when confidentiality, integrity, or availability are not provided", () => {
    // Test case for missing confidentiality, integrity, or availability
    expect(() =>
      CVSSv4({
        attackVector: "N",
        attackComplexity: "L",
        attackRequirements: "N",
        privilegesRequired: "N",
        userInteraction: "N",
        vulnerabilityResponseEffort: "L",
        providerUrgency: "H",
        systemRecovery: "H",
        // Missing confidentiality, integrity, or availability
      })
    ).toThrow("All required CVSS v4.0 metrics must be provided.");
  });
});
