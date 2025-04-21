const { calculateCVSS } = require("../src/index.js");

describe("CVSS v3.1", () => {
  const cases = [
    {
      name: "High severity",
      input: { AV: "N", AC: "L", PR: "N", UI: "N", C: "H", I: "H", A: "H" },
      expected: 9.8,
    },
    {
      name: "Medium severity",
      input: { AV: "L", AC: "H", PR: "L", UI: "R", C: "L", I: "L", A: "N" },
      expected: 5.2,
    },
    {
      name: "No impact",
      input: { AV: "N", AC: "L", PR: "N", UI: "N", C: "N", I: "N", A: "N" },
      expected: 0.0,
    },
  ];

  cases.forEach(({ name, input, expected }) => {
    test(name, () => {
      const score = calculateCVSS("v3", input);
      expect(score).toBeCloseTo(expected, 1);
    });
  });

  test("Invalid metric throws error", () => {
    expect(() =>
      calculateCVSS("v3", {
        AV: "Z",
        AC: "L",
        PR: "N",
        UI: "N",
        C: "H",
        I: "H",
        A: "H",
      })
    ).toThrow("Invalid Exploitability Metric value.");
  });
});

describe("CVSS v4.0", () => {
  const cases = [
    {
      name: "High severity",
      input: {
        AV: "N",
        AC: "L",
        PR: "N",
        UI: "N",
        AT: "N",
        VC: "H",
        VI: "H",
        VA: "H",
        SC: "H",
        SI: "H",
        SA: "H",
      },
      expected: 10.0,
    },
    {
      name: "Low severity",
      input: {
        AV: "L",
        AC: "H",
        PR: "L",
        UI: "R",
        AT: "L",
        VC: "L",
        VI: "N",
        VA: "N",
        SC: "N",
        SI: "N",
        SA: "N",
      },
      expected: 1.8,
    },
    {
      name: "No impact",
      input: {
        AV: "N",
        AC: "L",
        PR: "N",
        UI: "N",
        AT: "N",
        VC: "N",
        VI: "N",
        VA: "N",
        SC: "N",
        SI: "N",
        SA: "N",
      },
      expected: 0.0,
    },
  ];

  cases.forEach(({ name, input, expected }) => {
    test(name, () => {
      const score = calculateCVSS("v4", input);
      expect(score).toBeCloseTo(expected, 1);
    });
  });
});
