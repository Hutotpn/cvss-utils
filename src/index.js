// index.js

/**
 * CVSS v3.1 Base Score Calculator
 * Reference: https://www.first.org/cvss/specification-document
 */

function calculateCVSS({
  attackVector,
  attackComplexity,
  privilegesRequired,
  userInteraction,
  scope,
  confidentiality,
  integrity,
  availability,
}) {
  if (
    !attackVector ||
    !attackComplexity ||
    !privilegesRequired ||
    !userInteraction ||
    !scope ||
    !confidentiality ||
    !integrity ||
    !availability
  ) {
    throw new Error("All CVSS base metrics must be provided.");
  }

  const metrics = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    PR: {
      U: { N: 0.85, L: 0.62, H: 0.27 },
      C: { N: 0.85, L: 0.68, H: 0.5 },
    },
    UI: { N: 0.85, R: 0.62 },
    C: { N: 0, L: 0.22, H: 0.56 },
    I: { N: 0, L: 0.22, H: 0.56 },
    A: { N: 0, L: 0.22, H: 0.56 },
  };

  const AV = metrics.AV[attackVector];
  const AC = metrics.AC[attackComplexity];
  const PR = metrics.PR[scope][privilegesRequired];
  const UI = metrics.UI[userInteraction];
  const C = metrics.C[confidentiality];
  const I = metrics.I[integrity];
  const A = metrics.A[availability];

  const impactSubScore = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact =
    scope === "U"
      ? 6.42 * impactSubScore
      : 7.52 * (impactSubScore - 0.029) -
        3.25 * Math.pow(impactSubScore - 0.02, 15);

  const exploitability = 8.22 * AV * AC * PR * UI;
  const baseScore =
    scope === "U"
      ? Math.min(impact + exploitability, 10)
      : Math.min(1.08 * (impact + exploitability), 10);

  return Math.round(baseScore * 10) / 10;
}

module.exports = { calculateCVSS };
