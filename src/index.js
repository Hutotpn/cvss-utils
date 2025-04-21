/**
 * CVSS Base Score Calculator (v3.1 & v4.0)
 * Reference: https://www.first.org/cvss/specification-document
 */

function CVSSv3({
  attackVector,
  attackComplexity,
  privilegesRequired,
  userInteraction,
  scope,
  confidentiality,
  integrity,
  availability,
}) {
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
    throw new Error("All CVSS v3.1 base metrics must be provided.");
  }

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

function CVSSv4({
  attackVector,
  attackComplexity,
  attackRequirements,
  privilegesRequired,
  userInteraction,
  vulnerabilityResponseEffort,
  providerUrgency,
  systemRecovery,
  confidentiality,
  integrity,
  availability,
  safetyConfidentiality = "N",
  safetyIntegrity = "N",
  safetyAvailability = "N",
}) {
  const metrics = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    AT: { N: 1.0, P: 0.85 },
    PR: { N: 0.85, L: 0.62, H: 0.27 },
    UI: { N: 0.85, R: 0.62 },
    VC: { N: 0, L: 0.22, H: 0.56 },
    VI: { N: 0, L: 0.22, H: 0.56 },
    VA: { N: 0, L: 0.22, H: 0.56 },
    SC: { N: 0, L: 0.22, H: 0.56 },
    SI: { N: 0, L: 0.22, H: 0.56 },
    SA: { N: 0, L: 0.22, H: 0.56 },
  };

  // Validate all required metrics are provided
  if (
    !attackVector ||
    !attackComplexity ||
    !attackRequirements ||
    !privilegesRequired ||
    !userInteraction ||
    !vulnerabilityResponseEffort ||
    !providerUrgency ||
    !systemRecovery ||
    !confidentiality ||
    !integrity ||
    !availability
  ) {
    throw new Error("All required CVSS v4.0 metrics must be provided.");
  }

  // Destructure all metrics
  const AV = metrics.AV[attackVector];
  const AC = metrics.AC[attackComplexity];
  const AT = metrics.AT[attackRequirements];
  const PR = metrics.PR[privilegesRequired];
  const UI = metrics.UI[userInteraction];
  const VC = metrics.VC[confidentiality];
  const VI = metrics.VI[integrity];
  const VA = metrics.VA[availability];
  const SC = metrics.SC[safetyConfidentiality];
  const SI = metrics.SI[safetyIntegrity];
  const SA = metrics.SA[safetyAvailability];

  // Calculate exploitability
  const exploitability = 8.22 * AV * AC * AT * PR * UI;

  // Calculate impact sub-scores
  const impactSubScore = 1 - (1 - VC) * (1 - VI) * (1 - VA);
  const safetySubScore = 1 - (1 - SC) * (1 - SI) * (1 - SA);

  // Impact and safety impact calculations
  const impact =
    7.52 * (impactSubScore - 0.029) -
    3.25 * Math.pow(impactSubScore - 0.02, 15);
  const safetyImpact = 6.42 * safetySubScore;

  // Base score calculation
  const baseScore = Math.min(
    1.08 * (impact + exploitability + safetyImpact),
    10
  );

  return Math.round(baseScore * 10) / 10;
}

module.exports = {
  CVSSv3,
  CVSSv4,
};
