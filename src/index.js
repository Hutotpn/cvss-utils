/**
 * CVSS Base Score Calculator (v3.1 & v4.0)
 * Reference: https://www.first.org/cvss/specification-document
 */

// CVSS v3.1 Base Score
function CVSSv3({
  attackVector, // AV: N, A, L, P
  attackComplexity, // AC: L, H
  privilegesRequired, // PR: N, L, H
  userInteraction, // UI: N, R
  scope, // S: U, C
  confidentiality, // C: N, L, H
  integrity, // I: N, L, H
  availability, // A: N, L, H
}) {
  const W = {
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
    !W.AV[attackVector] ||
    !W.AC[attackComplexity] ||
    !W.PR[scope]?.[privilegesRequired] ||
    !W.UI[userInteraction] ||
    !Object.prototype.hasOwnProperty.call(W.C, confidentiality) ||
    !Object.prototype.hasOwnProperty.call(W.I, integrity) ||
    !Object.prototype.hasOwnProperty.call(W.A, availability) ||
    !["U", "C"].includes(scope)
  ) {
    throw new Error("All CVSS v3.1 base metrics must be provided and valid.");
  }

  const AVw = W.AV[attackVector];
  const ACw = W.AC[attackComplexity];
  const PRw = W.PR[scope][privilegesRequired];
  const UIw = W.UI[userInteraction];
  const Cw = W.C[confidentiality];
  const Iw = W.I[integrity];
  const Aw = W.A[availability];

  const impactSub = 1 - (1 - Cw) * (1 - Iw) * (1 - Aw);
  const impact =
    scope === "U"
      ? 6.42 * impactSub
      : 7.52 * (impactSub - 0.029) - 3.25 * Math.pow(impactSub - 0.02, 15);

  const exploit = 8.22 * AVw * ACw * PRw * UIw;

  let base = 0;
  if (impact > 0) {
    base =
      scope === "U"
        ? Math.min(impact + exploit, 10)
        : Math.min(1.08 * (impact + exploit), 10);
  }

  return Math.round(base * 10) / 10;
}

// CVSS v4.0 Base Score
function CVSSv4({
  attackVector, // AV: N, A, L, P
  attackComplexity, // AC: L, H
  attackRequirements, // AR: N, P
  privilegesRequired, // PR: N, L, H
  userInteraction, // UI: N, R
  scope = "U", // S: U, C
  confidentiality, // VC: N, L, H
  integrity, // VI: N, L, H
  availability, // VA: N, L, H
  safetyConfidentiality, // SC: N, L, H
  safetyIntegrity, // SI: N, L, H
  safetyAvailability, // SA: N, L, H
}) {
  const W = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    AR: { N: 1.0, P: 0.85 },
    PR: { N: 0.85, L: 0.62, H: 0.27 },
    UI: { N: 0.85, R: 0.62 },
    VC: { N: 0, L: 0.22, H: 0.56 },
    VI: { N: 0, L: 0.22, H: 0.56 },
    VA: { N: 0, L: 0.22, H: 0.56 },
    SC: { N: 0, L: 0.22, H: 0.56 },
    SI: { N: 0, L: 0.22, H: 0.56 },
    SA: { N: 0, L: 0.22, H: 0.56 },
  };

  const fields = [
    attackVector,
    attackComplexity,
    attackRequirements,
    privilegesRequired,
    userInteraction,
    confidentiality,
    integrity,
    availability,
    safetyConfidentiality,
    safetyIntegrity,
    safetyAvailability,
  ];

  // Validate using hasOwnProperty for zero values and scope
  if (
    fields.some((f) => f == null) ||
    !W.AV[attackVector] ||
    !W.AC[attackComplexity] ||
    !W.AR[attackRequirements] ||
    !W.PR[privilegesRequired] ||
    !W.UI[userInteraction] ||
    !["U", "C"].includes(scope) ||
    !Object.prototype.hasOwnProperty.call(W.VC, confidentiality) ||
    !Object.prototype.hasOwnProperty.call(W.VI, integrity) ||
    !Object.prototype.hasOwnProperty.call(W.VA, availability) ||
    !Object.prototype.hasOwnProperty.call(W.SC, safetyConfidentiality) ||
    !Object.prototype.hasOwnProperty.call(W.SI, safetyIntegrity) ||
    !Object.prototype.hasOwnProperty.call(W.SA, safetyAvailability)
  ) {
    throw new Error(
      "All required CVSS v4.0 base metrics must be provided and valid."
    );
  }

  const AVw = W.AV[attackVector];
  const ACw = W.AC[attackComplexity];
  const ARw = W.AR[attackRequirements];
  const PRw = W.PR[privilegesRequired];
  const UIw = W.UI[userInteraction];
  const VCw = W.VC[confidentiality];
  const VIw = W.VI[integrity];
  const VAw = W.VA[availability];
  const SCw = W.SC[safetyConfidentiality];
  const SIw = W.SI[safetyIntegrity];
  const SAw = W.SA[safetyAvailability];

  const exploit = 8.22 * AVw * ACw * ARw * PRw * UIw;
  const impactSub =
    1 - (1 - VCw) * (1 - VIw) * (1 - VAw) * (1 - SCw) * (1 - SIw) * (1 - SAw);
  const impact =
    scope === "U"
      ? 6.42 * impactSub
      : 7.52 * (impactSub - 0.029) - 3.25 * Math.pow(impactSub - 0.02, 15);

  let base = 0;
  if (impact > 0) {
    base =
      scope === "U"
        ? Math.min(impact + exploit, 10)
        : Math.min(1.08 * (impact + exploit), 10);
  }

  return Math.round(base * 10) / 10;
}

module.exports = {
  CVSSv3,
  CVSSv4,
};
