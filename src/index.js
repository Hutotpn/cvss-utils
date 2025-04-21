function calculateCVSS(version, metrics) {
  if (version === "v3") {
    return calculateCVSSv3(metrics);
  } else if (version === "v4") {
    return calculateCVSSv4(metrics);
  } else {
    throw new Error("Invalid CVSS version. Please use 'v3' or 'v4'.");
  }
}

// * CVSS v3.1 calculation
function calculateCVSSv3({ AV, AC, PR, UI, C, I, A }) {
  const AV_WEIGHTS = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const AC_WEIGHTS = { L: 0.77, H: 0.44 };
  const PR_WEIGHTS = {
    U: { N: 0.85, L: 0.62, H: 0.27 },
    C: { N: 0.85, L: 0.68, H: 0.5 },
  };
  const UI_WEIGHTS = { N: 0.85, R: 0.62 };
  const IMPACT_WEIGHTS = { H: 0.56, L: 0.22, N: 0.0 };

  // Validating Exploitability Metrics
  if (
    !Object.prototype.hasOwnProperty.call(AV_WEIGHTS, AV) ||
    !Object.prototype.hasOwnProperty.call(AC_WEIGHTS, AC) ||
    !Object.prototype.hasOwnProperty.call(PR_WEIGHTS["U"], PR) ||
    !Object.prototype.hasOwnProperty.call(UI_WEIGHTS, UI)
  ) {
    throw new Error("Invalid Exploitability Metric value.");
  }

  // Validating Impact Metrics
  if (
    !Object.prototype.hasOwnProperty.call(IMPACT_WEIGHTS, C) ||
    !Object.prototype.hasOwnProperty.call(IMPACT_WEIGHTS, I) ||
    !Object.prototype.hasOwnProperty.call(IMPACT_WEIGHTS, A)
  ) {
    throw new Error("Invalid Impact Metric value.");
  }

  const impactSubscore =
    1 -
    (1 - IMPACT_WEIGHTS[C]) * (1 - IMPACT_WEIGHTS[I]) * (1 - IMPACT_WEIGHTS[A]);
  const impact = 6.42 * impactSubscore;

  const exploitability =
    8.22 *
    AV_WEIGHTS[AV] *
    AC_WEIGHTS[AC] *
    PR_WEIGHTS["U"][PR] *
    UI_WEIGHTS[UI];

  let baseScore = 0;
  if (impact <= 0) {
    baseScore = 0;
  } else {
    baseScore = Math.min(impact + exploitability, 10);
  }

  return Math.round(baseScore * 10) / 10;
}

// * CVSS v4.0 calculation
function calculateCVSSv4({ AV, AC, PR, UI, AT, VC, VI, VA, SC, SI, SA }) {
  const AV_WEIGHTS = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const AC_WEIGHTS = { L: 0.77, H: 0.44 };
  const PR_WEIGHTS = {
    N: { N: 0.85, L: 0.62, H: 0.27 },
    L: { N: 0.77, L: 0.5, H: 0.2 },
  };
  const UI_WEIGHTS = { N: 0.85, R: 0.62 };
  const AT_WEIGHTS = { N: 0.85, P: 0.62 }; // 'L' is not valid, corrected to 'P'
  const IMPACT_WEIGHTS = { H: 0.56, L: 0.22, N: 0.0 };

  // Validating Exploitability Metrics
  if (
    !Object.prototype.hasOwnProperty.call(AV_WEIGHTS, AV) ||
    !Object.prototype.hasOwnProperty.call(AC_WEIGHTS, AC) ||
    !Object.prototype.hasOwnProperty.call(PR_WEIGHTS[PR], UI) ||
    !Object.prototype.hasOwnProperty.call(UI_WEIGHTS, UI) ||
    !Object.prototype.hasOwnProperty.call(AT_WEIGHTS, AT)
  ) {
    throw new Error("Invalid Exploitability Metric value.");
  }

  // Validating Impact Metrics
  if (
    !Object.prototype.hasOwnProperty.call(IMPACT_WEIGHTS, VC) ||
    !Object.prototype.hasOwnProperty.call(IMPACT_WEIGHTS, VI) ||
    !Object.prototype.hasOwnProperty.call(IMPACT_WEIGHTS, VA) ||
    !Object.prototype.hasOwnProperty.call(IMPACT_WEIGHTS, SC) ||
    !Object.prototype.hasOwnProperty.call(IMPACT_WEIGHTS, SI) ||
    !Object.prototype.hasOwnProperty.call(IMPACT_WEIGHTS, SA)
  ) {
    throw new Error("Invalid Impact Metric value.");
  }

  const impactSubscore =
    1 -
    (1 - IMPACT_WEIGHTS[VC]) *
      (1 - IMPACT_WEIGHTS[VI]) *
      (1 - IMPACT_WEIGHTS[VA]) *
      (1 - IMPACT_WEIGHTS[SC]) *
      (1 - IMPACT_WEIGHTS[SI]) *
      (1 - IMPACT_WEIGHTS[SA]);
  const impact = 7.52 * impactSubscore;

  const exploitability =
    8.22 *
    AV_WEIGHTS[AV] *
    AC_WEIGHTS[AC] *
    PR_WEIGHTS[PR][UI] *
    UI_WEIGHTS[UI] *
    AT_WEIGHTS[AT];

  let baseScore = 0;
  if (impact <= 0) {
    baseScore = 0;
  } else {
    baseScore = Math.min(impact + exploitability, 10);
  }

  return Math.round(baseScore * 10) / 10;
}

// Export module
module.exports = {
  calculateCVSS,
};
