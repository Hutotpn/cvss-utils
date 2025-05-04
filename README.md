# CVSS Calculator

A simple calculator for CVSS v3.1 and v4.0 scores. This library helps you compute the base score for vulnerabilities based on the CVSS metrics.

## Features

- Calculates CVSS v3.1 scores
- Calculates CVSS v4.0 scores
- Supports metric validation and error handling

## Installation

You can install this library via npm.

```bash
npm install cvss-utils
```

## Usage

### CVSS v3.1 Example:

```js
const { CVSSv3 } = require("cvss-utils");

const score = CVSSv3({
  attackVector: "N",
  attackComplexity: "L",
  privilegesRequired: "N",
  userInteraction: "N",
  confidentialityImpact: "H",
  integrityImpact: "H",
  availabilityImpact: "H",
});

console.log(`CVSS v3.1 Base Score: ${score}`);
```

### CVSS v4.0 Example:

```js
const { CVSSv4 } = require("cvss-utils");

const score = CVSSv4({
  attackVector: "N",
  attackComplexity: "L",
  privilegesRequired: "N",
  userInteraction: "N",
  attackRequirements: "L",
  providerUrgency: "H",
  confidentialityImpact: "H",
  integrityImpact: "H",
  availabilityImpact: "H",
  safetyConfidentiality: "N",
  safetyIntegrity: "N",
  safetyAvailability: "N",
});

console.log(`CVSS v4.0 Base Score: ${score}`);
```

## Contributing

1. Fork this repository.
2. Create a branch for your feature or bug fix.
3. Write tests for your changes.
4. Create a pull request.

## License

This project is licensed under the MPL-2.0 License - see the LICENSE file for details.
