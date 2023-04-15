const CVSS_VALUES = {
    attackVector: 0,
    attackComplexity: 0,
    privilegesRequired: 0,
    userInteraction: 0,
    scope: 0,
    confidentiality: 0,
    integrity: 0,
    availability: 0,
    exploitCodeMaturity: 1,
    remediationLevel: 1,
    reportConfidence: 1,
    confidentialityRequirement: 1,
    integrityRequirement: 1,
    availabilityRequirement: 1,
    modifiedAttackVector: 0,
    modifiedAttackComplexity: 0,
    modifiedPrivilegesRequired: 0,
    modifiedUserInteraction: 0,
    modifiedScope: 0,
    modifiedConfidentiality: 0,
    modifiedIntegrity: 0,
    modifiedAvailability: 0,
};

function calculateCVSS() {
    // Get values from form
    const formData = Object.fromEntries(
        Object.entries(CVSS_VALUES).map(([key, value]) => [
            key,
            parseFloat(document.getElementById(key).value) || value,
        ])
    );

    // Calculate base score
    const impactSubscore =
        10.41 * (1 - (1 - formData.confidentiality) * (1 - formData.integrity) * (1 - formData.availability));
    const exploitabilitySubscore =
        20 *
        formData.attackVector *
        formData.attackComplexity *
        formData.privilegesRequired *
        formData.userInteraction;
    const baseScore =
        formData.scope === 0
            ? Math.min((impactSubscore + exploitabilitySubscore) / 10, 10)
            : Math.min(1.08 * (impactSubscore + exploitabilitySubscore), 10);

    // Calculate environmental score
    const modifiedImpactSubscore =
        10.41 *
        (1 -
            (1 - formData.modifiedConfidentiality) *
            (1 - formData.modifiedIntegrity) *
            (1 - formData.modifiedAvailability));
    const modifiedExploitabilitySubscore =
        20 *
        formData.modifiedAttackVector *
        formData.modifiedAttackComplexity *
        formData.modifiedPrivilegesRequired *
        formData.modifiedUserInteraction;
    const environmentalScore =
        Math.max(
            (1 - formData.confidentialityRequirement) *
            (1 - formData.integrityRequirement) *
            (1 - formData.availabilityRequirement) *
            baseScore,
            formData.scope === 0
                ? Math.min((modifiedImpactSubscore + modifiedExploitabilitySubscore) / 10, 10)
                : Math.min(1.08 * (modifiedImpactSubscore + modifiedExploitabilitySubscore), 10)
        );

    // Set results
    document.getElementById("cvssScore").value = baseScore.toFixed(1);
    document.getElementById("cvssSeverity").value = getSeverity(baseScore);
    document.getElementById("attackVectorResult").value = getAttackVector(formData);
    console.log(formData)
}
function getSeverity(score) {
    if (score >= 9.0) {
        return "Critical";
    } else if (score >= 7.0) {
        return "High";
    } else if (score >= 4.0) {
        return "Medium";
    } else if (score >= 0.1) {
        return "Low";
    } else {
        return "None";
    }
}

function getAttackVector(formData) {
    const AV_VALUES = {
        0.85: "N",
        0.62: "A",
        0.55: "L",
        0.2: "P",
    };

    const PR_VALUES = {
        0.85: "N",
        0.62: "L",
        0.27: "H",
    };

    const C_VALUES = {
        0: "N",
        0.22: "L",
        0.56: "H",
    };

    const I_VALUES = {
        0: "N",
        0.22: "L",
        0.56: "H",
    };

    const A_VALUES = {
        0: "N",
        0.22: "L",
        0.56: "H",
    };

    const avResult = AV_VALUES[formData.attackVector] || "";
    const acResult = formData.attackComplexity == 0.77 ? "L" : "H";
    const prResult = PR_VALUES[formData.privilegesRequired] || "";
    const uiResult = formData.userInteraction == 0.85 ? "N" : "R";
    const sResult = formData.scope == 0 ? "U" : "C";
    const cResult = C_VALUES[formData.confidentiality] || "";
    const iResult = I_VALUES[formData.integrity] || "";
    const aResult = A_VALUES[formData.availability] || "";

    return `CVSS:3.1/AV:${avResult}/AC:${acResult}/PR:${prResult}/UI:${uiResult}/S:${sResult}/C:${cResult}/I:${iResult}/A:${aResult}`;
}