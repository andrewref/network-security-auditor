from langchain_core.tools import tool


def level_for(risk: int) -> str:
    """Map a per-finding risk (impact*likelihood, 0-25) to a level, using the
    same thresholds as the overall score so a finding and the headline agree."""
    pct = round((risk / 25) * 100)
    if pct >= 80:
        return "Critical"
    if pct >= 60:
        return "High"
    if pct >= 30:
        return "Medium"
    return "Low"


@tool
def calculate_risk(findings: list) -> dict:
    """
    Calculate overall network risk using Risk = Impact x Likelihood
    (NIST SP 800-30 / ISO 27005). Each finding scores 1-5 on impact
    and likelihood; per-finding risk is impact*likelihood (max 25).
    """
    finding_risks = []
    for finding in findings:
        impact = finding.get("impact", 1)
        likelihood = finding.get("likelihood", 1)
        finding_risks.append(impact * likelihood)

    score = max(finding_risks) if finding_risks else 0  # worst single finding drives overall level
    score_pct = round((score / 25) * 100)
    level = level_for(score)  # single source of truth for the thresholds

    return {"score": score_pct, "level": level, "per_finding_risk": finding_risks}
