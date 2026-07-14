from soc_agent.models import RiskLevel


def map_risk(
    etiqueta: str,
) -> RiskLevel:

    match etiqueta:
        case "NORMAL":
            return RiskLevel.LOW

        case "OBSERVAR":
            return RiskLevel.MEDIUM

        case "SOSPECHOSO":
            return RiskLevel.HIGH

        case "ANOMALO":
            return RiskLevel.CRITICAL

        case _:
            return RiskLevel.LOW
