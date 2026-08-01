"""CRA Article 14 notification payload builders + validator.

Implements the four notification stages defined by Regulation (EU) 2024/2847
Article 14 (and the comparable structure of Article 15):

  * 24 h  — early warning              (Art. 14(2)(a) / 14(4)(a))
  * 72 h  — vulnerability notification (Art. 14(2)(b))
  * 72 h  — incident notification      (Art. 14(4)(b))
  * 14 d  — final vulnerability report (Art. 14(2)(c))
  * 1 m   — final incident report      (Art. 14(4)(c))

Output payloads follow a stable JSON schema (``schema_version = "1.1.0"``)
designed for the ENISA Single Reporting Platform (SRP).

v1.1.0 additions (2026-08-01, aligned with ENISA AR guidance 31 Jul 2026):
  * ``eu_representative`` block in the manufacturer section — required when a
    non-EU manufacturer appoints an EU-based Assigned Representative (AR) to
    operate the SRP portal on their behalf. When present the AR country is
    used for CSIRT routing.
  * ``dissemination_delay`` top-level block — supports Art. 16(2) Particularly
    Exceptional Circumstances (PEC). When present on a 72h notification the
    ENISA portal shows status "72h under PEC". Grounds: art_16_2_a/b/c per
    Delegated Regulation (EU) 2026/881.
  * ENISA SRP FAQ Q16 optional fields added to all builders:
    ``notification_level``, ``title``, ``euvd_id``,
    ``sensitivity_of_information``, ``product_type``, ``annex_category``.

This module does NOT submit notifications. ENISA SRP authentication uses
EU Login (CAS), a closed government identity scheme; Article 14 reporting
is the manufacturer's non-delegable legal obligation (EC FAQ §4.6.1).
Submission may be performed by the manufacturer's own SRP user or, where
appointed, their AR user in the ENISA portal.
Use this library to *prepare* payloads, then submit them via the SRP portal
or your designated CSIRT's intake channel.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from cra_scope_core.csirt import EU_CSIRT_MAP, resolve_csirt

SCHEMA_VERSION = "1.1.0"
REGULATORY_BASIS = "Regulation (EU) 2024/2847"

# Valid Art. 16(2) grounds for dissemination delay (Delegated Reg. (EU) 2026/881)
VALID_DISSEMINATION_DELAY_GROUNDS = {"art_16_2_a", "art_16_2_b", "art_16_2_c"}

_VALID_NOTIFICATION_TYPES = {
    "early_warning",
    "vulnerability_notification",
    "incident_notification",
    "final_report",
}
_VALID_SUBJECT_TYPES = {"vulnerability", "severe_incident"}


class ValidationError(ValueError):
    """Raised when a payload fails schema validation.

    The ``errors`` attribute contains the full list of validation messages.
    """

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__(
            f"Payload failed validation ({len(self.errors)} error"
            f"{'s' if len(self.errors) != 1 else ''}): {self.errors}"
        )


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def build_early_warning(
    *,
    manufacturer_name: str,
    manufacturer_country: str,
    manufacturer_contact: str,
    product_name: str,
    product_version: str,
    product_category: str,
    vulnerability_id: str,
    detection_timestamp: str,
    suspected_malicious: Optional[bool] = None,
    cross_border_impact: Optional[bool] = None,
    preliminary_description: str = "",
    affected_member_states: Optional[list[str]] = None,
    article_basis: str = "art_14_mandatory",
    report_subject_type: str = "vulnerability",
    # EU representative (AR) — required for non-EU manufacturers (v1.1.0)
    eu_representative_name: str = "",
    eu_representative_country: str = "",
    eu_representative_contact: str = "",
    # ENISA SRP FAQ Q16 optional fields (v1.1.0)
    notification_level: str = "",
    title: str = "",
    euvd_id: str = "",
    sensitivity_of_information: str = "",
    product_type: str = "",
    annex_category: str = "",
) -> dict[str, Any]:
    """Build an Early Warning notification (CRA Art. 14 stage (a)).

    Must be submitted within 24 hours of becoming aware of an actively
    exploited vulnerability (or a severe incident).

    When a non-EU manufacturer has appointed an EU Assigned Representative (AR),
    pass ``eu_representative_country`` — CSIRT routing will use that country
    rather than the manufacturer's own country.
    """
    # AR routing: if an EU representative country is provided, route to that CSIRT
    routing_country = eu_representative_country.upper() if eu_representative_country else manufacturer_country
    csirt = resolve_csirt(routing_country)
    now = datetime.now(timezone.utc).isoformat()

    if article_basis == "art_14_mandatory":
        cra_article = "14(4)(a)" if report_subject_type == "severe_incident" else "14(2)(a)"
    else:
        cra_article = "15(1)"

    manufacturer_block: dict[str, Any] = {
        "name": manufacturer_name,
        "main_establishment_country": manufacturer_country,
        "contact_email": manufacturer_contact,
    }
    if eu_representative_name or eu_representative_country or eu_representative_contact:
        manufacturer_block["eu_representative"] = {
            "name": eu_representative_name,
            "country": eu_representative_country,
            "contact_email": eu_representative_contact,
        }

    product_block: dict[str, Any] = {
        "name": product_name,
        "version": product_version,
        "category": product_category,
    }
    if product_type:
        product_block["product_type"] = product_type
    if annex_category:
        product_block["annex_category"] = annex_category

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "notification_type": "early_warning",
        "cra_article": cra_article,
        "submission_basis": article_basis,
        "report_subject_type": report_subject_type,
        "regulatory_basis": REGULATORY_BASIS,
        "submission_timestamp": now,
        "deadline_hours": 24,
        "manufacturer": manufacturer_block,
        "designated_csirt": csirt,
        "enisa_simultaneous": True,
        "product": product_block,
    }

    # Q16 optional top-level fields
    if notification_level:
        payload["notification_level"] = notification_level
    if title:
        payload["title"] = title
    if euvd_id:
        payload["euvd_id"] = euvd_id
    if sensitivity_of_information:
        payload["sensitivity_of_information"] = sensitivity_of_information

    subject_block = {
        "id": vulnerability_id,
        "detection_timestamp": detection_timestamp,
        "suspected_malicious_action": suspected_malicious,
        "cross_border_impact": cross_border_impact,
        "preliminary_description": preliminary_description,
        "affected_member_states": affected_member_states or [],
    }
    if report_subject_type == "severe_incident":
        payload["incident"] = {"severe_incident": True, **subject_block}
    else:
        payload["vulnerability"] = {"actively_exploited": True, **subject_block}

    return payload


def build_incident_notification(
    *,
    manufacturer_name: str,
    manufacturer_country: str,
    manufacturer_contact: str,
    product_name: str,
    product_version: str,
    product_category: str,
    incident_id: str,
    detection_timestamp: str,
    early_warning_reference: Optional[str] = None,
    severity_assessment: str = "",
    incident_description: str = "",
    impact_assessment: str = "",
    estimated_affected_users: Optional[int] = None,
    corrective_measures_applied: Optional[list[str]] = None,
    corrective_measures_planned: Optional[list[str]] = None,
    user_guidance: str = "",
    cross_border_impact: Optional[bool] = None,
    affected_member_states: Optional[list[str]] = None,
    article_basis: str = "art_14_mandatory",
    # EU representative (AR) — required for non-EU manufacturers (v1.1.0)
    eu_representative_name: str = "",
    eu_representative_country: str = "",
    eu_representative_contact: str = "",
    # Art. 16(2) dissemination delay / PEC (v1.1.0)
    dissemination_delay_requested: bool = False,
    dissemination_delay_grounds: Optional[list[str]] = None,
    dissemination_delay_justification: str = "",
    # ENISA SRP FAQ Q16 optional fields (v1.1.0)
    notification_level: str = "",
    title: str = "",
    euvd_id: str = "",
    sensitivity_of_information: str = "",
    product_type: str = "",
    annex_category: str = "",
) -> dict[str, Any]:
    """Build a severe-incident notification (CRA Art. 14(4)(b)).

    Pass ``dissemination_delay_requested=True`` and one or more
    ``dissemination_delay_grounds`` to invoke Art. 16(2) PEC — the ENISA
    portal will show this notification as "72h under PEC".
    """
    routing_country = eu_representative_country.upper() if eu_representative_country else manufacturer_country
    csirt = resolve_csirt(routing_country)
    now = datetime.now(timezone.utc).isoformat()

    cra_article = "14(4)(b)" if article_basis == "art_14_mandatory" else "15(1)"

    manufacturer_block: dict[str, Any] = {
        "name": manufacturer_name,
        "main_establishment_country": manufacturer_country,
        "contact_email": manufacturer_contact,
    }
    if eu_representative_name or eu_representative_country or eu_representative_contact:
        manufacturer_block["eu_representative"] = {
            "name": eu_representative_name,
            "country": eu_representative_country,
            "contact_email": eu_representative_contact,
        }

    product_block: dict[str, Any] = {
        "name": product_name,
        "version": product_version,
        "category": product_category,
        "estimated_affected_users": estimated_affected_users,
    }
    if product_type:
        product_block["product_type"] = product_type
    if annex_category:
        product_block["annex_category"] = annex_category

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "notification_type": "incident_notification",
        "cra_article": cra_article,
        "submission_basis": article_basis,
        "report_subject_type": "severe_incident",
        "regulatory_basis": REGULATORY_BASIS,
        "submission_timestamp": now,
        "deadline_hours": 72,
        "early_warning_reference": early_warning_reference,
        "manufacturer": manufacturer_block,
        "designated_csirt": csirt,
        "enisa_simultaneous": True,
        "product": product_block,
        "incident": {
            "id": incident_id,
            "severe_incident": True,
            "detection_timestamp": detection_timestamp,
            "description": incident_description,
            "impact_assessment": impact_assessment,
            "severity_assessment": severity_assessment,
            "cross_border_impact": cross_border_impact,
            "affected_member_states": affected_member_states or [],
        },
        "corrective_measures": {
            "applied": corrective_measures_applied or [],
            "planned": corrective_measures_planned or [],
            "user_guidance": user_guidance,
        },
    }

    if dissemination_delay_requested or dissemination_delay_grounds:
        payload["dissemination_delay"] = {
            "requested": dissemination_delay_requested,
            "grounds": dissemination_delay_grounds or [],
            "justification": dissemination_delay_justification,
        }

    if notification_level:
        payload["notification_level"] = notification_level
    if title:
        payload["title"] = title
    if euvd_id:
        payload["euvd_id"] = euvd_id
    if sensitivity_of_information:
        payload["sensitivity_of_information"] = sensitivity_of_information

    return payload


def build_vulnerability_notification(
    *,
    manufacturer_name: str,
    manufacturer_country: str,
    manufacturer_contact: str,
    product_name: str,
    product_version: str,
    product_category: str,
    vulnerability_id: str,
    detection_timestamp: str,
    early_warning_reference: Optional[str] = None,
    severity_assessment: str = "",
    cvss_score: Optional[float] = None,
    cvss_vector: str = "",
    nature_of_vulnerability: str = "",
    exploitation_details: str = "",
    affected_product_versions: Optional[list[str]] = None,
    estimated_affected_users: Optional[int] = None,
    corrective_measures_applied: Optional[list[str]] = None,
    corrective_measures_planned: Optional[list[str]] = None,
    user_guidance: str = "",
    publicly_known: bool = False,
    public_references: Optional[list[str]] = None,
    cross_border_impact: Optional[bool] = None,
    affected_member_states: Optional[list[str]] = None,
    article_basis: str = "art_14_mandatory",
    # EU representative (AR) — required for non-EU manufacturers (v1.1.0)
    eu_representative_name: str = "",
    eu_representative_country: str = "",
    eu_representative_contact: str = "",
    # Art. 16(2) dissemination delay / PEC (v1.1.0)
    dissemination_delay_requested: bool = False,
    dissemination_delay_grounds: Optional[list[str]] = None,
    dissemination_delay_justification: str = "",
    # ENISA SRP FAQ Q16 optional fields (v1.1.0)
    notification_level: str = "",
    title: str = "",
    euvd_id: str = "",
    sensitivity_of_information: str = "",
    product_type: str = "",
    annex_category: str = "",
) -> dict[str, Any]:
    """Build a Vulnerability Notification (CRA Art. 14(2)(b)).

    Pass ``dissemination_delay_requested=True`` and one or more
    ``dissemination_delay_grounds`` to invoke Art. 16(2) PEC — the ENISA
    portal will show this notification as "72h under PEC".
    """
    routing_country = eu_representative_country.upper() if eu_representative_country else manufacturer_country
    csirt = resolve_csirt(routing_country)
    now = datetime.now(timezone.utc).isoformat()
    cra_article = "14(2)(b)" if article_basis == "art_14_mandatory" else "15(1)"

    manufacturer_block: dict[str, Any] = {
        "name": manufacturer_name,
        "main_establishment_country": manufacturer_country,
        "contact_email": manufacturer_contact,
    }
    if eu_representative_name or eu_representative_country or eu_representative_contact:
        manufacturer_block["eu_representative"] = {
            "name": eu_representative_name,
            "country": eu_representative_country,
            "contact_email": eu_representative_contact,
        }

    product_block: dict[str, Any] = {
        "name": product_name,
        "version": product_version,
        "category": product_category,
        "affected_versions": affected_product_versions or [],
        "estimated_affected_users": estimated_affected_users,
    }
    if product_type:
        product_block["product_type"] = product_type
    if annex_category:
        product_block["annex_category"] = annex_category

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "notification_type": "vulnerability_notification",
        "cra_article": cra_article,
        "submission_basis": article_basis,
        "regulatory_basis": REGULATORY_BASIS,
        "submission_timestamp": now,
        "deadline_hours": 72,
        "early_warning_reference": early_warning_reference,
        "manufacturer": manufacturer_block,
        "designated_csirt": csirt,
        "enisa_simultaneous": True,
        "product": product_block,
        "vulnerability": {
            "id": vulnerability_id,
            "actively_exploited": True,
            "detection_timestamp": detection_timestamp,
            "nature_of_vulnerability": nature_of_vulnerability,
            "exploitation_details": exploitation_details,
            "severity_assessment": severity_assessment,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "publicly_known": publicly_known,
            "public_references": public_references or [],
            "cross_border_impact": cross_border_impact,
            "affected_member_states": affected_member_states or [],
        },
        "corrective_measures": {
            "applied": corrective_measures_applied or [],
            "planned": corrective_measures_planned or [],
            "user_guidance": user_guidance,
        },
    }

    if dissemination_delay_requested or dissemination_delay_grounds:
        payload["dissemination_delay"] = {
            "requested": dissemination_delay_requested,
            "grounds": dissemination_delay_grounds or [],
            "justification": dissemination_delay_justification,
        }

    if notification_level:
        payload["notification_level"] = notification_level
    if title:
        payload["title"] = title
    if euvd_id:
        payload["euvd_id"] = euvd_id
    if sensitivity_of_information:
        payload["sensitivity_of_information"] = sensitivity_of_information

    return payload


def build_final_report(
    *,
    manufacturer_name: str,
    manufacturer_country: str,
    manufacturer_contact: str,
    product_name: str,
    product_version: str,
    product_category: str,
    vulnerability_id: str,
    detection_timestamp: str,
    early_warning_reference: Optional[str] = None,
    notification_reference: Optional[str] = None,
    detailed_description: str = "",
    severity_assessment: str = "",
    cvss_score: Optional[float] = None,
    cvss_vector: str = "",
    root_cause_analysis: str = "",
    threat_type: str = "",
    exploitation_details: str = "",
    attacker_information: str = "",
    affected_product_versions: Optional[list[str]] = None,
    estimated_affected_users: Optional[int] = None,
    corrective_measures_applied: Optional[list[str]] = None,
    corrective_measures_ongoing: Optional[list[str]] = None,
    security_update_available: bool = False,
    security_update_url: str = "",
    user_guidance: str = "",
    cross_border_impact: Optional[bool] = None,
    affected_member_states: Optional[list[str]] = None,
    timeline: Optional[list[dict[str, str]]] = None,
    lessons_learned: str = "",
    article_basis: str = "art_14_mandatory",
    deadline_days: int = 14,
    report_subject_type: str = "vulnerability",
    # EU representative (AR) — required for non-EU manufacturers (v1.1.0)
    eu_representative_name: str = "",
    eu_representative_country: str = "",
    eu_representative_contact: str = "",
    # ENISA SRP FAQ Q16 optional fields (v1.1.0)
    notification_level: str = "",
    title: str = "",
    euvd_id: str = "",
    sensitivity_of_information: str = "",
    product_type: str = "",
    annex_category: str = "",
) -> dict[str, Any]:
    """Build a Final Report (CRA Art. 14(2)(c) / 14(4)(c)).

    Vulnerability final report: 14 days after a corrective measure is available.
    Severe-incident final report: 1 month after the incident notification.
    """
    routing_country = eu_representative_country.upper() if eu_representative_country else manufacturer_country
    csirt = resolve_csirt(routing_country)
    now = datetime.now(timezone.utc).isoformat()

    if article_basis == "art_14_mandatory":
        cra_article = "14(4)(c)" if report_subject_type == "severe_incident" else "14(2)(c)"
    else:
        cra_article = "15(1)"

    manufacturer_block: dict[str, Any] = {
        "name": manufacturer_name,
        "main_establishment_country": manufacturer_country,
        "contact_email": manufacturer_contact,
    }
    if eu_representative_name or eu_representative_country or eu_representative_contact:
        manufacturer_block["eu_representative"] = {
            "name": eu_representative_name,
            "country": eu_representative_country,
            "contact_email": eu_representative_contact,
        }

    product_block: dict[str, Any] = {
        "name": product_name,
        "version": product_version,
        "category": product_category,
        "affected_versions": affected_product_versions or [],
        "estimated_affected_users": estimated_affected_users,
    }
    if product_type:
        product_block["product_type"] = product_type
    if annex_category:
        product_block["annex_category"] = annex_category

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "notification_type": "final_report",
        "cra_article": cra_article,
        "submission_basis": article_basis,
        "report_subject_type": report_subject_type,
        "regulatory_basis": REGULATORY_BASIS,
        "submission_timestamp": now,
        "deadline_days": deadline_days,
        "early_warning_reference": early_warning_reference,
        "notification_reference": notification_reference,
        "manufacturer": manufacturer_block,
        "designated_csirt": csirt,
        "enisa_simultaneous": True,
        "product": product_block,
        "corrective_measures": {
            "applied": corrective_measures_applied or [],
            "ongoing": corrective_measures_ongoing or [],
            "security_update_available": security_update_available,
            "security_update_url": security_update_url,
            "user_guidance": user_guidance,
        },
        "incident_timeline": timeline or [],
        "lessons_learned": lessons_learned,
    }

    if notification_level:
        payload["notification_level"] = notification_level
    if title:
        payload["title"] = title
    if euvd_id:
        payload["euvd_id"] = euvd_id
    if sensitivity_of_information:
        payload["sensitivity_of_information"] = sensitivity_of_information

    if report_subject_type == "severe_incident":
        payload["incident"] = {
            "id": vulnerability_id,
            "severe_incident": True,
            "detection_timestamp": detection_timestamp,
            "detailed_description": detailed_description,
            "severity_assessment": severity_assessment,
            "root_cause_analysis": root_cause_analysis,
            "threat_type": threat_type,
            "attacker_information": attacker_information,
            "cross_border_impact": cross_border_impact,
            "affected_member_states": affected_member_states or [],
        }
    else:
        payload["vulnerability"] = {
            "id": vulnerability_id,
            "actively_exploited": True,
            "detection_timestamp": detection_timestamp,
            "detailed_description": detailed_description,
            "severity_assessment": severity_assessment,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "root_cause_analysis": root_cause_analysis,
            "threat_type": threat_type,
            "exploitation_details": exploitation_details,
            "attacker_information": attacker_information,
            "cross_border_impact": cross_border_impact,
            "affected_member_states": affected_member_states or [],
        }

    return payload


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

def validate_notification(payload: dict) -> list[str]:
    """Validate an SRP notification payload.

    Returns a list of error messages (empty = valid). To raise on failure,
    use ``assert_valid`` or wrap with ``ValidationError(errors)``.
    """
    errors: list[str] = []

    notification_type = payload.get("notification_type")
    if notification_type not in _VALID_NOTIFICATION_TYPES:
        errors.append(f"Invalid notification_type: {notification_type!r}")
        return errors

    report_subject_type = payload.get("report_subject_type", "vulnerability")
    if report_subject_type not in _VALID_SUBJECT_TYPES:
        errors.append(f"Invalid report_subject_type: {report_subject_type!r}")
        return errors

    for field in ("schema_version", "cra_article", "submission_timestamp"):
        if not payload.get(field):
            errors.append(f"Missing required field: {field}")

    mfr = payload.get("manufacturer", {}) or {}
    for field in ("name", "main_establishment_country", "contact_email"):
        if not mfr.get(field):
            errors.append(f"Missing manufacturer.{field}")

    country = mfr.get("main_establishment_country", "")
    if country and country.upper() not in EU_CSIRT_MAP:
        errors.append(
            f"Country {country!r} is not a recognized EU Member State. "
            "Manufacturer must have main establishment in an EU Member State."
        )

    # Validate eu_representative block if present
    eu_rep = mfr.get("eu_representative")
    if eu_rep is not None:
        if not isinstance(eu_rep, dict):
            errors.append("manufacturer.eu_representative must be an object")
        else:
            rep_country = eu_rep.get("country", "")
            if rep_country and rep_country.upper() not in EU_CSIRT_MAP:
                errors.append(
                    f"manufacturer.eu_representative.country {rep_country!r} is not "
                    "a recognized EU Member State."
                )

    # Validate dissemination_delay block if present (Art. 16(2) / PEC)
    delay = payload.get("dissemination_delay")
    if delay is not None:
        if not isinstance(delay, dict):
            errors.append("dissemination_delay must be an object")
        else:
            bad_grounds = [
                g for g in (delay.get("grounds") or [])
                if g not in VALID_DISSEMINATION_DELAY_GROUNDS
            ]
            if bad_grounds:
                errors.append(
                    f"Invalid dissemination_delay.grounds: {bad_grounds}. "
                    f"Must be subset of {sorted(VALID_DISSEMINATION_DELAY_GROUNDS)}."
                )

    product = payload.get("product", {}) or {}
    for field in ("name", "version"):
        if not product.get(field):
            errors.append(f"Missing product.{field}")

    subject_key = "incident" if report_subject_type == "severe_incident" else "vulnerability"
    subject = payload.get(subject_key, {}) or {}
    if not subject.get("id"):
        errors.append(f"Missing {subject_key}.id")
    if not subject.get("detection_timestamp"):
        errors.append(f"Missing {subject_key}.detection_timestamp")

    if notification_type == "early_warning":
        if subject.get("suspected_malicious_action") is None:
            errors.append(
                f"early_warning requires {subject_key}.suspected_malicious_action "
                "(Art. 14(2)(a): indicate whether due to malicious action)"
            )
        if subject.get("cross_border_impact") is None:
            errors.append(
                f"early_warning requires {subject_key}.cross_border_impact "
                "(Art. 14(2)(a): indicate potential cross-border impact)"
            )

    elif notification_type == "vulnerability_notification":
        if report_subject_type != "vulnerability":
            errors.append("vulnerability_notification requires report_subject_type='vulnerability'")
        if not subject.get("nature_of_vulnerability"):
            errors.append(
                "vulnerability_notification requires vulnerability.nature_of_vulnerability "
                "(Art. 14(2)(b): general description of nature)"
            )
        if not subject.get("severity_assessment"):
            errors.append(
                "vulnerability_notification requires vulnerability.severity_assessment "
                "(Art. 14(2)(b): preliminary assessment of severity)"
            )
        corrective = payload.get("corrective_measures", {}) or {}
        if not corrective.get("applied") and not corrective.get("planned"):
            errors.append(
                "vulnerability_notification requires at least one corrective measure "
                "(Art. 14(2)(b): corrective measures applied or offered)"
            )

    elif notification_type == "incident_notification":
        if report_subject_type != "severe_incident":
            errors.append("incident_notification requires report_subject_type='severe_incident'")
        if not subject.get("description"):
            errors.append("incident_notification requires incident.description")
        if not subject.get("severity_assessment"):
            errors.append("incident_notification requires incident.severity_assessment")
        corrective = payload.get("corrective_measures", {}) or {}
        if not corrective.get("applied") and not corrective.get("planned"):
            errors.append("incident_notification requires at least one corrective measure")

    elif notification_type == "final_report":
        if not subject.get("detailed_description"):
            errors.append(
                f"final_report requires {subject_key}.detailed_description "
                "(Art. 14(2)(c): detailed description including severity and impact)"
            )
        if not subject.get("root_cause_analysis") and not subject.get("threat_type"):
            errors.append(
                f"final_report requires {subject_key}.root_cause_analysis or threat_type "
                "(Art. 14(2)(c): type of threat or root cause)"
            )

    return errors


def assert_valid(payload: dict) -> None:
    """Validate ``payload`` and raise ``ValidationError`` if it fails."""
    errors = validate_notification(payload)
    if errors:
        raise ValidationError(errors)
