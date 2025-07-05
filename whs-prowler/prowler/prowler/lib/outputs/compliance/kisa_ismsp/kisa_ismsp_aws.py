from prowler.config.config import timestamp
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutput
from prowler.lib.outputs.compliance.kisa_ismsp.models import AWSKISAISMSPModel
from prowler.lib.outputs.finding import Finding


def _ensure_list(value: object):
    """Return ``value`` as a list if it's not already one."""
    if value is None or isinstance(value, list):
        return value
    return [value]


class AWSKISAISMSP(ComplianceOutput):
    """
    This class represents the AWS KISA-ISMS-P compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into AWS KISA-ISMS-P compliance format.
    """

    def transform(
        self,
        findings: list[Finding],
        compliance: Compliance,
        compliance_name: str,
    ) -> None:
        """
        Transforms a list of findings into AWS KISA-ISMS-P compliance format.

        Parameters:
            - findings (list): A list of findings.
            - compliance (Compliance): A compliance model.
            - compliance_name (str): The name of the compliance model.

        Returns:
            - None
        """
        for finding in findings:
            # Get the compliance requirements for the finding
            finding_requirements = finding.compliance.get(compliance_name, [])
            for requirement in compliance.Requirements:
                if requirement.Id in finding_requirements:
                    # Retrieve check context if available
                    check_context = next(
                        (
                            c
                            for c in requirement.Checks
                            if (getattr(c, "Id", c) == finding.check_id)
                        ),
                        None,
                    )
                    for attribute in requirement.Attributes:
                        compliance_row = AWSKISAISMSPModel(
                            Provider=finding.provider,
                            Description=compliance.Description,
                            AccountId=finding.account_uid,
                            Region=finding.region,
                            AssessmentDate=str(timestamp),
                            Requirements_Id=requirement.Id,
                            Requirements_Name=requirement.Name,
                            Requirements_Description=requirement.Description,
                            Requirements_Attributes_Domain=attribute.Domain,
                            Requirements_Attributes_Subdomain=attribute.Subdomain,
                            Requirements_Attributes_Section=attribute.Section,
                            # Purpose and ActionPlan can be defined either as a
                            # list or a string in the compliance mapping. Cast
                            # them to a list to satisfy the model requirements.
                            Requirements_Attributes_Purpose=
                                _ensure_list(
                                    getattr(
                                        check_context,
                                        "Purpose",
                                        attribute.Purpose,
                                    )
                                ),
                            Requirements_Attributes_ActionPlan=
                                _ensure_list(
                                    getattr(
                                        check_context,
                                        "ActionPlan",
                                        attribute.ActionPlan,
                                    )
                                ),
                            Requirements_Attributes_AuditChecklist=attribute.AuditChecklist,
                            Requirements_Attributes_RelatedRegulations=attribute.RelatedRegulations,
                            Requirements_Attributes_AuditEvidence=attribute.AuditEvidence,
                            Requirements_Attributes_NonComplianceCases=attribute.NonComplianceCases,
                            Status=finding.status,
                            StatusExtended=finding.status_extended,
                            ResourceId=finding.resource_uid,
                            ResourceName=finding.resource_name,
                            CheckId=finding.check_id,
                            Muted=finding.muted,
                        )
                        self._data.append(compliance_row)
        # Add manual requirements to the compliance output
        for requirement in compliance.Requirements:
            if not requirement.Checks:
                for attribute in requirement.Attributes:
                    compliance_row = AWSKISAISMSPModel(
                        Provider=compliance.Provider.lower(),
                        Description=compliance.Description,
                        AccountId="",
                        Region="",
                        AssessmentDate=str(timestamp),
                        Requirements_Id=requirement.Id,
                        Requirements_Name=requirement.Name,
                        Requirements_Description=requirement.Description,
                        Requirements_Attributes_Domain=attribute.Domain,
                        Requirements_Attributes_Subdomain=attribute.Subdomain,
                        Requirements_Attributes_Section=attribute.Section,
                        Requirements_Attributes_Purpose=
                            _ensure_list(attribute.Purpose),
                        Requirements_Attributes_ActionPlan=
                            _ensure_list(attribute.ActionPlan),
                        Requirements_Attributes_AuditChecklist=attribute.AuditChecklist,
                        Requirements_Attributes_RelatedRegulations=attribute.RelatedRegulations,
                        Requirements_Attributes_AuditEvidence=attribute.AuditEvidence,
                        Requirements_Attributes_NonComplianceCases=attribute.NonComplianceCases,
                        Status="MANUAL",
                        StatusExtended="Manual check",
                        ResourceId="manual_check",
                        ResourceName="Manual check",
                        CheckId="manual",
                        Muted=False,
                    )
                    self._data.append(compliance_row)
