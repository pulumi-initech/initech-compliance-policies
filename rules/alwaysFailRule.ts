import { ReportViolation, ResourceValidationPolicy, ResourceValidationArgs } from "@pulumi/policy";

export const alwaysFailRule: ResourceValidationPolicy = {
    name: "always-fail-rule",
    enforcementLevel: "advisory",
    description: "This rule always fails for demonstration purposes.",
    remediationSteps: "This is a demo rule that always fails. No remediation is possible.",
    validateResource: (args: ResourceValidationArgs, reportViolation: ReportViolation)  => {
        reportViolation("Failed");
    }
}
