import { ReportViolation, StackValidationArgs, StackValidationPolicy } from "@pulumi/policy";

export const alwaysFailRule: StackValidationPolicy = {
    name: "always-fail-rule",
    enforcementLevel: "advisory",
    description: "This rule always fails for demonstration purposes.",
    remediationSteps: "This is a demo rule that always fails. No remediation is possible.",
    validateStack: (args: StackValidationArgs, reportViolation: ReportViolation)  => {
        reportViolation("Failed");
    },
}
