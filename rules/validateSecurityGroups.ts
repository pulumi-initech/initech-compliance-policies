import * as aws from "@pulumi/aws";
import { ReportViolation, ResourceValidationPolicy, StackValidationArgs, StackValidationPolicy, validateResourceOfType } from "@pulumi/policy";

export const securityGroupOpenIngresses: ResourceValidationPolicy = {
    name: "validate-open-ingresses",
    enforcementLevel: "advisory",
    description: "Warn on open ingresses",
    validateResource: [
        validateResourceOfType(aws.ec2.SecurityGroup, (securityGroup, args, reportViolation) => {
            if(securityGroup.ingress) {
                for (const rule of securityGroup.ingress!) {
                    if (rule.cidrBlocks && rule.cidrBlocks.includes("0.0.0.0/0")) {
                        reportViolation("Security group allows ingress on port 22 from 0.0.0.0/0");
                    }
                }
            }
        }),
        validateResourceOfType(aws.ec2.SecurityGroupRule, (rule, args, reportViolation) => {
            if (rule.cidrBlocks && rule.cidrBlocks.includes("0.0.0.0/0")) {
                reportViolation("Security group allows ingress on port 22 from 0.0.0.0/0");
            }
        })
    ]
}
