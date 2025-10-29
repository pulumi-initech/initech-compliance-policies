import { PolicyPack } from "@pulumi/policy";
import { policyManager } from "@pulumi/compliance-policy-manager";

import { validateEksNodeType } from "./rules/validateEksNodeType";
// import { checkStackTags } from "./rules/checkStackTags";
import { securityGroupOpenIngresses } from "./rules/validateSecurityGroups";
import { s3BucketLoggingEnabled } from "./rules/validateS3";
import { validateHitrustAWSProvider } from "./rules/validateHitrustAWSProvider";

new PolicyPack("initech-org-compliance-policies-aws", {
    enforcementLevel: "advisory",
    policies:[
        // select CIS security policies for IAM and Secrets
        ...policyManager.selectPolicies({
            vendors: ["aws"],
            // services: ["alb", "apigateway", "apigatewayv2", "appflow", "athena", "cloudfront", "ebs", "ec2", "ecr", "efs", "eks", "elb", "iam", "kms", "lambda", "rds", "s3", "secretsmanager"],
            services: ["iam", "kms", "secretsmanager"],
            // severities: ["critical", "high", "low", "medium"],
            // topics: ["availability", "backup", "container", "cost", "documentation", "encryption", "kubernetes", "logging", "network", "performance", "permissions", "resilience", "security", "storage", "vulnerability"],
            // topics: ["security", "vulnerability", "permissions"],
            frameworks: ["cis"] // Other available frameworks: cis", "hitrust", "iso27001", "pcidss"
        }, "mandatory"),

        // select ISO129001 and CIS polices for compute
        ...policyManager.selectPolicies({
            vendors: ["aws"],
            services: ["alb", "ec2", "ecr", "eks", "rds"],
            frameworks: ["cis", "iso27001"] // Other available frameworks: cis", "hitrust", "iso27001", "pcidss
        }, "advisory"),
        
        ...policyManager.selectPolicies({
            frameworks: ["pci-dss"],
            vendors: ["aws"],
            services: ["s3"],
        }),
        
        // select kubernetes policies
        ...policyManager.selectPolicies({
            vendors: ["kubernetes"],
            severities: ["high", "critical"],
        }, "advisory"),
    
        // include custom policies imported above
        // checkStackTags,
        validateEksNodeType,
        securityGroupOpenIngresses,
        s3BucketLoggingEnabled,
        validateHitrustAWSProvider
    ],
});

/**
 * Optional✔️: Display additional stats and helpful
 * information when the policy pack is evaluated.
 */
policyManager.displaySelectionStats({
    displayGeneralStats: true,
    displayModuleInformation: true,
    displaySelectedPolicyNames: true,
});
