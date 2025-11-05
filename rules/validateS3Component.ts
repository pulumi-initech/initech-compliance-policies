import * as aws from "@pulumi/aws";
import { ResourceValidationPolicy, validateResourceOfType } from "@pulumi/policy";

export const s3BucketLoggingEnabled: ResourceValidationPolicy = {
    name: "s3-bucket-parent-component",
    description: "Checks whether an S3 bucket is a child of a specific parent component.",
    enforcementLevel: "mandatory",
    validateResource: [
        validateResourceOfType(aws.s3.Bucket, (bucket, args, reportViolation) => {

            const parentType = 'alphaws:resources:S3Bucket'; // The type of the parent component we want to check against
            
            const parentArn = args.opts.parent; // Parent ARN in the format `urn:pulumi:${stack}::${project}::${type}::${name}`'

            if (!parentArn || !validateType(parentArn, parentType) ) {
                reportViolation(`Bucket must be a child of a '${parentArn}' component`);
            }
        }),
        validateResourceOfType(aws.s3.BucketV2, (bucket, args, reportViolation) => {
        }),
    ],
};

const validateType = (arn: string, type: string): boolean => {
    const parts = arn.split("::");
    if (parts.length < 3) {
        return false;
    }
    return parts[2] === type;
}