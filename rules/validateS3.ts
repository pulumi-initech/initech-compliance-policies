import * as aws from "@pulumi/aws";
import { StackValidationPolicy, validateStackResourcesOfType } from "@pulumi/policy";

export const s3BucketLoggingEnabled: StackValidationPolicy = {
    name: "s3-bucket-logging-enabled",
    description: "Checks whether logging is enabled for your S3 buckets.",
    enforcementLevel: "mandatory",
    validateStack: validateStackResourcesOfType(aws.s3.Bucket, (buckets, args, reportViolation) => {
        // First, save any bucket IDs that are being used as logging targets.
        const logBucketIDs: Set<string> = new Set();
        for (const bucket of buckets) {
            if (bucket.loggings) {
                for (const logging of bucket.loggings) {
                    if (logging.targetBucket) {
                        logBucketIDs.add(logging.targetBucket);
                    }
                }
            }
        }

        // Then, check the buckets for violations.
        for (const bucket of buckets) {
            // Skip any buckets not provisioned (i.e., during previews).
            if (!bucket.id) {
                continue;
            }
            // If the bucket doesn't have any loggings and the bucket itself isn't being used as
            // a log target, it's in violation of the policy.
            if (!bucket.loggings || bucket.loggings.length === 0) {
                if (!logBucketIDs.has(bucket.id)) {
                    // Report and associate the violation with the non-compliant bucket resource.
                    reportViolation("Bucket logging must be defined.", bucket.arn);
                }
            }
        }
    }),
};