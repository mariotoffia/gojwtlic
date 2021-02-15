import * as cdk from '@aws-cdk/core';
import * as kms from '@aws-cdk/aws-kms';
import * as iam from '@aws-cdk/aws-iam';
import {CfnOutput} from '@aws-cdk/core'

export class CdkStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const defaultPolicy = new iam.PolicyStatement({
      resources: ['*'],
      actions: ['kms:*'],
      principals: [new iam.AccountRootPrincipal()],
    });

    const signingKey = new kms.CfnKey(this, 'license-key', {
      description: "Key to sign licenses with",
      keyPolicy: defaultPolicy,
      enableKeyRotation: false,
      keyUsage: "SIGN_VERIFY",
      keySpec: "ECC_NIST_P384",
      enabled: true,
      tags: [
        {key: "keytype", value: "ECC384"},
        {key:"masterkey", value:"true"}
      ]
    });

    new CfnOutput(this, 'license-key', {
      exportName: 'license-ley',
      value: signingKey.attrArn,
    });
  }
}
