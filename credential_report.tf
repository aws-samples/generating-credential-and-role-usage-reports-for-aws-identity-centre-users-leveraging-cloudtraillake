data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
locals {
    account_id = data.aws_caller_identity.current.account_id
    region = data.aws_region.current.name
}



data "aws_iam_policy_document" "AWSLambdaTrustPolicy" {
  statement {
    actions    = ["sts:AssumeRole"]
    effect     = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}



resource "aws_lambda_function" "terraform_lambda_func" {
#checkov:skip=CKV_AWS_50: Not a requirement
#checkov:skip=CKV_AWS_117: No resources to be accessed within the VPC and only interacting with the AWS API. 
#checkov:skip=CKV_AWS_116: Not a requirement
#checkov:skip=CKV_AWS_115: Not a requirement
#checkov:skip=CKV_AWS_173: No sensitive information within the environment variable

  filename      = "my-deployment-package.zip"
  function_name = "iam_credential_report"
  role          = aws_iam_role.sso_credential_report_role.arn
  handler       = "credential-report-id-store.lambda_handler"
  runtime       = "python3.9"
  timeout       = 600
  environment {
    variables = {
      bucket_name = var.security_bucket
      identity_source = var.identity_source
      identity_store_arn = var.identity_store_arn
      lake_id= var.lake_id
    }

  }
}



data "aws_iam_policy_document" "iam_policy_for_credential_report"{
  statement{
    actions = ["logs:CreateLogGroup"]
    effect  = "Allow"
    resources = ["arn:aws:logs:${local.region}:${local.account_id}:*"]
  }
  statement{
    actions = ["logs:CreateLogStream",
                "logs:PutLogEvents"]
    effect  = "Allow"
    resources = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/iam_credential_report:*"]
  }

  statement{
    actions = [ "sso-directory:Search*",
                "sso-directory:Describe*",
                "ds:DescribeDirectories",
                "sso-directory:List*",
                "sso:ListPermissionSets",
                "sso:DescribePermissionSet",
                "sso:ListAccountsForProvisionedPermissionSet",
                "sso-directory:Get*",
                "identitystore:Describe*",
                "identitystore:List*",
                "sso:ListAccountAssignments"]
    effect  = "Allow"
    resources = ["*"]
  }
  statement{
    actions = [ "iam:GenerateCredentialReport",
                "iam:GenerateServiceLastAccessedDetails",
                "iam:Get*",
                "iam:List*",
                "iam:SimulateCustomPolicy",
                "iam:SimulatePrincipalPolicy"]
     effect  = "Allow"
    resources = ["*"]
  }
  statement{
    actions = [ "cloudtrail:Get*",
                "cloudtrail:Describe*",
                "cloudtrail:List*",
                "cloudtrail:LookupEvents",
                "cloudtrail:StartQuery"]
    effect  = "Allow"
    resources = ["*"]
  }

   statement {
    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl"
    ]

     resources = [
      "arn:aws:s3:::${var.security_bucket}/*",
    ]
  }

}

resource "aws_iam_role" "sso_credential_report_role" {
  name               = "sso_credential_report_role"
  assume_role_policy = data.aws_iam_policy_document.AWSLambdaTrustPolicy.json
}

resource "aws_iam_role_policy_attachment" "terraform_lambda_policy" {
  role       = aws_iam_role.sso_credential_report_role.name
  policy_arn = aws_iam_policy.iam_policy_for_cred_report.arn
}


resource "aws_iam_policy" "iam_policy_for_cred_report" {
 name         = "iam_policy_for_iam_sso_credentials"
 path         = "/"
 description  = "AWS IAM Policy for managing aws lambda role to generate the report"
 policy = data.aws_iam_policy_document.iam_policy_for_credential_report.json
}


resource "aws_cloudwatch_event_rule" "profile_generator_lambda_event_rule" {
  name = "profile-generator-lambda-event-rule"
  description = "Run every sunday at 8 pm"
  schedule_expression = "cron(0 20 * ? 7 *)"
}

resource "aws_cloudwatch_event_target" "profile_generator_lambda_target" {
  arn = aws_lambda_function.terraform_lambda_func.arn
  rule = aws_cloudwatch_event_rule.profile_generator_lambda_event_rule.name
}

resource "aws_lambda_permission" "allow_cloudwatch_to_call_rw_fallout_retry_step_deletion_lambda" {
  statement_id = "AllowExecutionFromCloudWatch"
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.terraform_lambda_func.function_name
  principal = "events.amazonaws.com"
  source_arn = aws_cloudwatch_event_rule.profile_generator_lambda_event_rule.arn
}


