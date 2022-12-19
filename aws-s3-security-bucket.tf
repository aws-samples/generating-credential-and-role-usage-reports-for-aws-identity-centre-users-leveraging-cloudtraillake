resource "aws_s3_bucket" "security_bucket" {
  #checkov:skip=CKV_AWS_145: The encryption is provided through the "aws_s3_bucket_server_side_encryption_configuration" resource rather than in a direct block
  #checkov:skip=CKV_AWS_18: Access logging is disabled as this does not contain sensitive information with wide open access
  #checkov:skip=CKV_AWS_144: S3 replication is not necessary as the data can easily be rebuilt

    bucket = var.security_bucket


}

resource "aws_s3_bucket_acl" "example_bucket_acl" {
  bucket = aws_s3_bucket.security_bucket.id
  acl    = "private"
}
resource "aws_s3_bucket_public_access_block" "access_control" {
  bucket = aws_s3_bucket.security_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_bucket_encryption" {
  bucket = aws_s3_bucket.security_bucket.bucket

    rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
  }
}
resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.security_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

