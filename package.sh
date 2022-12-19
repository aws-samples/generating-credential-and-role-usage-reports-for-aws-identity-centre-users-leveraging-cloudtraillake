#!/usr/bin/env sh
pip3.9 install boto3 --target ./package
7z a my-deployment-package.zip credential-report-id-store.py
7z a my-deployment-package.zip ./package/*