import boto3
import csv
import logging
import re
import time
import os
import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)
ids_client = boto3.client('identitystore', region_name='ap-southeast-1')
SLEEP = 3
ct_client = boto3.client('cloudtrail', 'ap-southeast-1')
directory_client = boto3.client('ds', region_name='ap-southeast-1')
sso_admin_client = boto3.client('sso-admin', region_name='ap-southeast-1')
LIST_PAGE_SIZE = 50
id_store = directory_client.describe_directories()


def _check_uuid(uuid):
    return bool(re.fullmatch("^[a-f0-9\-]+$", uuid))


def _get_results(lake_id, query_id):
    results = ct_client.get_query_results(EventDataStore=lake_id, QueryId=query_id, MaxQueryResults=1)
    status = results['QueryStatus']
    if status in ['QUEUED', 'RUNNING']:
        time.sleep(SLEEP)
        _get_results(lake_id, query_id)
    elif status in ['FINISHED']:
        query_results = results['QueryResultRows']
        while 'NextToken' in results:
            results = ct_client.get_query_results(EventDataStore=lake_id, QueryId=query_id, MaxQueryResults=1,
                                                  NextToken=results['NextToken'])
            query_results = query_results + results['QueryResultRows']
        return query_results
    else:
        raise


def query_and_get_results(lake_id, query):
    if _check_uuid(lake_id):
        query_id = ct_client.start_query(QueryStatement=query)['QueryId']
        time.sleep(SLEEP)
        results = _get_results(lake_id, query_id)
        return results
    else:
        raise Exception("UUID contains illegal characters")


def query_last_login(lake_id):
    query = "SELECT userIdentity.principalId, userIdentity.accountId, userIdentity.userName, max(eventtime) as last_login,  serviceEventDetails FROM " + lake_id + "  where  eventname like 'UserAuthentication' group by userIdentity.principalId, userIdentity.accountId, userIdentity.userName, serviceEventDetails "
    return query_and_get_results(lake_id, query)



def get_last_role_login_for_users_list(lake_id):
    def _parse_role(serviceEventDetails):
        left,right = serviceEventDetails.split(',')
        role = left.split('=')[1].strip()
        account_id = right.split('=')[1].strip('}')
        return  (role,account_id)
    role_login_list = []
    query = "SELECT userIdentity.principalId, userIdentity.accountId, userIdentity.userName, max(eventtime) as last_login, eventtype, eventName, serviceEventDetails FROM " + lake_id + " WHERE userIdentity.username != ''and eventName like 'Federate' group by userIdentity.principalId, userIdentity.accountId, userIdentity.userName, eventtype,eventname,serviceEventDetails"
    results = query_and_get_results(lake_id, query)
    account_dict = {}
    for row in results:
        role_name, account_id = _parse_role(row[6]['serviceEventDetails'])
        last_login = row[3]['last_login']
        hash_object =  (account_id,row[2]['username'],role_name)
        account_dict[hash_object] = last_login
    return account_dict

def get_user_list(identity_source):
    user_list = []
    paginator = ids_client.get_paginator("list_users")
    user_iterator = paginator.paginate(IdentityStoreId=identity_source, PaginationConfig={"PageSize": LIST_PAGE_SIZE})
    for users in user_iterator:
        user_list.append(users['Users'])
    return user_list


def get_group_list(identity_source):
    group_dict = {}
    paginator = ids_client.get_paginator("list_groups")
    group_iterator = paginator.paginate(IdentityStoreId=identity_source, PaginationConfig={"PageSize": LIST_PAGE_SIZE})
    for groups in group_iterator:
        group_list = groups['Groups']
        for group in group_list:
            group_dict[group['GroupId']] = group
    return group_dict


def _list_permission_sets(identity_store_arn):
    permission_sets = []
    paginator = sso_admin_client.get_paginator('list_permission_sets')
    permission_set_iterator = paginator.paginate(InstanceArn=identity_store_arn,
                                                 PaginationConfig={"PageSize": LIST_PAGE_SIZE})
    for permission_set in permission_set_iterator:
        permission_sets = permission_sets + permission_set['PermissionSets']
    return permission_sets


def list_accounts_for_provisioned_permission_sets(identity_store_arn):
    permission_sets_account_dict = {}
    permission_sets_list = _list_permission_sets(identity_store_arn)
    for permission_set_arn in permission_sets_list:
        paginator = sso_admin_client.get_paginator('list_accounts_for_provisioned_permission_set')
        permission_set_iterator = paginator.paginate(InstanceArn=identity_store_arn,
                                                     PermissionSetArn=permission_set_arn,
                                                     PaginationConfig={"PageSize": LIST_PAGE_SIZE})
        for account in permission_set_iterator:
            permission_sets_account_dict[permission_set_arn] = {'AccountIds': account['AccountIds'], 'PermissionSet':
                sso_admin_client.describe_permission_set(InstanceArn=identity_store_arn,
                                                         PermissionSetArn=permission_set_arn)['PermissionSet']}
    return permission_sets_account_dict


def list_account_assignments(permission_sets_account_dict,identity_store_arn):
    assignment_list = []
    for permission_set_arn in permission_sets_account_dict.keys():
        accounts = permission_sets_account_dict[permission_set_arn]['AccountIds']
        for account in accounts:
            paginator = sso_admin_client.get_paginator('list_account_assignments')
            assignment_iterator = paginator.paginate(InstanceArn=identity_store_arn,
                                                     AccountId=account, PermissionSetArn=permission_set_arn,
                                                     PaginationConfig={"PageSize": LIST_PAGE_SIZE})

            for assignment in assignment_iterator:
                assignment_list = assignment_list + assignment['AccountAssignments']
    return assignment_list


def get_users_permissions_per_group(group_list, identity_source):
    user_per_group_dict = {}
    for group_key in group_list.keys():
        user_per_group_dict[group_key] = []
        paginator = ids_client.get_paginator("list_group_memberships")
        group_membership_iterator = paginator.paginate(GroupId=group_key, IdentityStoreId=identity_source,
                                                       PaginationConfig={"PageSize": LIST_PAGE_SIZE})
        for member in group_membership_iterator:
            member_list = member['GroupMemberships']
            for member_dict in member_list:
                user_info = ids_client.describe_user(UserId=member_dict['MemberId']['UserId'],
                                                     IdentityStoreId=identity_source)
                user_info.pop('ResponseMetadata')
                user_per_group_dict[group_key].append(user_info)
    return user_per_group_dict

def _get_last_login(account_id, username, permission_set, last_login):
    hash_obj = (account_id, username, permission_set)
    if hash_obj in last_login.keys():
        return last_login[hash_obj]
    else:
        return 'NO_LOGIN_PRESENT'

def _csv_row_list_creator(account_list, permission_sets, users_per_group_dict, group_list, identity_source, last_login):
    row_list = []
    for account in account_list:
        account_id = account['AccountId']
        permission_set_arn = account['PermissionSetArn']
        type = account['PrincipalType']
        principal_id = account['PrincipalId']
        permission_set_name = permission_sets[account['PermissionSetArn']]['PermissionSet']['Name']
        try:
            permission_set_description = permission_sets[account['PermissionSetArn']]['PermissionSet']['Description']
        except KeyError as e:
            logger.info("No description exists for permission set: %s" % permission_set_arn)
            permission_set_description = 'DESCRIPTION NOT SET'
        row = [account_id, permission_set_arn, permission_set_name, permission_set_description, type]
        if type == "GROUP":
            user_list = users_per_group_dict[principal_id]
            group_name = group_list[principal_id]['DisplayName']
            for user in user_list:
                user_row = [principal_id, group_name, user['UserName'], user['UserId'], _get_last_login(account_id,user['UserName'],permission_set_name, last_login)]
                row_list.append([*row, *user_row])
        elif type == "USER":
            user = ids_client.describe_user(IdentityStoreId=identity_source, UserId=principal_id)
            user_row = [principal_id, "NOGROUP", user['UserName'], user['UserId'], _get_last_login(account_id,user['UserName'],permission_set_name, last_login)]
            row_list.append([*row, *user_row])
        else:
            logger.error("Unknown type %s" % type)
    row_list.sort(key=lambda x: x[0])
    return row_list

def write_login_csv(results):
    header = ['user_name','last_login_succesful']
    with open('last_login.csv', 'w') as FILE:
        csv_writer = csv.writer(FILE, delimiter=',')
        csv_writer.writerow(header)
        for user in results:
            csv_writer.writerow((user[2]['username'],user[3]['last_login']))

def _file_name_generator():
    now = datetime.datetime.now()
    dt_string = now.strftime("%d.%m.%Y.%H%M%S")
    return 'credential_report'+dt_string+'.csv'




def write_accounts_csv(file_name, account_list, permission_sets, users_per_group_dict, group_list, identity_source, last_login, bucket):
    header = ['account', 'PermissionSetArn', 'PermissionSetName', 'PermissionSetDescription', 'Type', 'GroupId',
              'GroupName', 'Username', 'UserId','LastLogin']
    path = '/tmp/' + file_name
    with open(path, 'w') as FILE:
        csv_writer = csv.writer(FILE, delimiter=',')
        csv_writer.writerow(header)
        csv_writer.writerows(
            _csv_row_list_creator(account_list, permission_sets, users_per_group_dict, group_list, identity_source, last_login))
        FILE.close()
    s3 = boto3.client('s3')
    s3.upload_file(path, bucket, 'credential_reports/'+file_name)

def lambda_handler(event, context):
    identity_source = os.environ["identity_source"]
    identity_store_arn = os.environ["identity_store_arn"]
    lake_id = os.environ["lake_id"]
    bucket = os.environ['bucket_name']
    permission_sets = list_accounts_for_provisioned_permission_sets(identity_store_arn)
    account_lists = list_account_assignments(permission_sets, identity_store_arn)
    group_list = (get_group_list(identity_source))
    users_per_group_dict = get_users_permissions_per_group(group_list, identity_source)
    last_login = get_last_role_login_for_users_list(lake_id)
    write_accounts_csv(_file_name_generator(),account_lists, permission_sets, users_per_group_dict, group_list, identity_source, last_login,bucket)
    return "done"



