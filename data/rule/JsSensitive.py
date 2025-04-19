#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/4/12

rules = {
    # "url": r'(\b|\'|")(?:http:|https:)(?:[\w/\.]+)?(?:[a-zA-Z0-9_\-\.]{1,})\.(?:php|asp|ashx|jspx|aspx|jsp|json|action|html|txt|xml|do)(\b|\'|")',
    # "email": r'[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+',
    "token_password": r'\b(?:secret|secret_key|token|secret_token|auth_token|access_token|username|password|aws_access_key_id|aws_secret_access_key|secretkey|authtoken|accesstoken|access-token|authkey|client_secret|bucket|email|HEROKU_API_KEY|SF_USERNAME|PT_TOKEN|id_dsa|clientsecret|client-secret|encryption-key|pass|encryption_key|encryptionkey|secretkey|secret-key|bearer|JEKYLL_GITHUB_TOKEN|HOMEBREW_GITHUB_API_TOKEN|api_key|api_secret_key|api-key|private_key|client_key|client_id|sshkey|ssh_key|ssh-key|privatekey|DB_USERNAME|oauth_token|irc_pass|dbpasswd|xoxa-2|xoxrprivate-key|private_key|consumer_key|consumer_secret|access_token_secret|SLACK_BOT_TOKEN|slack_api_token|api_token|ConsumerKey|ConsumerSecret|SESSION_TOKEN|session_key|session_secret|slack_token|slack_secret_token|bot_access_token|passwd|api|eid|sid|api_key|apikey|userid|user_id|user-id)["\s]*(?::|=|=:|=>)["\s]*[a-z0-9A-Z]{8,64}"?',
    # "ip": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    "cloudfront_cloud": r'[\w]+\.cloudfront\.net',
    "appspot_cloud": r'[\w\-.]+\.appspot\.com',
    "digitalocean_cloud": r'([\w\-.]*\.?digitaloceanspaces\.com\/?[\w\-.]*)',
    "google_cloud": r'(storage\.cloud\.google\.com\/[\w\-.]+)',
    "google_storage_api": r'([\w\-.]*\.?storage.googleapis.com\/?[\w\-.]*)',
    # "phone_number": '[^​\\​w]((?:(?:​\\​+|00)86)?1(?:(?:3[​\\​d])|(?:4[5-79])|(?:5[0-35-9])|(?:6[5-7])|(?:7[0-8])|(?:8[​\\​d])|(?:9[189]))​\\​d{8})[^​\\​w]​',
    # "host": r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:biz|cc|club|cn|com|co|edu|fun|group|info|ink|kim|link|live|ltd|mobi|net|online|org|pro|pub|red|ren|shop|site|store|tech|top|tv|vip|wang|wiki|work|xin|xyz|me))',
    "access Key": r'access_key.*?["\'](.*?)["\']',
    "access_key_id": r'accesskeyid.*?["\'](.*?)["\']',
    "sensitive_all_in_one": r'(((access_key|appsecret|app_secret|access_token|password|secretkey|accesskey|accesskeyid|accesskeysecret|secret_key|pwd|test_user|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_.]{0,25})(=|>|:=|:|<=|=>|:).{0,5}[\'\"\ ]([0-9a-zA-Z-_=]{12,64})[\'\"\ ])',
    "cloud_access_key": r'([\'\"\ ](GOOG[\w\W]{10,30})[\'\"\ ]|([\'\"\ ]AZ[A-Za-z0-9]{34,40}[\'\"\ ])|([\'\"\ ]AKID[A-Za-z0-9]{13,20}[\'\"\ ])|([\'\"\ ]AKIA[A-Za-z0-9]{16}[\'\"\ ])|([\'\"\ ][a-zA-Z0-9]{8}(-[a-zA-Z0-9]{4}){3}-[a-zA-Z0-9]{12}[\'\"\ ])|([\'\"\ ]OCID[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]LTAI[A-Za-z0-9]{12,20}[\'\"\ ])|([\'\"\ ][A-Z0-9]{20}$[\'\"\ ])|([\'\"\ ]JDC_[A-Z0-9]{28,32}[\'\"\ ])|([\'\"\ ]AK[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]UC[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]QY[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]AKLT[a-zA-Z0-9-_]{16,28}[\'\"\ ])|([\'\"\ ]LTC[A-Za-z0-9]{10,60}[\'\"\ ])|([\'\"\ ]YD[A-Za-z0-9]{10,60}[\'\"\ ])|([\'\"\ ]CTC[A-Za-z0-9]{10,60}[\'\"\ ])|([\'\"\ ]YYT[A-Za-z0-9]{10,60}[\'\"\ ])|([\'\"\ ]YY[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]CI[A-Za-z0-9]{10,40}[\'\"\ ])|([\'\"\ ]gcore[A-Za-z0-9]{10,30}[\'\"\ ]))',
    "jwt": r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    # "author": '@author[: ]+(.*?) ',
    'google_api'     : r'AIza[0-9A-Za-z-_]{35}',
    'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url1' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2' : r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    "amazon_aws_url3": r'[\w\-.]*s3[\w\-.]*\.?amazonaws\.com\/?[\w\-.]*',
    "authorization_header": r"​((basic [a-z0-9=:_​\\​+​\\​/-]{5,100})|(bearer [a-z0-9_.=:_​\\​+​\\​/-]{5,100}))​", 
    'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    # 'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    # 'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    # 'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
    # 'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
    # 'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
    # 'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    # 'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    # 'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    # 'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    # 'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'​(eyJ[A-Za-z0-9_-]{10,}​\\​.[A-Za-z0-9._-]{10,}|eyJ[A-Za-z0-9_​\\​/+-]{10,}​\\​.[A-Za-z0-9._​\\​/+-]{10,})',
    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'ssh_privkey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'heroku_api_key' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_creds' : r"(" \
                    r"password\s*[`=:\"]+\s*[^\s]+|" \
                    r"password is\s*[`=:\"]*\s*[^\s]+|" \
                    r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                    r"passwd\s*[`=:\"]+\s*[^\s]+)",
    '​java_deserialization​' : r"​(javax​\\​.faces​\\​.ViewState)​", 
    'jdbc' : r"jdbc:(mysql|h2|oracle|sqlserver|jtds:sqlserver):|System\.Data\.SqlClient|Data\.PassportContext|mysql\.username|mysql\.password|mysql\.url|jdbc\.username|jdbc\.password|mssql\.jdbc|mssql\.user|com\.microsoft\.sqlserver\.jdbc\.SQLServerDriver",
    'init_password' : r"​(initPassword​\\​s*[:=]​\\​s*​\"​?|​\"​initPassword​\"\\​s*:​\\​s*​\"​?|​\"​初始密码​\"\\​s*:​\\​s*​\"​?)[​\"​]?[^​\"\\​s]+[​\"​]?|​\\​b初始密码是​\\​s+[^​\"\\​s]+​",
}