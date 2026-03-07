PATTERNS = {
    # === AWS ===
    "AWS Access Key": (r"\bAKIA[0-9A-Z]{16}\b", 9, "api_key"),
    "AWS Secret Key": (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", 9, "api_secret"),
    "AWS Session Token": (r"\bAWS[0-9A-Za-z/+]{40,}\b", 8, "session_token"),
    "AWS Cognito Identity Pool": (r"\b[a-z]{2}_[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}\b", 6, "identity_pool"),
    "AWS Cognito Client ID": (r"\b[a-z0-9]{32}\b", 5, "client_id"),
    "AWS Cognito Secret": (r"(?i)cognito[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9/+]{40}['\"]?", 8, "api_secret"),
    "AWS AppSync GraphQL Key": (r"\bda2-[a-z0-9]{26}\b", 7, "api_key"),
    
    # === GitHub ===
    "GitHub Token": (r"\bghp_[a-zA-Z0-9]{36}\b", 9, "api_token"),
    "GitHub OAuth": (r"\bgho_[a-zA-Z0-9]{36}\b", 8, "oauth_token"),
    "GitHub App Token": (r"\bghs_[a-zA-Z0-9]{36}\b", 8, "app_token"),
    "GitHub Fine-grained Token": (r"\bgithub_pat_[A-Za-z0-9_]{80,}\b", 9, "api_token"),
    "GitHub User Token": (r"\bghu_[A-Za-z0-9]{36}\b", 8, "api_token"),
    "GitHub Refresh Token": (r"\bghr_[A-Za-z0-9]{36,}\b", 8, "api_token"),
    "GitHub SSH Key": (r"ssh-rsa [A-Za-z0-9+/]+[=]{0,3}(?: [^,\n]+)?", 7, "ssh_key"),
    "GitHub Deployment Token": (r"\bghd_[A-Za-z0-9]{36}\b", 8, "deployment_token"),
    
    # === Google ===
    "Google API Key": (r"\bAIza[0-9A-Za-z\-_]{35,39}\b", 8, "api_key"),
    "Google OAuth": (r"\b[0-9]+-[0-9A-Za-z_]{22,}\.apps\.googleusercontent\.com\b", 7, "oauth_client"),
    "Google Cloud Service Account": (r'"type"\s*:\s*"service_account"', 6, "service_account"),
    "Google Cloud Private Key ID": (r"(?i)private_key_id\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", 8, "private_key_id"),
    "Google Cloud Private Key": (r"(?i)private_key\s*[=:]\s*['\"]?-----BEGIN PRIVATE KEY-----", 9, "private_key"),
    "Google reCAPTCHA Secret": (r"(?i)recaptcha[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{40}['\"]?", 7, "api_secret"),
    "Google Firebase Database URL": (r"https://[a-z0-9-]+\.firebaseio\.com", 6, "database_url"),
    "Google GA4 Measurement ID": (r"\bG-[A-Z0-9]{10}\b", 5, "measurement_id"),
    "Google Universal Analytics ID": (r"\bUA-\d{4,}-\d{1,}\b", 5, "analytics_id"),
    
    # === Microsoft Azure ===
    "Azure Storage Account Key": (r"(?i)accountkey\s*[=:]\s*['\"]?[a-zA-Z0-9+/=]{88}['\"]?", 8, "storage_key"),
    "Azure Storage Connection String": (r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+", 9, "connection_string"),
    "Azure SAS Token": (r"\?sv=\d{4}-\d{2}-\d{2}&sig=[a-zA-Z0-9%]+", 7, "sas_token"),
    "Azure Client Secret": (r"(?i)azure[_-]?client[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_~./-]{20,}['\"]?", 8, "client_secret"),
    "Azure Tenant ID": (r"(?i)azure[_-]?tenant[_-]?id\s*[=:]\s*['\"]?[a-f0-9-]{36}['\"]?", 6, "tenant_id"),
    "Azure Subscription ID": (r"(?i)subscription[_-]?id\s*[=:]\s*['\"]?[a-f0-9-]{36}['\"]?", 7, "subscription_id"),
    "Azure AD Application ID": (r"(?i)application[_-]?id\s*[=:]\s*['\"]?[a-f0-9-]{36}['\"]?", 6, "application_id"),
    "Azure DevOps PAT": (r"\b[a-z0-9]{52}\b", 8, "personal_access_token"),
    "Azure Function Key": (r"(?i)function[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9]{32,}['\"]?", 7, "function_key"),
    
    # === Cloudflare ===
    "Cloudflare API Key": (r"\b[a-f0-9]{37}\b", 7, "api_key"),
    "Cloudflare Global API Key": (r"(?i)cloudflare[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-f0-9]{37}['\"]?", 8, "api_key"),
    "Cloudflare Origin CA Key": (r"\bv1\.[A-Za-z0-9_-]{43,}\b", 8, "origin_ca_key"),
    "Cloudflare Tunnel Secret": (r"(?i)tunnel[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{40,}['\"]?", 8, "tunnel_secret"),
    
    # === Slack ===
    "Slack Token": (r"\bxox[bpoa]-[0-9a-zA-Z\-]{10,48}\b", 8, "api_token"),
    "Slack Webhook URL": (r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}", 8, "webhook"),
    "Slack App Token": (r"\bxapp-[0-9A-Za-z\-]{100,}\b", 8, "app_token"),
    "Slack Signing Secret": (r"(?i)slack[_-]?signing[_-]?secret\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", 8, "signing_secret"),
    "Slack Bot Token": (r"\bxoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}\b", 8, "bot_token"),
    
    # === Stripe ===
    "Stripe Secret Key": (r"\bsk_live_[0-9a-zA-Z]{24,}\b", 9, "api_secret"),
    "Stripe Publishable Key": (r"\bpk_live_[0-9a-zA-Z]{24,}\b", 5, "api_key"),
    "Stripe Test Secret Key": (r"\bsk_test_[0-9a-zA-Z]{24,}\b", 4, "api_secret"),
    "Stripe Restricted API Key": (r"\bsk_live_[0-9a-zA-Z]{24,}_[0-9a-zA-Z]{24,}\b", 9, "restricted_api_key"),
    "Stripe Webhook Secret": (r"(?i)stripe[_-]?webhook[_-]?secret\s*[=:]\s*['\"]?whsec_[a-zA-Z0-9]{32,}['\"]?", 8, "webhook_secret"),
    
    # === Twilio ===
    "Twilio Account SID": (r"\bAC[a-zA-Z0-9]{32}\b", 7, "account_id"),
    "Twilio Auth Token": (r"\b[a-f0-9]{32}\b", 3, "api_secret"),
    "Twilio API Key": (r"\bSK[0-9a-fA-F]{32}\b", 8, "api_key"),
    "Twilio Access Token": (r"\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b", 7, "access_token"),
    
    # === OpenAI / Anthropic ===
    "OpenAI API Key": (r"\bsk-(?:proj|org)-[A-Za-z0-9_-]{20,}\b|\bsk-[A-Za-z0-9]{40,}\b", 9, "api_key"),
    "Anthropic API Key": (r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", 9, "api_key"),
    "Anthropic Session Token": (r"\bsk-ant-sess-[A-Za-z0-9_-]{20,}\b", 8, "session_token"),
    "OpenAI Organization ID": (r"\borg-[A-Za-z0-9]{28,}\b", 6, "org_id"),
    "OpenAI Project ID": (r"\bproj-[A-Za-z0-9]{28,}\b", 6, "project_id"),
    
    # === GitLab ===
    "GitLab Token": (r"\bglpat-[A-Za-z0-9_-]{20,}\b", 8, "api_token"),
    "GitLab Runner Token": (r"\bGR1348941[a-zA-Z0-9_-]{20,}\b", 7, "runner_token"),
    "GitLab Feed Token": (r"\bfeed_token=[a-zA-Z0-9_-]{20,}\b", 6, "feed_token"),
    
    # === Hugging Face ===
    "Hugging Face Token": (r"\bhf_[A-Za-z0-9]{30,}\b", 7, "api_token"),
    "Hugging Face Organization Token": (r"\bhf_org_[A-Za-z0-9]{30,}\b", 7, "org_token"),
    
    # === npm / PyPI ===
    "npm Access Token": (r"\bnpm_[A-Za-z0-9]{36}\b", 7, "api_token"),
    "npm Auth Token Config": (r"//registry\.npmjs\.org/:_authToken\s*=\s*[A-Za-z0-9_-]{20,}", 7, "api_token"),
    "PyPI API Token": (r"\bpypi-[A-Za-z0-9_-]{50,}\b", 8, "api_token"),
    "PyPI Legacy Token": (r"\bpypi-[A-Za-z0-9]{50,}\b", 7, "legacy_token"),
    
    # === Shopify ===
    "Shopify Access Token": (r"\bshpat_[a-fA-F0-9]{32}\b", 8, "api_token"),
    "Shopify Custom Access Token": (r"\bshpca_[a-fA-F0-9]{32}\b", 8, "custom_token"),
    "Shopify Shared Secret": (r"(?i)shopify[_-]?shared[_-]?secret\s*[=:]\s*['\"]?[a-fA-F0-9]{32}['\"]?", 8, "shared_secret"),
    "Shopify Store URL": (r"https://[a-z0-9-]+\.myshopify\.com", 5, "store_url"),
    
    # === DigitalOcean ===
    "DigitalOcean API Token": (r"\bdop_v1_[A-Za-z0-9]{40,}\b", 8, "api_token"),
    "DigitalOcean OAuth Token": (r"\bdo_v1_[A-Za-z0-9]{64}\b", 8, "oauth_token"),
    "DigitalOcean Spaces Key": (r"\b[A-Z0-9]{20}\b", 6, "spaces_key"),
    
    # === Linear ===
    "Linear API Key": (r"\blin_api_[A-Za-z0-9]{20,}\b", 7, "api_key"),
    "Linear Webhook Secret": (r"(?i)linear[_-]?webhook[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "webhook_secret"),
    
    # === Notion ===
    "Notion Secret Token": (r"\bsecret_[A-Za-z0-9]{40,}\b", 7, "api_token"),
    "Notion Integration Token": (r"\bsecret_[a-zA-Z0-9]{43}\b", 8, "integration_token"),
    
    # === Postman ===
    "Postman API Key": (r"\bPMAK-[A-Za-z0-9\-]{24,}\b", 7, "api_key"),
    "Postman Collection Token": (r"\bPMAT-[A-Za-z0-9\-]{24,}\b", 7, "collection_token"),
    
    # === Discord ===
    "Discord Bot Token": (r"\b(?:[MN][A-Za-z0-9_-]{23}|[A-Za-z0-9_-]{24})\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b", 8, "bot_token"),
    "Discord Webhook URL": (r"https://(?:discord(?:app)?\.com)/api/webhooks/\d{17,20}/[A-Za-z0-9._-]{40,}", 8, "webhook"),
    "Discord Client Secret": (r"(?i)discord[_-]?client[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "client_secret"),
    
    # === Dropbox ===
    "Dropbox Access Token": (r"\bsl\.[A-Za-z0-9_-]{80,}\b", 8, "api_token"),
    "Dropbox App Key": (r"(?i)dropbox[_-]?app[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9]{15}['\"]?", 6, "app_key"),
    "Dropbox App Secret": (r"(?i)dropbox[_-]?app[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9]{15}['\"]?", 7, "app_secret"),
    
    # === Asana ===
    "Asana Access Token": (r"\b(?:0|1)/[0-9a-f]{32}\b", 7, "api_token"),
    "Asana Personal Access Token": (r"(?i)asana[_-]?token\s*[=:]\s*['\"]?[0-9/]+['\"]?", 7, "personal_token"),
    
    # === Sentry ===
    "Sentry Auth Token": (r"\bsntrys_[A-Za-z0-9]{32,}\b", 8, "api_token"),
    "Sentry DSN": (r"https://[a-f0-9]+@[a-f0-9]+\.sentry\.io/\d+", 7, "dsn"),
    "Sentry Org Slug": (r"(?i)sentry[_-]?org\s*[=:]\s*['\"]?[a-zA-Z0-9_-]+['\"]?", 5, "org_slug"),
    
    # === Mailchimp / Brevo / SendGrid / Mailgun ===
    "Mailchimp API Key": (r"\b[0-9a-f]{32}-us\d{1,2}\b", 7, "api_key"),
    "Brevo API Key": (r"\bxkeysib-[A-Za-z0-9_-]{40,}\b", 8, "api_key"),
    "SendGrid API Key": (r"\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43,}\b", 9, "api_key"),
    "Mailgun API Key": (r"\bkey-[a-zA-Z0-9]{32}\b", 7, "api_key"),
    "Mailgun Domain": (r"(?i)mailgun[_-]?domain\s*[=:]\s*['\"]?[a-zA-Z0-9.-]+\.(mailgun\.org|mg\.eu\.mailgun\.com)['\"]?", 6, "domain"),
    
    # === Datadog ===
    "Datadog API Key": (r"(?i)dd(?:og)?[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", 7, "api_key"),
    "Datadog Application Key": (r"(?i)dd(?:og)?[_-]?(?:app|application)[_-]?key\s*[=:]\s*['\"]?[a-f0-9]{40}['\"]?", 7, "api_key"),
    "Datadog Client Token": (r"\bpub[0-9a-f]{32}\b", 6, "client_token"),
    
    # === Mapbox ===
    "Mapbox Secret Token": (r"\bsk\.[A-Za-z0-9]{20,}\.[A-Za-z0-9_-]{20,}\b", 8, "api_token"),
    "Mapbox Public Token": (r"\bpk\.[A-Za-z0-9]{20,}\.[A-Za-z0-9_-]{20,}\b", 5, "api_key"),
    "Mapbox Default Token": (r"\bpk\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]{20,}\b", 6, "default_token"),
    
    # === Firebase ===
    "Firebase Server Key": (r"\bAAAA[A-Za-z0-9_-]{7,}:[A-Za-z0-9_-]{100,}\b", 8, "api_key"),
    "Firebase Database URL": (r"https://[a-z0-9-]+\.firebaseio\.com", 6, "database_url"),
    "Firebase Project ID": (r"(?i)firebase[_-]?project[_-]?id\s*[=:]\s*['\"]?[a-z0-9-]+['\"]?", 5, "project_id"),
    
    # === Heroku ===
    "Heroku API Key": (r"(?i)heroku[_-]?api[_-]?key\s*[=:]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]?", 7, "api_key"),
    "Heroku OAuth Token": (r"(?i)heroku[_-]?token\s*[=:]\s*['\"]?[0-9a-f-]{36}['\"]?", 7, "oauth_token"),
    
    # === Pulumi / Vercel / Netlify ===
    "Pulumi Access Token": (r"\bpul-[A-Za-z0-9_-]{30,}\b", 8, "api_token"),
    "Vercel Token": (r"\bvercel_[A-Za-z0-9]{24,}\b", 7, "api_token"),
    "Netlify Access Token": (r"\bnfp_[A-Za-z0-9]{24,}\b", 7, "api_token"),
    "Netlify Site ID": (r"(?i)netlify[_-]?site[_-]?id\s*[=:]\s*['\"]?[a-f0-9-]{36}['\"]?", 6, "site_id"),
    
    # === Terraform / Atlas ===
    "Terraform Cloud Token": (r"\batlasv1\.[A-Za-z0-9_-]{40,}\b", 8, "api_token"),
    "Terraform Enterprise Token": (r"(?i)tfe[_-]?token\s*[=:]\s*['\"]?[A-Za-z0-9_-]{40,}['\"]?", 8, "enterprise_token"),
    
    # === Airtable ===
    "Airtable Personal Access Token": (r"\bpat[A-Za-z0-9]{14}\.[A-Za-z0-9]{20,}\b", 7, "api_token"),
    "Airtable API Key": (r"\bkey[A-Za-z0-9]{14}\b", 6, "api_key"),
    "Airtable Base ID": (r"\bapp[A-Za-z0-9]{14}\b", 5, "base_id"),
    
    # === Docker ===
    "Docker Hub Personal Access Token": (r"\bdckr_pat_[A-Za-z0-9_-]{20,}\b", 7, "api_token"),
    "Docker Registry Token": (r"\b[A-Za-z0-9_-]{64,}\.[A-Za-z0-9_-]{64,}\.[A-Za-z0-9_-]{64,}\b", 7, "registry_token"),
    
    # === Telegram / Yandex / VK / Russian services ===
    "Telegram Bot Token": (r"\b\d{8,10}:[A-Za-z0-9_-]{33,}\b", 8, "bot_token"),
    "Telegram API ID": (r"(?i)telegram[_-]?api[_-]?id\s*[=:]\s*['\"]?\d{5,10}['\"]?", 6, "api_id"),
    "Telegram API Hash": (r"(?i)telegram[_-]?api[_-]?hash\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", 7, "api_hash"),
    "Telegram Webhook URL": (r"https://api\.telegram\.org/bot\d+:[A-Za-z0-9_-]{33,}/setWebhook", 8, "webhook"),
    
    # === Yandex ===
    "Yandex Cloud OAuth Token": (r"\bt1\.[A-Za-z0-9_-]{128,}\b", 9, "oauth_token"),
    "Yandex Cloud IAM Token": (r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.t1\.[A-Za-z0-9_-]{64,}\b", 9, "iam_token"),
    "Yandex Cloud Service Account Key": (r"\bAQ[A-Za-z0-9_-]{38,}\b", 8, "service_account_key"),
    "Yandex Cloud API Key": (r"\bAQVN[A-Za-z0-9_-]{38,}\b", 8, "api_key"),
    "Yandex OAuth Token": (r"\byandex[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "oauth_token"),
    "Yandex API Key": (r"(?i)yandex[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Yandex Passport Token": (r"\bysu_[A-Za-z0-9_-]{32,}\b", 8, "passport_token"),
    "Yandex Tracker Token": (r"(?i)tracker[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "tracker_token"),
    "Yandex Metrica ID": (r"(?i)ym\(\d+\)", 5, "metrica_id"),
    "Yandex Direct API Token": (r"(?i)direct[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "direct_token"),
    "Yandex SpeechKit Key": (r"(?i)speechkit[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "speechkit_key"),
    "Yandex Translate API Key": (r"(?i)translate[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "translate_key"),
    "Yandex Maps API Key": (r"(?i)maps[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "maps_key"),
    "Yandex Disk Token": (r"(?i)disk[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "disk_token"),
    "Yandex Music Token": (r"(?i)music[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "music_token"),
    
    # === VK (VKontakte) ===
    "VK API Access Token": (r"\bvk[a-z0-9]{10,}[A-Za-z0-9_-]{10,}\b", 7, "api_token"),
    "VK API User Token": (r"(?i)vk_token\s*[=:]\s*['\"]?[a-f0-9]{40}['\"]?", 6, "user_token"),
    "VK API Service Token": (r"(?i)vk_api\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 7, "service_token"),
    "VK API Client Secret": (r"(?i)vk[_-]?client[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "client_secret"),
    "VK API Service Key": (r"(?i)vk[_-]?service[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "service_key"),
    "VK Group Token": (r"(?i)group[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "group_token"),
    "VK Community Token": (r"(?i)community[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "community_token"),
    "VK App ID": (r"(?i)vk[_-]?app[_-]?id\s*[=:]\s*['\"]?\d{5,10}['\"]?", 5, "app_id"),
    "VK Callback URL Secret": (r"(?i)vk[_-]?callback[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{16,}['\"]?", 6, "callback_secret"),
    
    # === Cloud.ru (SberCloud) ===
    "Cloud.ru API Token": (r"\bcrp_[a-zA-Z0-9_-]{32,}\b", 8, "api_token"),
    "Cloud.ru Service Account": (r"\bcrsa_[a-zA-Z0-9_-]{32,}\b", 8, "service_account"),
    "Cloud.ru IAM Token": (r"\bcriam_[a-zA-Z0-9_-]{64,}\b", 8, "iam_token"),
    "Cloud.ru Storage Key": (r"(?i)storage[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "storage_key"),
    
    # === Sber ===
    "Sber ID Token": (r"\bsber_[a-zA-Z0-9_-]{24,}\b", 7, "oauth_token"),
    "Sber API Key": (r"(?i)sber[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 7, "api_key"),
    "Sber OAuth Token": (r"(?i)sber[_-]?oauth[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "oauth_token"),
    "Sber Client ID": (r"(?i)sber[_-]?client[_-]?id\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 6, "client_id"),
    "Sber Client Secret": (r"(?i)sber[_-]?client[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "client_secret"),
    "Sber Salutespeak Token": (r"(?i)salutespeak[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "salutespeak_token"),
    "Sber GigaChat Token": (r"(?i)gigachat[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "gigachat_token"),
    "Sber Bank API Key": (r"(?i)sberbank[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "bank_api_key"),
    "Sber Acquiring Token": (r"(?i)acquiring[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "acquiring_token"),
    
    # === Tinkoff ===
    "Tinkoff API Token": (r"\btinkoff_[a-zA-Z0-9_-]{28,}\b", 8, "api_token"),
    "Tinkoff Merchant Token": (r"\bmerchant_[a-zA-Z0-9_-]{32,}\b", 8, "merchant_token"),
    "Tinkoff Terminal Key": (r"(?i)terminal[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{16,}['\"]?", 7, "terminal_key"),
    "Tinkoff Secret Key": (r"(?i)tinkoff[_-]?secret[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "secret_key"),
    "Tinkoff Invest Token": (r"(?i)invest[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "invest_token"),
    "Tinkoff Business Token": (r"(?i)business[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "business_token"),
    "Tinkoff OAuth Token": (r"(?i)tinkoff[_-]?oauth[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "oauth_token"),
    
    # === Ozon ===
    "Ozon API Key": (r"(?i)api-key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{28,}['\"]?", 8, "api_key"),
    "Ozon Client ID": (r"(?i)client[_-]?id\s*[=:]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]?", 6, "client_id"),
    "Ozon Seller Token": (r"(?i)seller[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "seller_token"),
    "Ozon Partner Token": (r"(?i)partner[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "partner_token"),
    "Ozon Fresh Token": (r"(?i)fresh[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "fresh_token"),
    "Ozon Analytics Token": (r"(?i)analytics[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "analytics_token"),
    
    # === Wildberries ===
    "Wildberries API Key": (r"(?i)wb[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", 8, "api_key"),
    "Wildberries Seller Token": (r"(?i)seller[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "seller_token"),
    "Wildberries Partner Token": (r"(?i)partner[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "partner_token"),
    "Wildberries Statistics Token": (r"(?i)statistics[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "stats_token"),
    "Wildberries Marketplace Token": (r"(?i)marketplace[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "marketplace_token"),
    
    # === YooMoney / YooKassa ===
    "YooMoney API Key": (r"(?i)yoomoney[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "YooKassa Shop ID": (r"(?i)shopid\s*[=:]\s*['\"]?\d{5,10}['\"]?", 6, "shop_id"),
    "YooKassa Secret Key": (r"(?i)yookassa[_-]?secret[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "secret_key"),
    "YooMoney OAuth Token": (r"(?i)yoomoney[_-]?oauth[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "oauth_token"),
    "YooMoney Wallet": (r"\b41001\d{10,14}\b", 5, "wallet_number"),
    
    # === Avito ===
    "Avito API Key": (r"(?i)avito[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Avito Client ID": (r"(?i)avito[_-]?client[_-]?id\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 6, "client_id"),
    "Avito Client Secret": (r"(?i)avito[_-]?client[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "client_secret"),
    "Avito OAuth Token": (r"(?i)avito[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "oauth_token"),
    
    # === Mail.ru ===
    "Mail.ru API Key": (r"(?i)mail[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Mail.ru Client ID": (r"(?i)mail[_-]?ru[_-]?client[_-]?id\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 6, "client_id"),
    "Mail.ru Client Secret": (r"(?i)mail[_-]?ru[_-]?client[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "client_secret"),
    "Mail.ru OAuth Token": (r"(?i)mail[_-]?ru[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "oauth_token"),
    "Mail.ru Cloud API Key": (r"(?i)mailcloud[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "cloud_api_key"),
    "Mail.ru Target API Key": (r"(?i)target[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", 7, "target_api_key"),
    "MyTracker Project ID": (r"(?i)tracker[_-]?project[_-]?id\s*[=:]\s*['\"]?\d{5,10}['\"]?", 5, "project_id"),
    "MyTracker API Key": (r"(?i)tracker[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", 7, "tracker_api_key"),
    
    # === Rambler / Afisha ===
    "Rambler API Key": (r"(?i)rambler[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "Afisha API Key": (r"(?i)afisha[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === Rutube ===
    "Rutube API Key": (r"(?i)rutube[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Rutube OAuth Token": (r"(?i)rutube[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "oauth_token"),
    
    # === Megafon ===
    "Megafon API Key": (r"(?i)megafon[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Megafon Client Secret": (r"(?i)megafon[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "client_secret"),
    
    # === Beeline ===
    "Beeline API Key": (r"(?i)beeline[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Beeline OAuth Token": (r"(?i)beeline[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "oauth_token"),
    
    # === MTS ===
    "MTS API Key": (r"(?i)mts[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "MTS Client Secret": (r"(?i)mts[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "client_secret"),
    
    # === Rostelecom ===
    "Rostelecom API Key": (r"(?i)rt[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Rostelecom OAuth Token": (r"(?i)rt[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "oauth_token"),
    
    # === Gosuslugi / State services ===
    "Gosuslugi API Key": (r"(?i)gosuslugi[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_key"),
    "ESIA Client ID": (r"(?i)esia[_-]?client[_-]?id\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 7, "esia_client_id"),
    "ESIA Client Secret": (r"(?i)esia[_-]?client[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "esia_secret"),
    "ESIA Certificate": (r"(?i)esia[_-]?cert\s*[=:]\s*['\"]?-----BEGIN CERTIFICATE-----", 8, "esia_cert"),
    
    # === Kaspersky ===
    "Kaspersky API Key": (r"(?i)kaspersky[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", 8, "api_key"),
    "Kaspersky Secret Key": (r"(?i)kaspersky[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "secret_key"),
    
    # === Dr.Web ===
    "Dr.Web API Key": (r"(?i)drweb[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", 7, "api_key"),
    
    # === 1C ===
    "1C Enterprise Token": (r"(?i)1c[_-]?enterprise[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "enterprise_token"),
    "1C License Key": (r"(?i)1c[_-]?license[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 7, "license_key"),
    
    # === Bitrix ===
    "Bitrix Webhook URL": (r"https://[a-z0-9]+\.bitrix24\.ru/rest/\d+/[a-zA-Z0-9]+/", 8, "webhook"),
    "Bitrix Client ID": (r"(?i)bitrix[_-]?client[_-]?id\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 6, "client_id"),
    "Bitrix Client Secret": (r"(?i)bitrix[_-]?client[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "client_secret"),
    "Bitrix License Key": (r"(?i)bitrix[_-]?license[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "license_key"),
    
    # === Selectel ===
    "Selectel API Token": (r"(?i)selectel[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_token"),
    "Selectel Service Account": (r"(?i)selectel[_-]?account\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "service_account"),
    
    # === Timeweb ===
    "Timeweb API Key": (r"(?i)timeweb[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Timeweb Secret Key": (r"(?i)timeweb[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "secret_key"),
    
    # === Reg.ru ===
    "Reg.ru API Key": (r"(?i)reg[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Reg.ru Username": (r"(?i)reg[_-]?ru[_-]?username\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{5,}['\"]?", 5, "username"),
    "Reg.ru Password": (r"(?i)reg[_-]?ru[_-]?password\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]", 7, "password"),
    
    # === 2GIS ===
    "2GIS API Key": (r"(?i)2gis[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "2GIS Client ID": (r"(?i)2gis[_-]?client[_-]?id\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 6, "client_id"),
    "2GIS Client Secret": (r"(?i)2gis[_-]?client[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "client_secret"),
    
    # === Dadata ===
    "Dadata API Key": (r"(?i)dadata[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", 7, "api_key"),
    "Dadata Secret Key": (r"(?i)dadata[_-]?secret[_-]?key\s*[=:]\s*['\"]?[a-f0-9]{40}['\"]?", 8, "secret_key"),
    
    # === Kontur ===
    "Kontur API Key": (r"(?i)kontur[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Kontur Token": (r"(?i)kontur[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "token"),
    
    # === Skyeng ===
    "Skyeng API Key": (r"(?i)skyeng[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Skyeng OAuth Token": (r"(?i)skyeng[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "oauth_token"),
    
    # === Tutu.ru ===
    "Tutu.ru API Key": (r"(?i)tutu[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Tutu.ru Partner Token": (r"(?i)tutu[_-]?partner[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "partner_token"),
    
    # === Lamoda ===
    "Lamoda API Key": (r"(?i)lamoda[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Lamoda Partner Token": (r"(?i)lamoda[_-]?partner[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "partner_token"),
    
    # === Delivery Club ===
    "Delivery Club API Key": (r"(?i)deliveryclub[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Delivery Club Partner Token": (r"(?i)deliveryclub[_-]?partner[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "partner_token"),
    
    # === Yandex Lavka ===
    "Lavka API Key": (r"(?i)lavka[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Lavka Partner Token": (r"(?i)lavka[_-]?partner[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "partner_token"),
    
    # === SberMarket ===
    "SberMarket API Key": (r"(?i)sbermarket[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "SberMarket Partner Token": (r"(?i)sbermarket[_-]?partner[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "partner_token"),
    
    # === Samokat ===
    "Samokat API Key": (r"(?i)samokat[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Samokat Partner Token": (r"(?i)samokat[_-]?partner[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "partner_token"),
    
    # === Ozon Fresh ===
    "Ozon Fresh API Key": (r"(?i)ozonfresh[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    
    # === Yandex Eda ===
    "Yandex Eda API Key": (r"(?i)yandexeda[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    
    # === Fix Price ===
    "FixPrice API Key": (r"(?i)fixprice[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === Magnit ===
    "Magnit API Key": (r"(?i)magnit[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === Pyaterochka ===
    "Pyaterochka API Key": (r"(?i)pyaterochka[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === Perekrestok ===
    "Perekrestok API Key": (r"(?i)perekrestok[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === MVideo ===
    "MVideo API Key": (r"(?i)mvideo[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === Eldorado ===
    "Eldorado API Key": (r"(?i)eldorado[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === Citilink ===
    "Citilink API Key": (r"(?i)citilink[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === DNS ===
    "DNS API Key": (r"(?i)dns[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === Technosila ===
    "Technosila API Key": (r"(?i)technosila[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === AliExpress Russia ===
    "AliExpress Russia API Key": (r"(?i)aliexpress[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    
    # === Ozon Global ===
    "Ozon Global API Key": (r"(?i)ozonglobal[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    
    # === Joom Russia ===
    "Joom Russia API Key": (r"(?i)joom[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    
    # === KazanExpress ===
    "KazanExpress API Key": (r"(?i)kazanexpress[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    
    # === Viberate ===
    "Viberate Russia API Key": (r"(?i)viberate[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === Russian AI/ML services ===
    "YandexGPT API Key": (r"(?i)yandexgpt[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_key"),
    "YandexGPT Token": (r"(?i)yandexgpt[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_token"),
    "Kandinsky API Key": (r"(?i)kandinsky[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_key"),
    "Kandinsky Token": (r"(?i)kandinsky[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_token"),
    "RuGPT API Key": (r"(?i)rugpt[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "RuGPT Token": (r"(?i)rugpt[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_token"),
    "DeepPavlov API Key": (r"(?i)deeppavlov[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Natasha NLP Token": (r"(?i)natasha[_-]?nlp[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "nlp_token"),
    "Solar API Key": (r"(?i)solar[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_key"),
    
    # === Russian payment systems ===
    "Robokassa API Key": (r"(?i)robokassa[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Robokassa Secret Key": (r"(?i)robokassa[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "secret_key"),
    "Robokassa Merchant Login": (r"(?i)robokassa[_-]?login\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{5,}['\"]?", 6, "merchant_login"),
    "Payeer API Key": (r"(?i)payeer[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Payeer Secret Key": (r"(?i)payeer[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "secret_key"),
    "Qiwi API Key": (r"(?i)qiwi[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Qiwi Secret Key": (r"(?i)qiwi[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "secret_key"),
    "Qiwi Wallet": (r"\+\d{10,12}\b", 4, "qiwi_wallet"),
    "WebMoney Purse": (r"\b(?:[RZEDU]\d{12}[A-Z]?)\b", 5, "webmoney_purse"),
    "WebMoney API Key": (r"(?i)webmoney[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Unitpay Secret": (r"(?i)unitpay[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "secret_key"),
    "Unitpay Login": (r"(?i)unitpay[_-]?login\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{5,}['\"]?", 6, "login"),
    "FreeKassa API Key": (r"(?i)freekassa[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "FreeKassa Secret": (r"(?i)freekassa[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "secret_key"),
    "Enot API Key": (r"(?i)enot[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Enot Secret": (r"(?i)enot[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "secret_key"),
    "Lava API Key": (r"(?i)lava[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Lava Secret": (r"(?i)lava[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "secret_key"),
    "CloudPayments API Key": (r"(?i)cloudpayments[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_key"),
    "CloudPayments Secret": (r"(?i)cloudpayments[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "secret_key"),
    "Assist API Key": (r"(?i)assist[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Assist Merchant": (r"(?i)assist[_-]?merchant\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{5,}['\"]?", 6, "merchant"),
    
    # === Russian hosting / cloud ===
    "RuCenter API Key": (r"(?i)rucenter[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Nic.ru API Key": (r"(?i)nic[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Beget API Key": (r"(?i)beget[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Beget Password": (r"(?i)beget[_-]?password\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]", 7, "password"),
    "Sprinthost API Key": (r"(?i)sprinthost[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "FirstVPS API Key": (r"(?i)firstvps[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "Aeza API Key": (r"(?i)aeza[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "VDSina API Key": (r"(?i)vdsina[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "Timeweb Cloud API Key": (r"(?i)timewebcloud[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Cloud4Y API Key": (r"(?i)cloud4y[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "IXEServer API Key": (r"(?i)ixeserver[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === Russian messengers / social ===
    "OK.ru API Key": (r"(?i)ok[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "OK.ru App ID": (r"(?i)ok[_-]?ru[_-]?app[_-]?id\s*[=:]\s*['\"]?\d{5,15}['\"]?", 6, "app_id"),
    "OK.ru Secret Key": (r"(?i)ok[_-]?ru[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "secret_key"),
    "Viber API Key": (r"(?i)viber[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Viber Bot Token": (r"(?i)viber[_-]?bot[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "bot_token"),
    "TamTam Bot Token": (r"(?i)tamtam[_-]?bot[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "bot_token"),
    "ICQ Bot Token": (r"(?i)icq[_-]?bot[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "bot_token"),
    
    # === Russian analytics / marketing ===
    "Calltouch API Key": (r"(?i)calltouch[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Calltouch Client ID": (r"(?i)calltouch[_-]?client[_-]?id\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 6, "client_id"),
    "Roistat API Key": (r"(?i)roistat[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Roistat Secret": (r"(?i)roistat[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "secret"),
    "Envybox API Key": (r"(?i)envybox[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "JivoSite API Key": (r"(?i)jivosite[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "JivoSite Token": (r"(?i)jivosite[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "token"),
    "LiveTex API Key": (r"(?i)livetex[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "Carrot Quest API Key": (r"(?i)carrotquest[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "Mindbox API Key": (r"(?i)mindbox[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Mindbox Secret": (r"(?i)mindbox[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "secret"),
    "Emarsys API Key": (r"(?i)emarsys[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "RetailRocket API Key": (r"(?i)retailrocket[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "Omnisend API Key": (r"(?i)omnisend[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "SendPulse API Key": (r"(?i)sendpulse[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "SendPulse Secret": (r"(?i)sendpulse[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "secret"),
    "Unisender API Key": (r"(?i)unisender[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Dashamail API Key": (r"(?i)dashamail[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Dashamail Secret": (r"(?i)dashamail[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "secret"),
    
    # === Russian CRM / ERP ===
    "AmoCRM OAuth Token": (r"(?i)amocrm[_-]?oauth[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "oauth_token"),
    "AmoCRM Client ID": (r"(?i)amocrm[_-]?client[_-]?id\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 7, "client_id"),
    "AmoCRM Client Secret": (r"(?i)amocrm[_-]?client[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "client_secret"),
    "Bitrix24 Webhook": (r"https://[a-z0-9]+\.bitrix24\.ru/rest/\d+/[a-zA-Z0-9]+/", 8, "webhook"),
    "Bitrix24 OAuth Token": (r"(?i)bitrix24[_-]?oauth[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "oauth_token"),
    "MegaPlan API Key": (r"(?i)megaplan[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "PlanFix API Key": (r"(?i)planfix[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "PlanFix Account ID": (r"(?i)planfix[_-]?account[_-]?id\s*[=:]\s*['\"]?\d{5,10}['\"]?", 6, "account_id"),
    "BaseLinker API Key": (r"(?i)baselinker[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "InSales API Key": (r"(?i)insales[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "InSales Secret": (r"(?i)insales[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "secret"),
    "AdvantShop API Key": (r"(?i)advantshop[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "OpenCart Russia API Key": (r"(?i)opencart[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "1C-Bitrix API Key": (r"(?i)1cbitrix[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    
    # === Russian delivery services ===
    "CDEK API Key": (r"(?i)cdek[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "CDEK Secret": (r"(?i)cdek[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "secret"),
    "Boxberry API Key": (r"(?i)boxberry[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Boxberry Secret": (r"(?i)boxberry[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "secret"),
    "PickPoint API Key": (r"(?i)pickpoint[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "Russian Post API Key": (r"(?i)russianpost[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Pochta.ru API Key": (r"(?i)pochta[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "DPD Russia API Key": (r"(?i)dpd[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "IML API Key": (r"(?i)iml[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "Hermes Russia API Key": (r"(?i)hermes[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === Russian travel services ===
    "Aviasales API Key": (r"(?i)aviasales[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Travelpayouts API Key": (r"(?i)travelpayouts[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Travelpayouts Secret": (r"(?i)travelpayouts[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "secret"),
    "Ostrovok API Key": (r"(?i)ostrovok[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Yandex Travel API Key": (r"(?i)yandextravel[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    
    # === Russian job sites ===
    "HH.ru API Key": (r"(?i)hh[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "HeadHunter OAuth": (r"(?i)hh[_-]?oauth[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "oauth_token"),
    "SuperJob API Key": (r"(?i)superjob[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Rabota.ru API Key": (r"(?i)rabota[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "Avito Jobs API Key": (r"(?i)avitojobs[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === Russian classifieds ===
    "Cian API Key": (r"(?i)cian[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Auto.ru API Key": (r"(?i)auto[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Drom.ru API Key": (r"(?i)drom[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === Russian food delivery ===
    "Yandex Eats API Key": (r"(?i)yandexeats[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Delivery Club Partner API": (r"(?i)deliveryclub[_-]?partner[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    
    # === Russian fintech ===
    "Tinkoff Invest API Token": (r"(?i)tinkoffinvest[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "invest_token"),
    "Sber Invest API Token": (r"(?i)sberinvest[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "invest_token"),
    "VTB API Key": (r"(?i)vtb[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_key"),
    "Alfa Bank API Key": (r"(?i)alfabank[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_key"),
    "Gazprombank API Key": (r"(?i)gazprombank[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_key"),
    "Rosbank API Key": (r"(?i)rosbank[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Raiffeisen API Key": (r"(?i)raiffeisen[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Otkritie API Key": (r"(?i)otkritie[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    
    # === Russian insurance ===
    "Ingosstrakh API Key": (r"(?i)ingosstrakh[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Reso API Key": (r"(?i)reso[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "Renaissance API Key": (r"(?i)renaissance[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Sberbank Insurance API": (r"(?i)sberbankinsurance[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    
    # === Russian telecom ===
    "Dom.ru API Key": (r"(?i)dom[_-]?ru[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "Akado API Key": (r"(?i)akado[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "TTK API Key": (r"(?i)ttk[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    "TransTeleCom API Key": (r"(?i)transtelecom[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "api_key"),
    
    # === Russian energy ===
    "Rosseti API Key": (r"(?i)rosseti[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Gazprom API Key": (r"(?i)gazprom[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_key"),
    "Lukoil API Key": (r"(?i)lukoil[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_key"),
    "Rosneft API Key": (r"(?i)rosneft[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_key"),
    
    # === Russian government tech ===
    "GosTech API Key": (r"(?i)gostech[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_key"),
    "GosData API Key": (r"(?i)gosdata[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_key"),
    "GosCloud API Key": (r"(?i)goscloud[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "api_key"),
    
    # === HubSpot ===
    
    # === Generic / Common ===
    "Generic API Key": (r"(?i)api[_\-\s]?key\s*[=:]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})['\"]?", 5, "api_key"),
    "Generic Secret": (r"(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", 5, "credential"),
    "Generic Token": (r"(?i)token\s*[=:]\s*['\"]([a-zA-Z0-9_\-\.]{16,})['\"]", 4, "api_token"),
    "Generic Private Key": (r"(?i)private[_-]?key\s*[=:]\s*['\"]?-----BEGIN[^'\"]*PRIVATE KEY-----", 9, "private_key"),
    "Generic SSH Key": (r"ssh-(rsa|ed25519|ecdsa) [A-Za-z0-9+/]+[=]{0,3}(?: [^,\n]+)?", 7, "ssh_key"),
    "Generic Bearer Token": (r"(?i)bearer\s+[a-zA-Z0-9_\-\.=]{20,}", 6, "bearer_token"),
    "Generic Basic Auth": (r"(?i)basic\s+[a-zA-Z0-9+/]{20,}={0,2}\b", 6, "basic_auth"),
    "Generic Connection String": (r"(?i)connection[_-]?string\s*[=:]\s*['\"]?[^'\"]{20,}['\"]", 6, "connection_string"),
    "Connection String": (r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", 8, "db_credential"),

    # === Database Connection Strings ===
    "PostgreSQL Connection String": (r"postgres(?:ql)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", 8, "db_credential"),
    "MySQL Connection String": (r"mysql://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", 8, "db_credential"),
    "MongoDB Connection String": (r"mongodb(?:\+srv)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", 8, "db_credential"),
    "Redis Connection String": (r"redis://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", 8, "db_credential"),
    "RabbitMQ Connection String": (r"amqp://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", 8, "db_credential"),
    "Elasticsearch Connection String": (r"elasticsearch://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", 8, "db_credential"),
    "Cassandra Connection String": (r"cassandra://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", 8, "db_credential"),
    "SQLite Connection String": (r"sqlite:///[^\s'\"]+", 4, "db_path"),
    "MSSQL Connection String": (r"mssql://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", 8, "db_credential"),
    "Oracle Connection String": (r"oracle://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", 8, "db_credential"),

    # === Private Keys ===
    "Private Key": (r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----", 10, "private_key"),
    "RSA Private Key": (r"-----BEGIN RSA PRIVATE KEY-----", 10, "private_key"),
    "EC Private Key": (r"-----BEGIN EC PRIVATE KEY-----", 10, "private_key"),
    "DSA Private Key": (r"-----BEGIN DSA PRIVATE KEY-----", 10, "private_key"),
    "OpenSSH Private Key": (r"-----BEGIN OPENSSH PRIVATE KEY-----", 10, "private_key"),
    "PGP Private Key": (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", 10, "private_key"),
    "Encrypted Private Key": (r"-----BEGIN ENCRYPTED PRIVATE KEY-----", 10, "private_key"),
    "Generic Private Key Block": (r"-----BEGIN PRIVATE KEY-----", 10, "private_key"),
    
    # === Tokens ===
    "JWT Token": (r"\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b", 7, "jwt"),
    "Bearer Token": (r"(?i)bearer\s+[a-zA-Z0-9_\.=]{20,}", 6, "bearer_token"),
    "Basic Auth": (r"(?i)basic\s+[a-zA-Z0-9+/]{20,}={0,2}\b", 6, "basic_auth"),
    "OAuth Access Token": (r"(?i)oauth[_-]?access[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 7, "access_token"),
    "OAuth Refresh Token": (r"(?i)oauth[_-]?refresh[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 7, "refresh_token"),
    "Session Token": (r"(?i)session[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 6, "session_token"),
    "Authentication Token": (r"(?i)auth[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 6, "auth_token"),
    
    # === Webhooks ===
    "Generic Webhook URL": (r"https://[^\s'\"]*/webhook/[^\s'\"]*", 6, "webhook"),
    "Stripe Webhook": (r"https://api\.stripe\.com/v1/webhooks/[^\s'\"]*", 7, "webhook"),
    "GitHub Webhook": (r"https://api\.github\.com/repos/[^\s]*/hooks/[^\s]*", 6, "webhook"),
    
    # === Certificates ===
    "SSL Certificate": (r"-----BEGIN CERTIFICATE-----", 5, "certificate"),
    "X509 Certificate": (r"-----BEGIN X509 CERTIFICATE-----", 5, "certificate"),
    "CSR Certificate": (r"-----BEGIN CERTIFICATE REQUEST-----", 4, "csr"),
    
    # === Environment / Config ===
    "Environment Variable Assignment": (r"(?i)(?:export|set)\s+[A-Z_][A-Z0-9_]*\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?", 4, "env_var"),
    "Dotenv Secret": (r"^[A-Z_][A-Z0-9_]*\s*=\s*['\"]?[^\s'\"]{8,}['\"]?\s*$", 4, "dotenv"),
    
    # === IP Addresses / Endpoints ===
    "Private IP in code": (
        r"(?i)(?:host|server|endpoint)\s*[=:]\s*['\"]?(192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)",
        2,
        "internal_endpoint",
    ),
    "Public IP in code": (
        r"(?i)(?:host|server|endpoint)\s*[=:]\s*['\"]?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        3,
        "public_endpoint",
    ),
    
    # === Cryptocurrency ===
    "Bitcoin Private Key": (r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b", 9, "crypto_key"),
    "Bitcoin Address": (r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", 4, "crypto_address"),
    "Ethereum Private Key": (r"\b0x[a-f0-9]{64}\b", 9, "crypto_key"),
    "Ethereum Address": (r"\b0x[a-fA-F0-9]{40}\b", 5, "crypto_address"),
    "Solana Private Key": (r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b", 8, "crypto_key"),
    "Binance Smart Chain Address": (r"\b0x[a-fA-F0-9]{40}\b", 5, "crypto_address"),
    
    # === Other Services ===
    "Fastly API Token": (r"\b[a-f0-9]{32}\b", 7, "api_token"),
    "New Relic License Key": (r"(?i)newrelic[_-]?license[_-]?key\s*[=:]\s*['\"]?[a-f0-9]{40}['\"]?", 7, "license_key"),
    "New Relic API Key": (r"(?i)newrelic[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", 7, "api_key"),
    "PagerDuty API Key": (r"\b[a-f0-9]{32}\b", 7, "api_key"),
    "Splunk Token": (r"(?i)splunk[_-]?token\s*[=:]\s*['\"]?[a-f0-9-]{36}['\"]?", 7, "api_token"),
    "CircleCI API Token": (r"\b[a-f0-9]{40}\b", 7, "api_token"),
    "Travis CI API Token": (r"\b[a-zA-Z0-9]{22}\b", 7, "api_token"),
    "Codecov Token": (r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b", 6, "codecov_token"),
    "SonarQube Token": (r"(?i)sonar[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_token"),
    "Artifactory Token": (r"\bAKC[a-zA-Z0-9]{70,}\b", 7, "api_token"),
    "Nexus API Key": (r"(?i)nexus[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "LaunchDarkly SDK Key": (r"\bsdk-[a-z0-9]{40}\b", 7, "sdk_key"),
    "LaunchDarkly Client ID": (r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b", 6, "client_id"),
    "Contentful Delivery API Token": (r"\b[a-z0-9_-]{43}\b", 7, "api_token"),
    "Contentful Preview API Token": (r"\b[a-z0-9_-]{43}\b", 7, "api_token"),
    "Sanity API Token": (r"(?i)sanity[_-]?api[_-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_token"),
    "Algolia API Key": (r"\b[a-f0-9]{32}\b", 7, "api_key"),
    "Algolia Admin API Key": (r"(?i)algolia[_-]?admin[_-]?key\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", 8, "admin_key"),
    "Elastic Cloud API Key": (r"\b[a-zA-Z0-9+/]{22}==\b", 7, "api_key"),
    "Auth0 Client Secret": (r"(?i)auth0[_-]?client[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "client_secret"),
    "Okta API Token": (r"\b00[a-zA-Z0-9_-]{40}\b", 8, "api_token"),
    "OneLogin API Key": (r"\b[a-f0-9]{32}\b", 7, "api_key"),
    "Keycloak Secret": (r"(?i)keycloak[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "client_secret"),
    "PingID": (r"(?i)ping[_-]?id\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 6, "ping_id"),
    
    # === AI / ML Services ===
    "Replicate API Token": (r"\br8_[a-zA-Z0-9_-]{32,}\b", 7, "api_token"),
    "Cohere API Key": (r"\b[a-zA-Z0-9]{40}\b", 7, "api_key"),
    "AI21 API Key": (r"(?i)ai21[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Stability AI API Key": (r"\bsk_[a-zA-Z0-9_-]{28,}\b", 8, "api_key"),
    "DeepL API Key": (r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}:[a-z]{2,3}\b", 7, "api_key"),
    "AssemblyAI API Key": (r"(?i)assembly[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", 7, "api_key"),
    "Hugging Face Inference Token": (r"\bhf_[a-zA-Z0-9]{34}\b", 7, "inference_token"),
    
    # === Payment Services ===
    "PayPal Client Secret": (r"(?i)paypal[_-]?client[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "client_secret"),
    "Square Access Token": (r"\bsq0atp-[a-zA-Z0-9_-]{22}\b", 8, "access_token"),
    "Square Application Secret": (r"\bsq0csp-[a-zA-Z0-9_-]{43}\b", 8, "app_secret"),
    "Plaid Client Secret": (r"(?i)plaid[_-]?client[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9]{30}['\"]?", 8, "client_secret"),
    "Plaid Access Token": (r"\baccess-[a-z0-9-]{20,}\b", 8, "access_token"),
    "Razorpay Key ID": (r"\brzp_live_[a-zA-Z0-9]{10,}\b", 8, "key_id"),
    "Razorpay Key Secret": (r"(?i)razorpay[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{24,}['\"]?", 8, "key_secret"),
    
    # === Communication Services ===
    "WhatsApp Business Token": (r"\bEAAG[0-9A-Za-z]{20,}\b", 7, "whatsapp_token"),
    "Signal API Key": (r"(?i)signal[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 7, "api_key"),
    "Zoom API Key": (r"(?i)zoom[_-]?api[_-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", 7, "api_key"),
    "Zoom Client Secret": (r"(?i)zoom[_-]?client[_-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{32,}['\"]?", 8, "client_secret"),
    "Teams Webhook URL": (r"https://outlook\.office\.com/webhook/[a-f0-9-]+", 7, "webhook"),
    "Line Channel Secret": (r"(?i)line[_-]?channel[_-]?secret\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", 7, "channel_secret"),
    "Line Access Token": (r"\b[a-zA-Z0-9+/=]{100,}\b", 6, "access_token"),
}

CONTEXT_KEYWORDS = [
    "api_key",
    "apikey",
    "secret",
    "password",
    "passwd",
    "pwd",
    "token",
    "auth",
    "credential",
    "private_key",
    "access_key",
    "client_secret",
    "app_secret",
    "api_secret",
    "database_url",
    "connection_string",
]

IGNORE_PATTERNS = [
    r"example",
    r"test",
    r"fake",
    r"dummy",
    r"placeholder",
    r"xxxx",
    r"1234",
    r"your[_\-]?\w*key",
    r"<[^>]+>",
    r"\*{4,}",
    r"TODO",
    r"FIXME",
]

HASH_PATTERNS = [
    r"^[a-f0-9]{32}$",
    r"^[a-f0-9]{40}$",
    r"^[a-f0-9]{64}$",
]

SKIP_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".mp3",
    ".zip",
    ".tar",
    ".gz",
    ".pdf",
    ".lock",
    ".sum",
    ".exe",
    ".dll",
    ".so",
    ".bin",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".idea",
    ".vscode",
    "vendor",
    "target",
    "out",
}

HIGH_ENTROPY_FILE_TYPES = {".env", ".cfg", ".conf", ".ini", ".yaml", ".yml", ".json", ".toml"}

SINK_NAMES = {
    r"\brequests\.(get|post|put|patch|delete|head)\b": "HTTP request",
    r"\burllib\.request\.": "HTTP request",
    r"\bhttpx\.(get|post|put|patch|delete)\b": "HTTP request",
    r"\baiohttp\.": "HTTP request",
    r"\bsmtplib\.": "Email sending",
    r"\blogging\.(info|debug|warning|error|critical)\b": "Logging",
    r"\bprint\s*\(": "Console output",
    r"\bopen\s*\(": "File write",
    r"\bsubprocess\.(run|call|Popen|check_output)\b": "Shell execution",
    r"\bos\.system\s*\(": "Shell execution",
    r"\bsocket\.": "Raw socket",
    r"\bparamiko\.": "SSH connection",
    r"\bpysftp\.": "SFTP connection",
    r"\bboto3\.": "AWS SDK call",
    r"\bpymongo\.": "MongoDB query",
    r"\bpsycopg2\.": "PostgreSQL query",
    r"\bsqlalchemy\.": "Database query",
    r"\bsequelize\.": "Database query",
    r"\bexec\s*\(": "Dynamic code execution",
}

# Российские сервисы (для фильтрации --ru-only)
RU_SERVICES_PATTERNS = {
    # Telegram
    "Telegram Bot Token",
    "Telegram API ID",
    "Telegram API Hash",
    "Telegram Webhook URL",
    
    # Yandex
    "Yandex Cloud OAuth Token",
    "Yandex Cloud IAM Token",
    "Yandex Cloud Service Account Key",
    "Yandex Cloud API Key",
    "Yandex OAuth Token",
    "Yandex API Key",
    "Yandex Passport Token",
    "Yandex Tracker Token",
    "Yandex Metrica ID",
    "Yandex Direct API Token",
    "Yandex SpeechKit Key",
    "Yandex Translate API Key",
    "Yandex Maps API Key",
    "Yandex Disk Token",
    "Yandex Music Token",
    "YandexGPT API Key",
    "YandexGPT Token",
    
    # VK (VKontakte)
    "VK API Access Token",
    "VK API User Token",
    "VK API Service Token",
    "VK API Client Secret",
    "VK API Service Key",
    "VK Group Token",
    "VK Community Token",
    "VK App ID",
    "VK Callback URL Secret",
    
    # Cloud.ru (SberCloud)
    "Cloud.ru API Token",
    "Cloud.ru Service Account",
    "Cloud.ru IAM Token",
    "Cloud.ru Storage Key",
    
    # Sber
    "Sber ID Token",
    "Sber API Key",
    "Sber OAuth Token",
    "Sber Client ID",
    "Sber Client Secret",
    "Sber Salutespeak Token",
    "Sber GigaChat Token",
    "Sber Bank API Key",
    "Sber Acquiring Token",
    "Sber Invest API Token",
    "SberMarket API Key",
    "SberMarket Partner Token",
    
    # Tinkoff
    "Tinkoff API Token",
    "Tinkoff Merchant Token",
    "Tinkoff Terminal Key",
    "Tinkoff Secret Key",
    "Tinkoff Invest Token",
    "Tinkoff Business Token",
    "Tinkoff OAuth Token",
    "Tinkoff Invest API Token",
    
    # Ozon
    "Ozon API Key",
    "Ozon Client ID",
    "Ozon Seller Token",
    "Ozon Partner Token",
    "Ozon Fresh Token",
    "Ozon Analytics Token",
    "Ozon Fresh API Key",
    "Ozon Global API Key",
    
    # Wildberries
    "Wildberries API Key",
    "Wildberries Seller Token",
    "Wildberries Partner Token",
    "Wildberries Statistics Token",
    "Wildberries Marketplace Token",
    
    # YooMoney / YooKassa
    "YooMoney API Key",
    "YooKassa Shop ID",
    "YooKassa Secret Key",
    "YooMoney OAuth Token",
    "YooMoney Wallet",
    
    # Avito
    "Avito API Key",
    "Avito Client ID",
    "Avito Client Secret",
    "Avito OAuth Token",
    "Avito Jobs API Key",
    
    # Mail.ru
    "Mail.ru API Key",
    "Mail.ru Client ID",
    "Mail.ru Client Secret",
    "Mail.ru OAuth Token",
    "Mail.ru Cloud API Key",
    "Mail.ru Target API Key",
    "MyTracker Project ID",
    "MyTracker API Key",
    
    # Rambler / Afisha
    "Rambler API Key",
    "Afisha API Key",
    
    # Rutube
    "Rutube API Key",
    "Rutube OAuth Token",
    
    # Megafon
    "Megafon API Key",
    "Megafon Client Secret",
    
    # Beeline
    "Beeline API Key",
    "Beeline OAuth Token",
    
    # MTS
    "MTS API Key",
    "MTS Client Secret",
    
    # Rostelecom
    "Rostelecom API Key",
    "Rostelecom OAuth Token",
    
    # Gosuslugi / State services
    "Gosuslugi API Key",
    "ESIA Client ID",
    "ESIA Client Secret",
    "ESIA Certificate",
    "GosTech API Key",
    "GosData API Key",
    "GosCloud API Key",
    
    # Kaspersky
    "Kaspersky API Key",
    "Kaspersky Secret Key",
    
    # Dr.Web
    "Dr.Web API Key",
    
    # 1C
    "1C Enterprise Token",
    "1C License Key",
    "1C-Bitrix API Key",
    
    # Bitrix
    "Bitrix Webhook URL",
    "Bitrix Client ID",
    "Bitrix Client Secret",
    "Bitrix License Key",
    "Bitrix24 Webhook",
    "Bitrix24 OAuth Token",
    
    # Selectel
    "Selectel API Token",
    "Selectel Service Account",
    
    # Timeweb
    "Timeweb API Key",
    "Timeweb Secret Key",
    "Timeweb Cloud API Key",
    
    # Reg.ru
    "Reg.ru API Key",
    "Reg.ru Username",
    "Reg.ru Password",
    
    # 2GIS
    "2GIS API Key",
    "2GIS Client ID",
    "2GIS Client Secret",
    
    # Dadata
    "Dadata API Key",
    "Dadata Secret Key",
    
    # Kontur
    "Kontur API Key",
    "Kontur Token",
    
    # Skyeng
    "Skyeng API Key",
    "Skyeng OAuth Token",
    
    # Tutu.ru
    "Tutu.ru API Key",
    "Tutu.ru Partner Token",
    
    # Lamoda
    "Lamoda API Key",
    "Lamoda Partner Token",
    
    # Delivery Club
    "Delivery Club API Key",
    "Delivery Club Partner Token",
    "Delivery Club Partner API",
    
    # Yandex Lavka / Eda / Eats
    "Lavka API Key",
    "Lavka Partner Token",
    "Yandex Eda API Key",
    "Yandex Eats API Key",
    
    # Samokat
    "Samokat API Key",
    "Samokat Partner Token",
    
    # Retail stores
    "FixPrice API Key",
    "Magnit API Key",
    "Pyaterochka API Key",
    "Perekrestok API Key",
    "MVideo API Key",
    "Eldorado API Key",
    "Citilink API Key",
    "DNS API Key",
    "Technosila API Key",
    
    # Marketplaces
    "AliExpress Russia API Key",
    "Ozon Global API Key",
    "Joom Russia API Key",
    "KazanExpress API Key",
    "Viberate Russia API Key",
    
    # Russian AI/ML
    "Kandinsky API Key",
    "Kandinsky Token",
    "RuGPT API Key",
    "RuGPT Token",
    "DeepPavlov API Key",
    "Natasha NLP Token",
    "Solar API Key",
    
    # Russian payment systems
    "Robokassa API Key",
    "Robokassa Secret Key",
    "Robokassa Merchant Login",
    "Payeer API Key",
    "Payeer Secret Key",
    "Qiwi API Key",
    "Qiwi Secret Key",
    "Qiwi Wallet",
    "WebMoney Purse",
    "WebMoney API Key",
    "Unitpay Secret",
    "Unitpay Login",
    "FreeKassa API Key",
    "FreeKassa Secret",
    "Enot API Key",
    "Enot Secret",
    "Lava API Key",
    "Lava Secret",
    "CloudPayments API Key",
    "CloudPayments Secret",
    "Assist API Key",
    "Assist Merchant",
    
    # Russian hosting / cloud
    "RuCenter API Key",
    "Nic.ru API Key",
    "Beget API Key",
    "Beget Password",
    "Sprinthost API Key",
    "FirstVPS API Key",
    "Aeza API Key",
    "VDSina API Key",
    "Cloud4Y API Key",
    "IXEServer API Key",
    
    # Russian messengers / social
    "OK.ru API Key",
    "OK.ru App ID",
    "OK.ru Secret Key",
    "Viber API Key",
    "Viber Bot Token",
    "TamTam Bot Token",
    "ICQ Bot Token",
    
    # Russian analytics / marketing
    "Calltouch API Key",
    "Calltouch Client ID",
    "Roistat API Key",
    "Roistat Secret",
    "Envybox API Key",
    "JivoSite API Key",
    "JivoSite Token",
    "LiveTex API Key",
    "Carrot Quest API Key",
    "Mindbox API Key",
    "Mindbox Secret",
    "Emarsys API Key",
    "RetailRocket API Key",
    "Omnisend API Key",
    "SendPulse API Key",
    "SendPulse Secret",
    "Unisender API Key",
    "Dashamail API Key",
    "Dashamail Secret",
    
    # Russian CRM / ERP
    "AmoCRM OAuth Token",
    "AmoCRM Client ID",
    "AmoCRM Client Secret",
    "MegaPlan API Key",
    "PlanFix API Key",
    "PlanFix Account ID",
    "BaseLinker API Key",
    "InSales API Key",
    "InSales Secret",
    "AdvantShop API Key",
    "OpenCart Russia API Key",
    
    # Russian delivery services
    "CDEK API Key",
    "CDEK Secret",
    "Boxberry API Key",
    "Boxberry Secret",
    "PickPoint API Key",
    "Russian Post API Key",
    "Pochta.ru API Key",
    "DPD Russia API Key",
    "IML API Key",
    "Hermes Russia API Key",
    
    # Russian travel services
    "Aviasales API Key",
    "Travelpayouts API Key",
    "Travelpayouts Secret",
    "Ostrovok API Key",
    "Yandex Travel API Key",
    
    # Russian job sites
    "HH.ru API Key",
    "HeadHunter OAuth",
    "SuperJob API Key",
    "Rabota.ru API Key",
    
    # Russian classifieds
    "Cian API Key",
    "Auto.ru API Key",
    "Drom.ru API Key",
    
    # Russian fintech
    "VTB API Key",
    "Alfa Bank API Key",
    "Gazprombank API Key",
    "Rosbank API Key",
    "Raiffeisen API Key",
    "Otkritie API Key",
    
    # Russian insurance
    "Ingosstrakh API Key",
    "Reso API Key",
    "Renaissance API Key",
    "Sberbank Insurance API",
    
    # Russian telecom
    "Dom.ru API Key",
    "Akado API Key",
    "TTK API Key",
    "TransTeleCom API Key",
    
    # Russian energy
    "Rosseti API Key",
    "Gazprom API Key",
    "Lukoil API Key",
    "Rosneft API Key",
}
