from ldap3 import SUBTREE
import cx_Oracle

gw_sof_headers = ['cust_status', 'main_acc', 'main_acc_status', 'register_channel', 'cif', 'cfn', 'gw_user_category', 'aml_status', 'credit_card_enabled',
                  'registration_email', 'registration_mobile', 'contact_mail', 'status',
                  'contact_mob', 'status', 'language', 'notification_lang', 'Portal_last_login_date', 'deactivation_date',
                  'gw_creation_date', 'last_modification_date', 'login_username',
                  'birth_date', 'gender','activation_code', 'alias', 'acc_last_modification_date']

sof_headers = ['cif', 'cp_status', 'main_acc_status', 'username', 'sof_category', 'main_account_number',
               'main_acc_creation_date', 'main_acc_last_modification_date', 'usage', 'account_type', 'alias']

sof_terminals_headers = ['cif', 'trm_type', 'terminal_status', 'CREATION_DATE', 'LAST_MODIFICATION_DATE', 'device_id',
                         'pin', 'trm_code']

gw_sof_cc_headers = ['cust_identifier', 'MASKED_CCARD_NUMBER', 'issuer_bank_id', 'LAST_FOUR_DIGITS', 'alias',
                     'gw_status', 'sof_status', 'type', 'gw_creation_date', 'sof_creation_date',
                     'last_modification_date', 'balance', 'credit_limit', 'account_number']

mcc_headers = ['user_name', 'CSP', 'full_name', 'cfn', 'cif', 'mobile', 'country_code', 'notified_mob', 'email_address',
               'email_status', 'main_acc', 'profile_code', 'user_category', 'mob_last_login_date', 'user_created_date',
               'first_activation_date', 'num_failed_trials', 'num_inv_activ_trials', 'user_active', 'main_acct_active',
               'main_acct_blocked', 'terminal_status', 'trm_active', 'trm_blocked', 'birth_date', 'terminal',
               'terminal_code', 'app_code', 'force_clear_cache', 'user_code', 'gender']

ldap_params = ['cn', 'sn', 'uid', 'mobile', 'mail', 'roomNumber', 'employeeNumber', 'internationalisdnnumber', 'title',
                'businessCategory']

ldap_headers = ['cn', 'sn', 'uid', 'mobile', 'mail', 'roomNumber', 'cif', 'country_code', 'status',
                'Activation_code']

gw_pmt_headers = ['channel', 'btc', 'BTC_Name', 'pmt_type', 'bill_date', 'bill_reference_number', 'pmt_method', 'pmt_status',
                  'DEBIT_STATUS_CODE', 'external_pmt_status', 'advice_status_code', 'gateway_pmt_date', 'sof_date',
                  'fawry_pmt_date', 'biller_pmt_date',  'pmt_amount', 'fees', 'customer_ref_number', 'pmt_nature',
                  'request_uid', 'EXTERNAL_SOF_CODE', 'billing_account_number', 'billing_acct_key_1', 'billing_acct_key_2',
                  'billing_acct_key_3', 'user_name', 'asynchronous_request_uid', 'terminal_id']

gw_velocity_counters_headers = ['measure_type', 'value', 'creation_date', 'last_modification_date', 'velocity_period',
                                'velocity_period_unit', 'blocking_period', 'blocking_period_unit']

velocity_violations_headers = ['fawry_cust_no', 'cust_category', 'velocity_measure_type', 'velocity_period',
                               'velocity_period_unit', 'criteria_measure_value', 'transaction_value',
                               'customer_vel_counter_value', 'action_taken', 'violation_logging_time', 'BTC', 'channel',
                               'account_type', 'billing_account', 'velocity_error_code']

mcc_activities_headers = ['REQ_CREATED_DATE', 'REQ_request_id', 'REQ_rrn',
                          'RES_message', 'RES_status_code', 'RES_host_status_code', 'REQ_service ',
                          'REQ_operation_type','REQ_custom_operation_id', 'REQ_transmission_date', 'REQ_front_end_date',
                          'REQ_client_session_id','REQ_client_pref_lang','REQ_application_code','REQ_application_version',
                          'REQ_user_name','REQ_terminal_code', 'REQ_ter_type','REQ_terminal_os_type', 'REQ_terminal_os_version']

gw_enr_headers = ['cust_identifier', 'enr_alias', 'status', 'BTC', 'billing_account_number', 'billing_acct_key_1',
                  'billing_acct_key_2', 'enr_type', 'inquiry_start_date', 'inquiry_last_date', 'inquiry_next_date',
                  'creation_date', 'last_modification_date', 'ern_code']

gw_mandates_headers = ['cust_identifier', 'enr_alias', 'sch_pmt_status', 'card', 'start_date', 'end_date',
                       'last_payment_date', 'next_payment_date', 'amount_threshold', 'no_of_repeats', 'code',
                       'FIXED_PAYMENT_AMOUNT', 'SUCCESS_PAYMENTS_COUNT', 'SUCCESS_PAYMENTS_AMOUNT',
                       'FAILED_PAYMENTS_AMOUNT', 'FAILED_PAYMENTS_COUNT', 'NEXT_EXECUTION_DATE', 'LAST_EXECUTION_DATE',
                       'mrn', 'account_number', 'CREATION_DATE', 'LAST_MODIFICATION_DATE']

gw_subscriptions_headers = ['type', 'status', 'status_reason', 'subscription_date', 'subscription_uid']

gw_official_ids_headers = ['type' ,'OFFICIAL_ID_NUMBER' ,'STATUS' ,'CREATION_DATE' ,'ISSUE_DATE' ,'EXPIRY_DATE' ,'ID_ADDRESS' ,'ID_TITLE' ,'IMAGE_FACE' ,'IMAGE_BACK' ,'IMG_FACE_BINAERY' ,'IMG_BACK_BINAERY' ,'FACTORY_NO' ,'PERSON_NAME' ,'FAMILY_NAME' ,'MOTHER_FIRST_NAME' ,'MOTHER_FAMILY_NAME' ,'GOVERNORATE' ,'POLICE_STATION']

loans_headers = ['gateway_pmt_creation_date', 'LoanAmt', 'FCRN']

"""
gw_sof_sql = "select csl.code, bnk.code, ll.code, lln.code, bkr.deactivation_date, bkr.creation_date, " \
             "bkr.last_modification_date, bkr.last_login_date, bkr.cif, uc.code, bkr.credit_card_enabled, " \
             "bkr.login_username, bkr.activation_code, bkr.registration_email, bkr.registration_mobile, bc.code, " \
             "cst.cfn, cst.birth_date, cst.gender, ba.account_number, ba.alias, ba.last_modification_date, bas.code," \
             " mail_cont.value_primary_lang, mail_cont.status_id, mob_cont.value_primary_lang, mob_cont.status_id, cp.code, " \
             "sl.code, cp.user_name, cuc.code, cptl.code, tsl.code, main_acc.code, main_acc.credit_limit, main_acc.balance," \
             " main_acc.daily_limit, main_acc.daily_collected_amount, main_acc.last_debit_date, main_acc.creation_date, " \
             "main_acc.last_modification_date, ul.code,acct.code, main_acc.alias, main_acc.daily_credit_limit, " \
             "mob_trm.terminal_status_id, mob_trm.device_id, mob_trm.pin, mob_trm.code, mob_trm.creation_date, " \
             "portal_trm.terminal_status_id, portal_trm.device_id, portal_trm.pin, portal_trm.code, portal_trm.creation_date, " \
             "mail_contact.contact_value, mail_contact.status_id, mob_contact.contact_value, mob_contact.status_id from " \
             "ebpp_core.bk_registration bkr join ebpp_core.customers cst on bkr.customer_id = cst.id join ebpp_core.bank_accounts " \
             "ba on bkr.id= ba.customer_bank_reg_id join ebpp_core.customer_contacts mob_cont on mob_cont.bk_rg_id = bkr.id " \
             "join ebpp_core.customer_contacts mail_cont on mail_cont.bk_rg_id = bkr.id join ebpp_core.customer_status_lookup " \
             "csl on csl.id = bkr.status_id join ebpp_core.banks bnk on bnk.id = bkr.sender_id join " \
             "EBPP_CORE.languages_lookup ll on ll.id=bkr.preferred_app_lang_id join EBPP_CORE.languages_lookup lln on " \
             "lln.id=bkr.preferred_notification_lang_id join ebpp_core.USER_CATEGORIES uc on uc.id = bkr.user_category_id " \
             "join ebpp_core.bank_channels bc on bc.id = bkr.csp_channel_id join EBPP_CORE.bank_account_status bas on " \
             "bas.id = ba.status_id join pos_sof.customer_profile cp on cp.user_name = bkr.login_username join pos_sof.accounts " \
             "main_acc on cp.id = main_acc.customer_profile_id join pos_sof.terminals portal_trm on portal_trm.pos_terminal_id " \
             "= main_acc.id join pos_sof.terminals mob_trm on mob_trm.pos_terminal_id = main_acc.id join " \
             "POS_SOF.customer_contacts mob_contact on cp.id = mob_contact.customer_profile_id join POS_SOF.customer_contacts " \
             "mail_contact on cp.id = mail_contact.customer_profile_id join pos_sof.STATUS_LOOKUP sl on sl.id = cp.status_id " \
             "join POS_SOF.customer_categories cuc on cuc.id = cp.cust_category_id join POS_SOF.customer_profile_types_lookup " \
             "cptl on cptl.id = cp.customer_profile_types_id join pos_sof.TERMINAL_STATUS_LOOKUP tsl on tsl.id = " \
             "main_acc.terminal_status_id join pos_sof.usage_lookup ul on ul.id = main_acc.usage_id join pos_sof.account_types " \
             "acct on acct.id = main_acc.account_type_id join pos_sof.TERMINAL_STATUS_LOOKUP tslm on tslm.id = " \
             "mob_trm.terminal_status_id join pos_sof.TERMINAL_STATUS_LOOKUP tslp on tslp.id = portal_trm.terminal_status_id " \
             "where ba.bank_account_type_id=2 and ba.alias !='Employee Program' and mob_cont.CUSTOMER_CONTACT_TYPE_ID=3 " \
             "and mail_cont.CUSTOMER_CONTACT_TYPE_ID=4 and main_acc.primary_acct_id is null and " \
             "mob_trm.terminal_type_id = 5 and portal_trm.terminal_type_id = 4 and mail_contact.contact_type_id=2 " \
             "and mob_contact.contact_type_id = 1 and cp.csp_id = 18 and bkr.cif= :cif " \
             "and EXTRACT(MINUTE from bkr.creation_date) = EXTRACT(MINUTE from main_acc.creation_date) " \
             "and EXTRACT(HOUR from bkr.creation_date) = EXTRACT(HOUR from main_acc.creation_date)"
"""
gw_sof_sql = "select csl.code, ba.account_number, bas.code, bc.code, bkr.cif, cst.cfn, uc.code, aml_lkp.code, bkr.credit_card_enabled, bkr.registration_email, bkr.registration_mobile, mail_cont.value_primary_lang, mail_cont.status_id, mob_cont.value_primary_lang, mob_cont.status_id, ll.code, lln.code, bkr.last_login_date, bkr.deactivation_date, bkr.creation_date,  bkr.last_modification_date, bkr.login_username, cst.birth_date, cst.gender, bkr.activation_code, ba.alias, ba.last_modification_date from  ebpp_core.bk_registration bkr join ebpp_core.customers cst on bkr.customer_id = cst.id join ebpp_core.bank_accounts  ba on bkr.id= ba.customer_bank_reg_id join ebpp_core.customer_contacts mob_cont on mob_cont.bk_rg_id = bkr.id  join ebpp_core.customer_contacts mail_cont on mail_cont.bk_rg_id = bkr.id join ebpp_core.customer_status_lookup  csl on csl.id = bkr.status_id join ebpp_core.banks bnk on bnk.id = bkr.sender_id join  EBPP_CORE.languages_lookup ll on ll.id=bkr.preferred_app_lang_id join EBPP_CORE.languages_lookup lln on  lln.id=bkr.preferred_notification_lang_id join ebpp_core.USER_CATEGORIES uc on uc.id = bkr.user_category_id  join ebpp_core.bank_channels bc on bc.id = bkr.csp_channel_id join EBPP_CORE.bank_account_status bas on  bas.id = ba.status_id join ebpp_core.customer_status_lookup aml_lkp on bkr.CUSTOMER_VALIDATION_STATUS = aml_lkp.id where ba.bank_account_type_id=2 and ba.alias !='Employee Program' and mob_cont.CUSTOMER_CONTACT_TYPE_ID=3  and mail_cont.CUSTOMER_CONTACT_TYPE_ID=4 and bkr.cif= :cif and bnk.code = 'MYFAWRY'"

sof_sql = "select cp.code, sl.code, tsl.code, cp.user_name, cuc.code, main_acc.code, main_acc.creation_date, main_acc.last_modification_date, ul.code, acct.code, main_acc.alias from ebpp_core.bk_registration bkr join pos_sof.customer_profile cp on cp.user_name = bkr.login_username join pos_sof.accounts main_acc on cp.id = main_acc.customer_profile_id join pos_sof.terminals portal_trm on portal_trm.pos_terminal_id = main_acc.id join pos_sof.terminals mob_trm on mob_trm.pos_terminal_id = main_acc.id join POS_SOF.customer_contacts mob_contact on cp.id = mob_contact.customer_profile_id join POS_SOF.customer_contacts mail_contact on cp.id = mail_contact.customer_profile_id join pos_sof.STATUS_LOOKUP sl on sl.id = cp.status_id join POS_SOF.customer_categories cuc on cuc.id = cp.cust_category_id join POS_SOF.customer_profile_types_lookup cptl on cptl.id = cp.customer_profile_types_id join pos_sof.TERMINAL_STATUS_LOOKUP tsl on tsl.id = main_acc.terminal_status_id join pos_sof.usage_lookup ul on ul.id = main_acc.usage_id join pos_sof.account_types acct on acct.id = main_acc.account_type_id join pos_sof.TERMINAL_STATUS_LOOKUP tslm on tslm.id = mob_trm.terminal_status_id join pos_sof.TERMINAL_STATUS_LOOKUP tslp on tslp.id = portal_trm.terminal_status_id where main_acc.primary_acct_id is null and mob_trm.terminal_type_id = 5 and portal_trm.terminal_type_id = 4 and mail_contact.contact_type_id=2 and mob_contact.contact_type_id = 1 and cp.csp_id = 18 and bkr.cif= :cif and EXTRACT(MINUTE from bkr.creation_date) = EXTRACT(MINUTE from main_acc.creation_date) and EXTRACT(HOUR from bkr.creation_date) = EXTRACT(HOUR from main_acc.creation_date)"

sof_terminals_sql = "select cp.code, ttl.code, tslp.code, portal_trm.CREATION_DATE, portal_trm.LAST_MODIFICATION_DATE, portal_trm.device_id, portal_trm.pin, portal_trm.code from ebpp_core.bk_registration bkr join pos_sof.customer_profile cp on cp.user_name = bkr.login_username join pos_sof.accounts main_acc on cp.id = main_acc.customer_profile_id join pos_sof.terminals portal_trm on portal_trm.pos_terminal_id = main_acc.id join pos_sof.TERMINAL_STATUS_LOOKUP tsl on tsl.id = main_acc.terminal_status_id join pos_sof.TERMINAL_STATUS_LOOKUP tslp on tslp.id = portal_trm.terminal_status_id join pos_sof.terminal_types_lookup ttl on ttl.id = portal_trm.TERMINAL_TYPE_ID where main_acc.primary_acct_id is null and cp.csp_id = 18 and bkr.cif= :cif and EXTRACT(MINUTE from bkr.creation_date) = EXTRACT(MINUTE from main_acc.creation_date) and EXTRACT(HOUR from bkr.creation_date) = EXTRACT(HOUR from main_acc.creation_date)"

gw_sof_cc_sql = "select bkr.cif, sof_acc.MASKED_CCARD_NUMBER, ba.issuer_bank_id, ba.LAST_FOUR_DIGITS, ba.alias, bas.code gw_status, tsl.code sof_status, batl.code type, ba.creation_date gw_creation_date, sof_acc.creation_date sof_creation_date, ba.last_modification_date, sof_acc.balance, sof_acc.credit_limit, ba.account_number from EBPP_CORE.bk_registration bkr join ebpp_core.bank_accounts BA on bkr.id = ba.customer_bank_reg_id join EBPP_CORE.bank_account_types_lookup  batl on ba.bank_account_type_id = batl.id join ebpp_core.BANK_ACCOUNT_STATUS bas on bas.id = ba.status_id join pos_sof.accounts sof_acc on sof_acc.code = ba.account_number join pos_sof.terminal_status_lookup tsl on tsl.id = sof_acc.terminal_status_id where bkr.cif= :cif and bkr.status_id=1 and (EXTRACT(MINUTE from ba.creation_date) < (EXTRACT(MINUTE from sof_acc.creation_date)+1)) and (EXTRACT(MINUTE from ba.creation_date) > (EXTRACT(MINUTE from sof_acc.creation_date)-1)) and  EXTRACT(HOUR from ba.creation_date) = EXTRACT(HOUR from sof_acc.creation_date) and EXTRACT(DAY from ba.creation_date) = EXTRACT(DAY from sof_acc.creation_date) order by ba.account_number, bas.code, ba.creation_date desc"

mcc_sql = "select t1.user_name, so.csp_code, t1.full_name, t2.fawry_cust_profile_id, t2.fawry_cif_id, t1.msisdn, t1.country_code, t3.notified_mobile_number, t1.email_address, t1.email_status, t2.acc_number, t2.fawry_profile_code, t2.fawry_category_code, t1.last_authentication_date, t1.created_date, t3.first_activation_date, t1.num_failed_trials, t1.num_invalid_activation_trials, t1.active, t2.active, t2.blocked, t3.terminal_status, t3.active, t3.blocked, t1.birth_date, t3.code, t1.default_terminal_code, t3.app_code, t3.force_clear_cache, t1.code, t1.gender from myfawry_mob.sub_user t1  left outer join myfawry_mob.sub_account t2 on t1.account_id = t2.account_id left outer  join myfawry_mob.sub_user_assigned_terminals suat on suat.user_id = t1.user_id left outer  join myfawry_mob.sub_terminal t3 on suat.terminal_id = t3.terminal_id left outer join myfawry_mob.sub_token  t4 on t3.activation_code_id = t4.token_id join myfawry_mob.sub_organization so on so.organization_id = t1.organization_id where t3.terminal_id = (select max(terminal_id) from  myfawry_mob.sub_terminal where terminal_id in ( select terminal_id from MYFAWRY_MOB.sub_user_assigned_terminals  where user_id=t1.user_id)) and t1.msisdn = :msisdn"


pmt_trx_sql = "select * from (select bc.code code, btc.code btc, btc.name_primary_lang, ptl.code pmt_type, b.creation_date bill_creation_date, b.bill_reference_number bill_reference_number,  pml.code pmt_method, psl.code pmt_status, pt.DEBIT_STATUS_CODE DEBIT_STATUS_CODE, epsl.code external_pmt_status, pt.advice_status_code advice_status_code, pt.gateway_pmt_creation_date gateway_pmt_creation_date, pt.debit_creation_date debit_creation_date, pt.fawry_pmt_creation_date fawry_pmt_creation_date, pt.biller_pmt_creation_date biller_pmt_creation_date, pt.bill_amount bill_amount, pt.fees_amount fees_amount, pt.customer_ref_number customer_ref_number, pnl.code pnlcode, pt.request_uid request_uid,pt.EXTERNAL_SOF_CODE EXTERNAL_SOF_CODE, pt.billing_account_number pt_billing_account_number, pt.billing_acct_key_1 billing_acct_key_1, pt.billing_acct_key_2 billing_acct_key_2,  pt.billing_acct_key_3 billing_acct_key_3, pt.user_name user_name, pt.asynchronous_request_uid asynchronous_request_uid, pt.terminal_id terminal_id from ebpp_core.payment_transactions pt join  EBPP_CORE.bk_registration bkr on pt.customer_bk_id = bkr.id join ebpp_core.bill_types btc on btc.id =  pt.bill_type_id join EBPP_CORE.payment_types_lookup ptl on ptl.id = btc.payment_type_id left outer join  EBPP_CORE.bills b on b.id = pt.bill_id left outer join EBPP_CORE.payment_methods_lookup pml on pml.id =  pt.payment_method_id join ebpp_core.payment_status_lookup psl on pt.payment_status_id = psl.id left outer join ebpp_core.payment_status_lookup epsl on epsl.id = pt.EXTERNAL_AUTH_STATUS_ID join  ebpp_core.payment_nature_lookup pnl on pnl.id = pt.payment_nature_id join ebpp_core.bank_channels bc on  bc.id = pt.bank_channel_id where bkr.cif = :cif and bkr.status_id=1 order by pt.gateway_pmt_creation_date desc )where rownum <= 20"

gw_velocity_counters_sql = "select vmtl.code, cvc.value, cvc.creation_date, cvc.last_modification_date, vpm.velocity_period," \
                       " iul.code,vpm.blocking_period, iulb.code from ebpp_core.customer_velocity_counters cvc " \
                       "join ebpp_core.bk_registration bkr on bkr.id = cvc.cust_bnk_reg_id join " \
                       "ebpp_core.velocity_periodic_measure vpm on vpm.id = cvc.velocity_periodic_measure_id join " \
                       "EBPP_CORE.velocity_measure_type_lookup vmtl on vmtl.id = vpm.velocity_measure_type_id left outer join " \
                       "ebpp_core.INTERVAL_UNITS_LOOKUP iulb on vpm.blocking_period_unit_id = iulb.id join " \
                       "ebpp_core.INTERVAL_UNITS_LOOKUP iul on vpm.velocity_period_unit_id = iul.id where bkr.cif=:cif and bkr.status_id=1"

gw_velocity_violations_sql = "select * from (select cust.cfn, vvl.cust_category_code, vvl.velocity_measure_type_code,vvl.velocity_period, vvl.velocity_period_unit,  vvl.criteria_measure_value, vvl.transaction_value, vvl.customer_vel_counter_value,  vvl.action_taken, vvl.violation_logging_time, vvl.bill_type_code, vvl.bank_channel_code,  vvl.account_type, vvl.billing_account, vvl.velocity_error_code from ebpp_core.bk_registration bkr join ebpp_core.customers cust on cust.id = bkr.customer_id left outer join EBPP_CORE.velocity_violations_log vvl on  cust.cfn= vvl.customer_cfn where bkr.cif= :cif and bkr.status_id=1  order by vvl.violation_logging_time desc) where ROWNUM <= 20"

gw_enrollments = "select bkr.cif, enr.alias, esl.code status, btc.code BTC, enr.billing_account_number, enr.billing_acct_key_1, enr.billing_acct_key_2, etl.code enr_type, enr.inquiry_start_date, enr.inquiry_last_date, enr.inquiry_next_date, enr.creation_date, enr.last_modification_date, enr.ern from ebpp_core.bk_registration bkr join ebpp_core.enrollments enr on bkr.id = enr.bk_rg_id join ebpp_core.ENROLLMENT_STATUS_LOOKUP esl on enr.status_id = esl.id join ebpp_core.customers cus on bkr.customer_id = cus.id join ebpp_core.bill_types btc on btc.id = enr.bill_type_id join EBPP_CORE.enrollment_types_lookup etl on enr.enrollment_type_id = etl.id where cif = :cif and bkr.status_id=1"

gw_mandates_sql = "select bkr.cif, enr.alias, pmsl.code, ba.alias cc, pm.start_date, pm.end_date, last_payment_date, next_payment_date, pm.amount_threshold,pm.no_of_repeats, iul.code, pm.FIXED_PAYMENT_AMOUNT, pm.SUCCESS_PAYMENTS_COUNT, pm.SUCCESS_PAYMENTS_AMOUNT, pm.FAILED_PAYMENTS_AMOUNT, pm.FAILED_PAYMENTS_COUNT, pm.NEXT_EXECUTION_DATE, pm.LAST_EXECUTION_DATE, pm.mrn, ba.account_number, pm.CREATION_DATE, pm.LAST_MODIFICATION_DATE from ebpp_core.bk_registration bkr join ebpp_core.enrollments enr on bkr.id = enr.bk_rg_id join ebpp_core.payment_mandates pm on pm.enrollment_id = enr.id join ebpp_core.bank_accounts ba on ba.id = pm.PRIMARY_SOF_ID join ebpp_core.PAYMENT_MANDATE_STATUS_LOOKUP pmsl on pmsl.id = pm.status_id join ebpp_core.MANDATES_TYPES_LOOKUP mtl on mtl.id = pm.MANDATE_TYPE_ID join ebpp_core.INTERVAL_UNITS_LOOKUP iul on iul.id = pm.PAYMENT_PERIOD_UNIT_ID  where cif = :cif and bkr.status_id=1"

gw_subscriptions_sql = "select cs.type, ssl.code, cs.status_reason, cs.creation_date, cs.subscription_uid from ebpp_core.bk_registration bkr join ebpp_core.customer_subscriptions cs on bkr.id = cs.cust_bk_rrg_id join ebpp_core.SUBSCRIPTION_STATUS_LOOKUP ssl on cs.status_id = ssl.id where bkr.cif = :cif"

gw_official_ids_sql = "select cotl.code ,coi.OFFICIAL_ID_NUMBER ,coi.STATUS ,coi.CREATION_DATE ,coi.ISSUE_DATE ,coi.EXPIRY_DATE ,coi.ID_ADDRESS ,coi.ID_TITLE ,coi.IMAGE_FACE ,coi.IMAGE_BACK ,coi.IMG_FACE_BINAERY ,coi.IMG_BACK_BINAERY ,coi.FACTORY_NO ,coi.PERSON_NAME ,coi.FAMILY_NAME ,coi.MOTHER_FIRST_NAME ,coi.MOTHER_FAMILY_NAME ,coi.GOVERNORATE ,coi.POLICE_STATION from ebpp_core.bk_registration bkr join ebpp_core.customers cst on bkr.customer_id = cst.id join ebpp_core.customer_official_ids coi on cst.id = coi.customer_id join ebpp_core.customer_official_types_lookup cotl on coi.official_id_type_id = cotl.id where bkr.cif = :cif"

pmt_trxs_loans_sql = "select * from (select pt.gateway_pmt_creation_date gateway_pmt_creation_date, pted.value LoanAmt, pt.customer_ref_number customer_ref_number from ebpp_core.payment_transactions pt join  EBPP_CORE.bk_registration bkr on pt.customer_bk_id = bkr.id join ebpp_core.pmt_trx_extra_details pted on pt.id = pted.pmt_trx_id where bkr.cif = :cif and bkr.status_id=1 and  pted.key = 'LoanAmt' order by pt.gateway_pmt_creation_date desc )where rownum <= 20"

def get_logged_in_user(request):
    current_user = request.user
    return current_user


def get_ldap_users(user, query, ldap_conn):
    if user.has_perm('auth.search_myfawry_users') == False:
        return "user has no permission to use this function"

    # Provide a search base to search for.
    ldap_base = "cn=internetUsers,cn=users,ou=eBIP,ou=fawry,o=com"
    # provide a uidNumber to search for. '*" to fetch all users/groups
    #query = "(employeeNumber=" + cif + ")"

    # Establish connection to the server

    try:
        # only the attributes specified will be returned
        ldap_conn.search(search_base=ldap_base,
                         search_filter=query,
                         search_scope=SUBTREE,
                         attributes=ldap_params)
        # search will not return any values.
        # the entries method in connection object returns the results
        results = ldap_conn.entries
        return results
    except LDAPException as e:
        print(e.with_traceback())


def form_ldap_entries(user, results):
    if user.has_perm('auth.search_myfawry_users') == False:
        return "user has no permission to use this function"
    table = "<h2>LDAP INFO</h2>\n" + "<table>\n<tr class= 'info-class'>\n"

    for x in range(len(ldap_headers)):
        cell = "<th>" + ldap_headers[x] + "</th>\n"
        table += cell

    table += "</tr>\n"

    for entry in results:
        table += "<tr class= 'info-class'>\n"
        row = ""
        for x in range(len(ldap_params)):
            value = entry[ldap_params[x]]
            try:
                value = str(value)
                cell = "<td>" + value + "</td>\n"
            except (UnicodeDecodeError, AttributeError, TypeError):
                cell = "<td></td>\n"
                pass

            row += cell
        table += row
        table += "</tr>\n"
    table += "</table>"

    return table


def form_table_entries(user, title, gw_sof_headers, results):
    if user.has_perm('auth.search_myfawry_users') == False:
        return "user has no permission to use this function"

    table = "<h2>" + title + "</h2>\n" + "<table>\n<tr class= 'info-class'>\n"

    for x in range(len(gw_sof_headers)):
        cell = "<th>" + gw_sof_headers[x] + "</th>\n"
        table += cell

    table += "</tr>\n"

    for entry in results:
        table += "<tr class= 'info-class'>\n"
        row = ""
        for x in range(len(gw_sof_headers)):
            value = entry[x]
            try:
                cell = "<td>" + str(value) + "</td>\n"
            except TypeError as e:
                cell = "<td>" + str("BLOB") + "</td>\n"
            row += cell
        table += row
        table += "</tr>\n"
    table += "</table>"

    return table


def form_mcc_entries(user, results):
    if user.has_perm('auth.search_myfawry_users') == False:
        return "user has no permission to use this function"

    table = "<h2>MCC INFO</h2>\n" + "<table>\n<tr class= 'info-class'>\n"

    for x in range(len(mcc_headers)):
        cell = "<th>" + mcc_headers[x] + "</th>\n"
        table += cell

    table += "</tr>\n"

    for entry in results:
        table += "<tr class= 'info-class'>\n"
        row = ""
        for x in range(len(mcc_headers)):
            value = entry[x]
            cell = "<td>" + str(value) + "</td>\n"
            row += cell
        table += row
        table += "</tr>\n"
    table += "</table>"

    return table


def form_customer_data_tables(request, cifs, mobiles):
    table = ''
    try:
        with cx_Oracle.connect(
                "EBPP_CORE",
                "Ebpp_C0re2013",
                "10.100.82.62:1551/cnsmrdb",
                encoding='UTF-8') as gw_connection:
            with gw_connection.cursor() as gw_cursor:
                gw_sof_query_rows = []
                sof_query_rows = []
                sof_trm_query_rows = []
                for cif in cifs:
                    gw_cursor.execute(gw_sof_sql, cif=cif)
                    while True:
                        db_row = gw_cursor.fetchone()
                        if db_row is None:
                            break
                        gw_sof_query_rows.append(db_row)

                table += form_table_entries(get_logged_in_user(request), 'GW INFO', gw_sof_headers, gw_sof_query_rows)

                for cif in cifs:
                    gw_cursor.execute(sof_sql, cif=cif)
                    while True:
                        db_row = gw_cursor.fetchone()
                        if db_row is None:
                            break
                        sof_query_rows.append(db_row)

                table += form_table_entries(get_logged_in_user(request), 'SOF INFO', sof_headers, sof_query_rows)

                for cif in cifs:
                    gw_cursor.execute(sof_terminals_sql, cif=cif)
                    while True:
                        db_row = gw_cursor.fetchone()
                        if db_row is None:
                            break
                        sof_trm_query_rows.append(db_row)

                table += form_table_entries(get_logged_in_user(request), 'TERMINAL INFO', sof_terminals_headers,
                                            sof_trm_query_rows)

        with cx_Oracle.connect(
                "MYFAWRY_MOB",
                "MYFAWRY_MOB",
                "10.100.82.42:1555/MFUAT",
                encoding='UTF-8') as mcc_connection:
            with mcc_connection.cursor() as mcc_cursor:
                query_rows = []
                for mobile in mobiles:
                    mcc_cursor.execute(mcc_sql, msisdn=mobile)
                    while True:
                        db_row = mcc_cursor.fetchone()
                        if db_row is None:
                            break
                        query_rows.append(db_row)

                table += form_mcc_entries(get_logged_in_user(request), query_rows)

        with cx_Oracle.connect(
                "EBPP_CORE",
                "Ebpp_C0re2013",
                "10.100.82.62:1551/cnsmrdb",
                encoding='UTF-8') as gw_cc_connection:
            with gw_cc_connection.cursor() as gw_cursor:
                cc_query_rows = []
                enr_query_rows = []
                for cif in cifs:
                    gw_cursor.execute(gw_sof_cc_sql, cif=cif)
                    while True:
                        db_row = gw_cursor.fetchone()
                        if db_row is None:
                            break
                        cc_query_rows.append(db_row)

                table += form_table_entries(get_logged_in_user(request), 'CREDIT CARDS', gw_sof_cc_headers,
                                            cc_query_rows)

                for cif in cifs:
                    gw_cursor.execute(gw_enrollments, cif=cif)
                    while True:
                        db_row = gw_cursor.fetchone()
                        if db_row is None:
                            break
                        enr_query_rows.append(db_row)

                table += form_table_entries(get_logged_in_user(request), 'FAVOURITES', gw_enr_headers, enr_query_rows)

                query_rows = []
                for cif in cifs:
                    gw_cursor.execute(gw_mandates_sql, cif=cif)
                    while True:
                        db_row = gw_cursor.fetchone()
                        if db_row is None:
                            break
                        query_rows.append(db_row)

                table += form_table_entries(get_logged_in_user(request), 'SCHEDULED FAVs', gw_mandates_headers,
                                            query_rows)

                query_rows = []
                for cif in cifs:
                    gw_cursor.execute(gw_subscriptions_sql, cif=cif)
                    while True:
                        db_row = gw_cursor.fetchone()
                        if db_row is None:
                            break
                        query_rows.append(db_row)

                table += form_table_entries(get_logged_in_user(request), 'SUBSCRIPTIONS', gw_subscriptions_headers,
                                            query_rows)

                query_rows = []
                for cif in cifs:
                    gw_cursor.execute(gw_official_ids_sql, cif=cif)
                    while True:
                        db_row = gw_cursor.fetchone()
                        if db_row is None:
                            break
                        query_rows.append(db_row)

                table += form_table_entries(get_logged_in_user(request), 'OFFICIAL IDS', gw_official_ids_headers,
                                            query_rows)

                pmt_query_rows = []
                for cif in cifs:
                    gw_cursor.execute(pmt_trx_sql, cif=cif)
                    while True:
                        db_row = gw_cursor.fetchone()
                        if db_row is None:
                            break
                        pmt_query_rows.append(db_row)
                print(pmt_query_rows)
                table += form_table_entries(get_logged_in_user(request), 'PAYMENTS', gw_pmt_headers, pmt_query_rows)

                query_rows = []
                for cif in cifs:
                    gw_cursor.execute(pmt_trxs_loans_sql, cif=cif)
                    while True:
                        db_row = gw_cursor.fetchone()
                        if db_row is None:
                            break
                        query_rows.append(db_row)
                print(query_rows)
                table += form_table_entries(get_logged_in_user(request), 'Loans',
                                            loans_headers, query_rows)

                vel_query_rows = []
                for cif in cifs:
                    gw_cursor.execute(gw_velocity_counters_sql, cif=cif)
                    while True:
                        db_row = gw_cursor.fetchone()
                        if db_row is None:
                            break
                        vel_query_rows.append(db_row)
                print(vel_query_rows)
                table += form_table_entries(get_logged_in_user(request), 'VELOCITY COUNTERS',
                                            gw_velocity_counters_headers, vel_query_rows)

                query_rows = []
                for cif in cifs:
                    gw_cursor.execute(gw_velocity_violations_sql, cif=cif)
                    while True:
                        db_row = gw_cursor.fetchone()
                        if db_row is None:
                            break
                        query_rows.append(db_row)
                print(query_rows)
                table += form_table_entries(get_logged_in_user(request), 'VELOCITY VIOLATIONS',
                                            velocity_violations_headers, query_rows)

        return table
    except cx_Oracle.Error as error:
        print(error)

