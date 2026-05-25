# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from aura_helper import AuraHelper
from datetime import date, datetime, timezone
from colored_logger import init_logger,logger,add_logging_level
import logging
import sys
import os
import argparse
import json
import signal
import secrets
from urllib.parse import parse_qs

# ---------------------------------------------------------------------------
# Database integration — CLI scan results persisted to web DB (SQLite)
# ---------------------------------------------------------------------------

def _db_session():
	"""Return a SQLAlchemy session connected to the shared web database."""
	_src = os.path.dirname(os.path.abspath(__file__))
	if _src not in sys.path:
		sys.path.insert(0, _src)
	from web.database import SessionLocal, init_db  # noqa: PLC0415
	init_db()
	return SessionLocal()


def _db_get_or_create_user(username: str):
	"""
	Return the DB User for *username*.
	If no matching user exists, create a locked CLI-only account and log the fact.
	Returns (user_id, created: bool).
	"""
	from web.database import User  # noqa: PLC0415
	from web.auth import hash_password  # noqa: PLC0415

	db = _db_session()
	try:
		user = db.query(User).filter(User.username == username).first()
		if user:
			logger.info(f"[DB] Using existing user '{username}' (id={user.id})")
			return user.id, False

		# New user — generate a locked random password (CLI users log in via web)
		email = f'{username}@cli.local'
		locked_pw = secrets.token_hex(24)
		user = User(
			username=username,
			email=email,
			hashed_password=hash_password(locked_pw),
			is_admin=False,
		)
		db.add(user)
		db.commit()
		db.refresh(user)
		logger.info(f"[DB] Created new CLI user '{username}' (id={user.id}, email={email})")
		return user.id, True
	finally:
		db.close()


def _db_create_scan_job(user_id: int, url: str, scan_type: str,
                        app_path: str | None, aura_path: str | None,
                        proxy: str | None) -> int:
	"""Insert a ScanJob row with status='running' and return its id."""
	from web.database import ScanJob  # noqa: PLC0415

	db = _db_session()
	try:
		job = ScanJob(
			user_id=user_id,
			target_url=url,
			scan_type=scan_type,
			app_path=app_path,
			aura_path=aura_path,
			proxy=proxy,
			status='running',
		)
		db.add(job)
		db.commit()
		db.refresh(job)
		logger.info(f"[DB] Scan job created (id={job.id})")
		return job.id
	finally:
		db.close()


# Severity heuristics — objects that warrant elevated risk ratings
_HIGH_SEVERITY_OBJECTS  = {'User', 'ContentDocument', 'ContentVersion', 'Contact', 'Lead', 'Account', 'Case'}
_MEDIUM_SEVERITY_OBJECTS = {'ContentWorkspace', 'EntityDefinition', 'Profile', 'RecordType',
                             'LiveChatButton', 'Calendar', 'Event', 'StaticResource', 'ProcessDefinition'}


def _object_severity(obj_name: str, record_count: int) -> str:
	if obj_name in _HIGH_SEVERITY_OBJECTS:
		return 'high'
	if obj_name in _MEDIUM_SEVERITY_OBJECTS or record_count > 500:
		return 'medium'
	if record_count > 0:
		return 'low'
	return 'info'


def _db_persist_results(scan_job_id: int, scan_data: dict, aura) -> None:
	"""
	Convert raw CLI scan_data into Finding rows and mark the ScanJob completed.
	"""
	from web.database import Finding, ScanJob  # noqa: PLC0415

	all_records     = scan_data.get('all_records', {})
	all_records_gql = scan_data.get('all_records_gql', {})
	recordlists     = scan_data.get('recordlists', [])
	custom_ctrl     = scan_data.get('custom_controllers', [])

	db = _db_session()
	try:
		findings = []

		# Standard Aura API exposed objects
		for obj_name, info in all_records.items():
			count = info.get('total_count', 0) if isinstance(info, dict) else 0
			sev   = _object_severity(obj_name, count)
			findings.append(Finding(
				scan_job_id  = scan_job_id,
				scanner      = 'IDORScanner',
				title        = f'Guest-accessible Salesforce object: {obj_name}',
				severity     = sev,
				description  = (
					f'The Salesforce object "{obj_name}" is accessible via the Aura API '
					f'without authentication. {count} record(s) were retrieved.'
				),
				evidence     = f'Object: {obj_name}, Records: {count}',
				remediation  = (
					f'Remove Read access for "{obj_name}" from the Experience Cloud '
					f'Guest User Profile. Review field-level security and sharing rules.'
				),
				owasp_ref    = 'API1:2023',
				affected_objects = [obj_name],
			))

		# GraphQL-only exposed objects
		gql_only = {k: v for k, v in all_records_gql.items() if k not in all_records}
		for obj_name, info in gql_only.items():
			count = info.get('total_count', 0) if isinstance(info, dict) else 0
			sev   = _object_severity(obj_name, count)
			findings.append(Finding(
				scan_job_id  = scan_job_id,
				scanner      = 'AuraFuzzer',
				title        = f'GraphQL uiapi exposure: {obj_name}',
				severity     = sev,
				description  = (
					f'"{obj_name}" is readable via GraphQL (uiapi) by unauthenticated guests. '
					f'{count} record(s) accessible.'
				),
				evidence     = f'GraphQL Object: {obj_name}, Records: {count}',
				remediation  = (
					f'Remove Read access for "{obj_name}" from the Guest User Profile '
					f'or disable Lightning Data Service for guest users.'
				),
				owasp_ref    = 'API5:2023',
				affected_objects = [obj_name],
			))

		# Exposed record-list URLs
		for url in recordlists:
			findings.append(Finding(
				scan_job_id  = scan_job_id,
				scanner      = 'AuraFuzzer',
				title        = 'Exposed UI record list URL accessible to guests',
				severity     = 'low',
				description  = 'A browseable record list URL was discovered that may render records for unauthenticated users.',
				evidence     = url,
				remediation  = 'Restrict the list view or remove the public page. Verify in an incognito window.',
				owasp_ref    = 'API1:2023',
				affected_objects = [],
			))

		# Custom Apex controllers
		for ctrl in custom_ctrl:
			findings.append(Finding(
				scan_job_id  = scan_job_id,
				scanner      = 'ApexScanner',
				title        = f'Custom Apex controller accessible: {ctrl}',
				severity     = 'high',
				description  = f'Custom Apex controller "{ctrl}" is accessible via the Aura API.',
				evidence     = f'Controller: {ctrl}',
				remediation  = 'Audit controller for system-mode execution and data exposure. Apply with sharing.',
				owasp_ref    = 'API5:2023',
				affected_objects = [ctrl],
			))

		# SOAP API enabled finding
		if getattr(aura, 'soap_enabled', False):
			findings.append(Finding(
				scan_job_id  = scan_job_id,
				scanner      = 'AuraFuzzer',
				title        = 'SOAP API is enabled',
				severity     = 'medium',
				description  = 'The Salesforce SOAP API endpoint is reachable. This enables credential-based brute-force attacks.',
				evidence     = f'{aura.url}/services/Soap/',
				remediation  = 'Disable SOAP API for guest contexts or restrict via IP allowlist.',
				owasp_ref    = 'API8:2023',
				affected_objects = [],
			))

		db.add_all(findings)

		# Calculate risk score: weighted by severity
		weights = {'high': 25, 'medium': 10, 'low': 3, 'info': 0}
		risk = min(100, sum(weights.get(f.severity, 0) for f in findings))

		job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
		if job:
			job.status       = 'completed'
			job.risk_score   = risk
			job.completed_at = datetime.now(timezone.utc)

		db.commit()
		logger.info(f"[DB] Persisted {len(findings)} finding(s) for scan job {scan_job_id} (risk={risk})")

	except Exception:
		db.rollback()
		logger.error('[DB] Failed to persist scan results', exc_info=True)
		try:
			job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
			if job:
				job.status = 'failed'
				db.commit()
		except Exception:
			pass
	finally:
		db.close()


def is_authenticated_scan(cookies=None, context=None, token="null"):
	return cookies is not None or context is not None or token not in [None, '', 'null']


def validate_output_dir(output_dir, authenticated_mode, allow_unsafe_output):
	if not output_dir:
		return output_dir

	normalized_output_dir = os.path.abspath(output_dir)
	if authenticated_mode:
		logger.warning('Authenticated scan output may contain sensitive metadata. Store it in a protected location and delete it when no longer needed.')
		repo_root = os.path.abspath(os.getcwd())
		try:
			inside_repo = os.path.commonpath([repo_root, normalized_output_dir]) == repo_root
		except ValueError:
			inside_repo = False
		if inside_repo and not allow_unsafe_output:
			logger.error('Authenticated scan output inside the current repository is blocked by default. Use --allow-unsafe-output to override.')
			exit()
	return normalized_output_dir


def parse_named_argument(value, option_name):
	if '=' not in value:
		logger.error(f'{option_name} must use the format name=value')
		exit()
	name, parsed_value = value.split('=', 1)
	if not name.strip() or not parsed_value.strip():
		logger.error(f'{option_name} must use the format name=value')
		exit()
	return name.strip(), parsed_value.strip()


def summarize_scan(scan_name, all_objects, all_records, all_records_gql):
	record_counts = {object_name: record_info['total_count'] for object_name, record_info in all_records.items()}
	return {
		'name': scan_name,
		'object_count': len(all_objects),
		'retrievable_objects': sorted(all_records.keys()),
		'gql_objects': sorted(all_records_gql.keys()),
		'nonzero_record_objects': sorted([object_name for object_name, total_count in record_counts.items() if total_count != 0]),
		'record_counts': record_counts
	}


def collect_audit_data(url, cookies, object_list, proxy, fetch_max_data=False, insecure=False, app=None, aura_path="/aura", context=None, token="null", no_gql=False):

	aura = AuraHelper(url=url, cookies=cookies, proxy=proxy, insecure=insecure, app=app, aura=aura_path, context=context, token=token)

	# Check for self-registration
	aura.check_self_registration_enabled()
	aura.check_rest_api_enabled()
	aura.check_soap_api_enabled()
	if not no_gql:
		aura.check_graphql_enabled()

	custom_controllers = aura.get_custom_controllers()

	# Get all Salesforce Objects and CSP trusted list
	all_objects = aura.get_objects()
	objects = all_objects
	if object_list:
		all_objects_lower = [x.lower() for x in all_objects]
		valid_objects = [x for x in object_list if x.lower() in all_objects_lower]
		invalid_objects = [x for x in object_list if x.lower() not in all_objects_lower]
		if valid_objects:
			objects = valid_objects
			logger.info(f'Targeting valid objects provided: {",".join(valid_objects)}')
		else:
			logger.error('No valid objects provided with -l')
			exit()
		if invalid_objects:
			logger.warning(f'Ignoring invalid objects: {",".join(invalid_objects)}')
	if objects is None:
		logger.error('Could not find any objects')
		exit()

	all_records = []
	all_records_gql = []
	if not fetch_max_data:
		# Get records of all objects
		all_records = aura.get_records(objects)
		if aura.gql_enabled:
			all_records_gql = aura.get_records_graphql(objects, records_per_action=100, fetch_all=False)
	all_ui_lists = dict()


	# Get UI list for records
	recordlists = aura.get_records_ui_list(objects)

	home_urls = aura.get_object_home_urls()

	return {
		'aura': aura,
		'all_objects': all_objects,
		'all_records': all_records,
		'all_records_gql': all_records_gql,
		'recordlists': recordlists,
		'home_urls': home_urls,
		'custom_controllers': custom_controllers
	}


def save_audit_data(scan_data, output_dir):
	aura = scan_data['aura']
	write_records_to_directory(scan_data['all_records'], output_dir, "records")
	write_records_to_directory(scan_data['all_records_gql'], output_dir, "gql_records")
	write_misc_to_directory(scan_data['recordlists'], output_dir, sub_dir='misc',file_name='recordlists.json')
	write_misc_to_directory(scan_data['home_urls'], output_dir, sub_dir='misc',file_name='homeurls.json')
	write_misc_to_directory(aura.csp_trusted, output_dir, sub_dir='misc',file_name='csp_trusted_sites.json')
	write_misc_to_directory(scan_data['custom_controllers'], output_dir, sub_dir='misc',file_name='custom_controllers.json')
	logger.info(f'Please check the {output_dir} folder for retrieved records, object home URLs and records UI list record URLs')
	logger.warning('The object home URLs and records UI list need to be checked manually at the moment to verify whether any sensitive data or panel is available')


def audit(url, cookies, object_list, output_dir, proxy, fetch_max_data=False, insecure=False, app=None, aura_path="/aura", context=None, token="null", no_gql=False, authenticated_mode=False, allow_save_prompt=True, scan_name='default'):

	scan_data = collect_audit_data(url=url, cookies=cookies, object_list=object_list, proxy=proxy, fetch_max_data=fetch_max_data, insecure=insecure, app=app, aura_path=aura_path, context=context, token=token, no_gql=no_gql)
	aura = scan_data['aura']
	all_records = scan_data['all_records']
	all_records_gql = scan_data['all_records_gql']
	
	print('')
	print('--- Summary ---')
	print(draw_table(all_records))
	print('')
	if aura.gql_enabled:
		print('--- Summary GraphQL ---')
		print(draw_table(all_records_gql))
		print('')

	if not output_dir:
		if authenticated_mode:
			logger.warning('Authenticated scan results were not saved. Pass -o with a protected directory if you need to persist them.')
		elif allow_save_prompt:
			while True:
				is_save = input('Would you like to save the results? (y/N): ')
				if is_save == 'y':
					output_dir = input('Please specify the relative or full path to directory you would like to save the results to: ')
					logger.info(f'Results have been saved to: {output_dir}')
					break
				elif is_save == 'N':
					logger.warning('Results were not saved')
					break
				else:
					logger.warning('Invalid choice, try again')

	if output_dir:
		save_audit_data(scan_data, output_dir)

	summary = summarize_scan(scan_name, scan_data['all_objects'], all_records, all_records_gql)
	return {**summary, 'scan_data': scan_data}


def write_records_to_directory(all_records, parent_dir, sub_dir):
	
	if len(all_records) == 0:
		return

	path_to_write = os.path.join(parent_dir, sub_dir)
	os.makedirs(path_to_write, exist_ok=True)

	logger.info(f'Writing record information to {path_to_write}')
	with open(os.path.join(path_to_write, f'summary.txt'), 'w') as f:
		f.write(draw_table(all_records))


def write_misc_to_directory(obj_to_write, parent_dir, sub_dir='misc', file_name=''):
	
	if len(obj_to_write) == 0:
		return

	path_to_write = os.path.join(parent_dir,sub_dir)
	os.makedirs(path_to_write, exist_ok=True)

	file_to_write = os.path.join(path_to_write, file_name)

	logger.info(f'Writing miscellaneous to {file_to_write}')

	with open(f'{file_to_write}', 'w') as f:
		json.dump(obj_to_write, f)

def draw_table(records):
	record_count = [
		[
			'Object Name',
			'Total Count'
		]
	]
	col_width = 15
	for object_name in records:
		retrievable = records[object_name]['total_count']
		if retrievable == 0:
			continue
		col_width = max(col_width,len(object_name)+1)
		record_count.append(
			[
				object_name,
				retrievable if retrievable != -1 else 'Unknown'
			]
        )
	table = ''
	for row_index in range(len(record_count)):
		table += ''.join(f'{x:<{col_width}}' for x in record_count[row_index]) + '\n'
	return table


def build_compare_report(persona_summaries):
	baseline = persona_summaries[0]
	comparisons = []
	baseline_retrievable = set(baseline['retrievable_objects'])
	baseline_gql = set(baseline['gql_objects'])
	for current in persona_summaries[1:]:
		current_retrievable = set(current['retrievable_objects'])
		current_gql = set(current['gql_objects'])
		increased_record_counts = {}
		for object_name, total_count in current['record_counts'].items():
			baseline_total_count = baseline['record_counts'].get(object_name)
			if total_count in [-1, None] or baseline_total_count in [-1, None]:
				continue
			if baseline_total_count is not None and total_count > baseline_total_count:
				increased_record_counts[object_name] = {
					'baseline': baseline_total_count,
					'current': total_count
				}
		comparisons.append({
			'persona': current['name'],
			'new_retrievable_objects': sorted(current_retrievable - baseline_retrievable),
			'new_gql_objects': sorted(current_gql - baseline_gql),
			'increased_record_counts': increased_record_counts
		})
	return {
		'baseline': baseline['name'],
		'comparisons': comparisons
	}


def print_compare_report(compare_report):
	print('--- Persona Compare ---')
	print(f'Baseline persona: {compare_report["baseline"]}')
	for comparison in compare_report['comparisons']:
		print('')
		print(f'Persona: {comparison["persona"]}')
		print(f'New retrievable objects: {len(comparison["new_retrievable_objects"])}')
		if comparison['new_retrievable_objects']:
			print(','.join(comparison['new_retrievable_objects']))
		print(f'New GraphQL objects: {len(comparison["new_gql_objects"])}')
		if comparison['new_gql_objects']:
			print(','.join(comparison['new_gql_objects']))
		print(f'Objects with increased record counts: {len(comparison["increased_record_counts"])}')


def run_compare_mode(args, object_list, guest_url, guest_app):
	persona_summaries = []
	if args.compare_with_guest:
		guest_summary = audit(
			guest_url,
			cookies=None,
			object_list=object_list,
			output_dir=None,
			proxy=args.proxy,
			insecure=args.insecure,
			app=guest_app,
			aura_path=args.aura,
			context=None,
			token='null',
			no_gql=args.no_gql,
			authenticated_mode=False,
			allow_save_prompt=False,
			scan_name='guest'
		)
		persona_summaries.append(guest_summary)

	for persona_request in args.persona_request_file:
		persona_name, request_file = parse_named_argument(persona_request, '--persona-request-file')
		logger.warning(f'Persona request file {request_file} contains live auth material. Store it securely and delete it when no longer needed.')
		parsed_http_req = parse_http_request_file(request_file)
		persona_summaries.append(audit(
			parsed_http_req['url'],
			cookies=parsed_http_req['cookies'],
			object_list=object_list,
			output_dir=None,
			proxy=args.proxy,
			insecure=args.insecure,
			app=guest_app,
			aura_path=parsed_http_req['aura_endpoint'],
			context=parsed_http_req['context'],
			token=parsed_http_req['token'],
			no_gql=args.no_gql,
			authenticated_mode=True,
			allow_save_prompt=False,
			scan_name=persona_name
		))

	compare_report = build_compare_report(persona_summaries)
	print('')
	print_compare_report(compare_report)
	if args.output_dir:
		write_misc_to_directory(compare_report, args.output_dir, sub_dir='compare', file_name='persona_compare.json')

def parse_http_request_file(http_req_file):

	http_request = ''

	with open(http_req_file, 'r') as req_file:
		http_request = [l.strip() for l in req_file.readlines()]

	request_line = http_request[0]
	aura_endpoint = request_line.split(" ")[1]

	if "?" in aura_endpoint:
		aura_endpoint = aura_endpoint.split("?", 1)[0]

	if not ('aura' in aura_endpoint and 'POST' in request_line) :
		logger.warning('Request file does not appear to be a POST request to aura!')

	headers = {}

	# We only need the Host and Cookie headers
	for line in http_request[1:]:

		# If the line is empty, it marks the end of headers
		if line.strip() == '':
			break

		# Split the line into key and value
		key, value = line.split(':', 1)
		if key.lower().strip() == 'host':
			headers['host'] = value.strip()
		elif key.lower().strip() == 'cookie':
			headers['cookies'] = value.strip()
		else:
			continue

	body = parse_qs(http_request[-1])

	aura_context = body['aura.context'][0]
	parsed_context = json.loads(aura_context)

	aura_token = body['aura.token'][0]

	result = {
		'url':'https://' + headers['host'],
		'cookies': headers['cookies'],
		'context':aura_context,
		'aura_endpoint':aura_endpoint,
		'token':aura_token
	}

	return result

def main():

	parser = argparse.ArgumentParser(prog="python3 aura_cli.py")
	parser.add_argument("-U", "--username", help="Username to associate this scan with (looked up or created in the web DB)", required=True)
	parser.add_argument("-u", "--url", help="Root URL of Salesforce application to audit")
	parser.add_argument("-c", "--cookies", help="Cookies after authenticating to Salesforce application", default=None)
	parser.add_argument("-o", "--output-dir", help="Output directory", default=None)
	parser.add_argument("-l", "--object-list", help="Pull data of only the provided objects. Comma separated list of objects.", type=str, default=None)
	parser.add_argument("-d", "--debug", help="Print debug information", action="store_const", const=True, default=False)
	parser.add_argument("-v", "--verbose", help="Print verbose information", action="store_const", const=True, default=False)
	parser.add_argument("-p", "--proxy", help="Proxy requests", default=None)
	parser.add_argument("-k","--insecure", help="Ignore invalid TLS certificates", action="store_true")
	parser.add_argument("--app", help="Provide the target salesforce app's path (e.g: /myApp), the script will try to detect it if not provided")
	parser.add_argument("--aura", help="Provide the target salesforce aura's path (e.g: /aura), the script will try to detect it if not provided")
	parser.add_argument("--context", help="Provide a context to be used as aura.context in POST requests, the script will use a dummy one if not provided")
	parser.add_argument("--token", help="Provide an aura token to be used as aura.token in POST requests, the script will use a dummy one if not provided")
	parser.add_argument("--no-gql", help="Do not check for GraphQL capability and do not use it", action="store_true")
	parser.add_argument("--no-banner", help="Do not display banner", action="store_true")
	parser.add_argument("-r", "--aura-request-file", help="Provide a request file to an /aura endpoint")
	parser.add_argument("--allow-insecure-auth", help="Allow authenticated scans to run with -k/--insecure", action="store_true")
	parser.add_argument("--allow-unsafe-output", help="Allow authenticated scan output to be written inside the current repository", action="store_true")
	parser.add_argument("--compare-with-guest", help="Include a guest persona as the baseline when using --persona-request-file", action="store_true")
	parser.add_argument("--persona-request-file", help="Compare mode persona definition in the form name=path-to-aura-request-file", action="append", default=[])

	args = parser.parse_args()

	if len(sys.argv[1:]) == 0:
		parser.print_help()
		exit()

	add_logging_level('VERBOSE', 15)
	init_logger(logging.DEBUG if args.debug else logging.VERBOSE if args.verbose else logging.INFO)

	banner = r'''
    _                   ___                           _
   / \  _   _ _ __ __ _|_ _|_ __  ___ _ __   ___  ___| |_ ___  _ __
  / _ \| | | | '__/ _` || || '_ \/ __| '_ \ / _ \/ __| __/ _ \| '__|
 / ___ \ |_| | | | (_| || || | | \__ \ |_) |  __/ (__| || (_) | |
/_/   \_\__,_|_|  \__,_|___|_| |_|___/ .__/ \___|\___|\__\___/|_|
                                     |_|
	'''
	if not args.no_banner:
		logger.warning(banner)

	url = args.url	
	app = args.app
	cookies = args.cookies
	aura = args.aura
	token = args.token
	context = args.context
	compare_mode = len(args.persona_request_file) > 0

	# If request file exists, parse it and ignore the url
	if args.aura_request_file:
		logger.warning(f'Aura request file {args.aura_request_file} contains live auth material. Store it securely and delete it when no longer needed.')
		parsed_http_req = parse_http_request_file(args.aura_request_file)
		
		url = parsed_http_req['url']
		aura = parsed_http_req['aura_endpoint']
		context = parsed_http_req['context']
		cookies = parsed_http_req['cookies']
		token = parsed_http_req['token']
	else:
		if url is None:
			logger.error('Specify a URL or a request file')
			exit()

		if url.endswith('/'):
			url = url[:-1] 

		if url.endswith('/s'):
			logger.warning('URL contains the /s path which is usually not the root, if this does not work try providing the URL without the /s')

	if app and app == "/":
		app = "/s"

	object_list = args.object_list
	if object_list:
		object_list = [str(obj) for obj in object_list.split(",")]

	if compare_mode and (args.cookies or args.aura_request_file or args.context or args.token not in [None, '', 'null']):
		logger.error('Compare mode uses --persona-request-file entries instead of -c, -r, --context, or --token.')
		exit()

	if compare_mode and not args.compare_with_guest and len(args.persona_request_file) < 2:
		logger.error('Compare mode requires at least two --persona-request-file values, or one persona plus --compare-with-guest.')
		exit()

	if compare_mode and args.compare_with_guest and url is None:
		logger.error('Compare mode with --compare-with-guest requires -u/--url for the guest baseline.')
		exit()

	authenticated_mode = is_authenticated_scan(cookies=cookies, context=context, token=token) or compare_mode
	if authenticated_mode and args.insecure and not args.allow_insecure_auth:
		logger.error('Authenticated scans cannot be combined with -k/--insecure by default. Use --allow-insecure-auth to override.')
		exit()

	args.output_dir = validate_output_dir(args.output_dir, authenticated_mode, args.allow_unsafe_output)

	if compare_mode:
		run_compare_mode(args, object_list, url, app)
		return

	# ── DB: resolve user ──────────────────────────────────────────────────
	user_id, created = _db_get_or_create_user(args.username)
	if created:
		logger.warning(f"[DB] New CLI user '{args.username}' registered. Log in at http://localhost:8080 to view scan history.")

	scan_type = 'auth' if authenticated_mode else 'guest'
	scan_job_id = _db_create_scan_job(
		user_id   = user_id,
		url       = url,
		scan_type = scan_type,
		app_path  = app,
		aura_path = aura,
		proxy     = args.proxy,
	)

	# ── Run scan ──────────────────────────────────────────────────────────
	result = audit(url, cookies=cookies,
		object_list=object_list,
		output_dir=args.output_dir,
		proxy=args.proxy,
		insecure=args.insecure,
		app=app,
		aura_path=aura,
		context=context,
		token=token,
		no_gql=args.no_gql,
		authenticated_mode=authenticated_mode,
	)

	# ── DB: persist results ───────────────────────────────────────────────
	if result is not None:
		raw = result.get('scan_data')
		if raw:
			_db_persist_results(scan_job_id, raw, raw.get('aura'))
			logger.info(f"[DB] Scan results saved — view at http://localhost:8080/scans/{scan_job_id}")
		logger.info(f"[DB] Scan results saved — view at http://localhost:8080/scans/{scan_job_id}")

if __name__ == "__main__":
    main()
