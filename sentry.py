import argparse
import logging
import requests
import json
import os
import sys
import re
import pprint
import hashlib

trim_level = None
with_line_numbers = True
exception_query = None

pp = pprint.PrettyPrinter(indent=2)

sentry_api_token = None

all_issues = []
all_events = []
issues_events_semaphores = []

def parse_paging_links(link_header):
	links = re.split('\s*,\s*', link_header)
	if (len(links) != 2):
		raise('Can not parse previous and next links.')

	prev_raw = links[0]
	next_raw = links[1]

	prev_parts = re.split('\s*;\s*', prev_raw)
	next_parts = re.split('\s*;\s*', next_raw)

	prev_link_raw = prev_parts[0]
	prev_link_flag = prev_parts[2]

	next_link_raw = next_parts[0]
	next_link_flag = next_parts[2]

	if (prev_link_flag == 'results="true"'):
		prev_link = prev_link_raw.strip('<>')
	else:
		prev_link = None

	if (next_link_flag == 'results="true"'):
		next_link = next_link_raw.strip('<>')
	else:
		next_link = None

	return (prev_link, next_link)


def fetch_issues_page(fetch_url=None, page_num=1):
	if not fetch_url:
		fetch_url = 'https://sentry.io/api/0/projects/optimizelycom/www/issues/'

	logging.debug('Fetching issues from page {:>2}.'.format(page_num))
	logging.debug('URL is {}'.format(fetch_url))

	payload = {'query': exception_query}
	auth_headers = {'Authorization': 'Bearer {}'.format(sentry_api_token)}
	issues_resp = requests.get(fetch_url, headers = auth_headers, params=payload)

	if issues_resp.status_code != 200:
		raise ('Failed to get list of issues.')

	issues = issues_resp.json()
	all_issues.extend(issues)

	logging.debug('Fetched {:>3} issues on page {:>2}.'.format(len(issues), page_num))

	prev_link, next_link = parse_paging_links(issues_resp.headers.get('Link'))
	logging.debug('Previous link: {}'.format(prev_link))
	logging.debug('Next     link: {}'.format(next_link))
	if (next_link):
		logging.debug('Checking next page.')
		fetch_issues_page(fetch_url=next_link, page_num=page_num + 1)
	else:
		all_issues_fetched()


def fetch_events_page(issue_id=None, fetch_url=None, page_num=1):
	if not issue_id:
		raise('Can not fetch event without issue ID.')

	if not fetch_url:
		fetch_url = 'https://sentry.io/api/0/issues/{}/events/'.format(issue_id)

	logging.debug('Fetching events for issue {} from page {:>2}.'.format(issue_id, page_num))
	logging.debug('URL is {}'.format(fetch_url))

	auth_headers = {'Authorization': 'Bearer {}'.format(sentry_api_token)}
	events_resp = requests.get(fetch_url, headers = auth_headers)

	if events_resp.status_code != 200:
		raise ('Failed to get list of events.')

	events = events_resp.json()
	all_events.extend(events)
	logging.debug('Fetched {:>3} events on page {:>2}.'.format(len(events), page_num))

	prev_link, next_link = parse_paging_links(events_resp.headers.get('Link'))
	logging.debug('Previous link: {}'.format(prev_link))
	logging.debug('Next     link: {}'.format(next_link))
	if (next_link):
		logging.debug('Checking next page.')
		fetch_events_page(issue_id=issue_id, fetch_url=next_link, page_num=page_num + 1)
	else:
		all_events_fetched(issue_id)

def all_issues_fetched():
	logging.info('Totally fetched {:>4} issues.'.format(len(all_issues)))

	culprits = set()

	with open('issues.json', 'w') as f:
		json.dump(all_issues, f, indent=2)

	for issue in all_issues:
		logging.debug('{:-^100}'.format(' ' + issue['id'] + ' '))
		logging.debug(issue['title'])
		logging.debug(issue['metadata']['type'])
		logging.debug(issue['metadata']['value'])
		logging.debug('We believe the culprit is {}.'.format(issue['culprit']))
		logging.debug('The issue is seen by {:>3} users.'.format(issue['userCount']))
		logging.debug('The issue has {:>3} events.'.format(issue['count']))
		culprits.add(issue['culprit'])
		logging.debug('Fetching {:>5} events for issue {}'.format(issue['count'], issue['id']))
		fetch_events_page(issue_id=issue['id'])

	if (len(culprits) > 0):
		logging.info('All detected culprits:')
		for culprit in culprits:
			logging.info('\t{}'.format(culprit))


def all_events_fetched(issue_id=None):
	if issue_id:
		if issue_id in issues_events_semaphores:
			raise('Duplicated fetch for {}'.format(issue_id))

		issues_events_semaphores.append(issue_id)

		logging.info('Fetched {:>4} events so far, last issue {}.'.format(len(all_events), issue_id))
		logging.info('Processed {:>5} issues of {:>5}'.format(len(issues_events_semaphores), len(all_issues)))

		if (len(issues_events_semaphores) == len(all_issues)):
			logging.info('Totally fetched {:>4} events.'.format(len(all_events)))
			with open('events.json', 'w') as f:
				json.dump(all_events, f, indent=2)
			analyze_all_events()
	else:
		analyze_all_events()


def analyze_all_events():
	logging.info('Totally loaded {:5} issues'.format(len(all_issues)))
	logging.info('Totally loaded {:5} events'.format(len(all_events)))

	events_sources_hashmap = {}
	events_sources_counter = {}
	events_sources_last_lines = set()
	events_sources_commons = {}

	for event in all_events:

		for event_entry in event['entries']:
			if (event_entry['type'] == 'exception'):
				for event_entry_value in event_entry['data']['values']:
					frame_sources = []
					for frame in event_entry_value['stacktrace']['frames']:
						if 'google.appengine' in frame['module']:
							continue
						if 'webapp2' in frame['module']:
							continue
						if with_line_numbers:
							frame_source = '{}:{}:{}'.format(frame['module'], frame['function'], frame['lineNo'])
						else:
							frame_source = '{} in {}'.format(frame['module'], frame['function'])
						frame_sources.append(frame_source)

					# Sorry, too lazy to make it cool. Don't want to spend time on it.
					if trim_level:
						if trim_level == 4:
							if (len(frame_sources) > 3):
								 frame_sources = [frame_sources[-4], frame_sources[-3], frame_sources[-2], frame_sources[-1]]
							elif (len(frame_sources) > 2):
								 frame_sources = [frame_sources[-3], frame_sources[-2], frame_sources[-1]]
							elif (len(frame_sources) > 1):
								frame_sources = [frame_sources[-2], frame_sources[-1]]
							else:
								frame_sources = [frame_sources[-1]]
						elif trim_level == 3:
							if (len(frame_sources) > 2):
								 frame_sources = [frame_sources[-3], frame_sources[-2], frame_sources[-1]]
							elif (len(frame_sources) > 1):
								frame_sources = [frame_sources[-2], frame_sources[-1]]
							else:
								frame_sources = [frame_sources[-1]]
						elif trim_level == 2:
							if (len(frame_sources) > 1):
								frame_sources = [frame_sources[-2], frame_sources[-1]]
							else:
								frame_sources = [frame_sources[-1]]
						elif trim_level == 1:
							frame_sources = [frame_sources[-1]]

					frame_sources_hash = hashlib.md5('::'.join(frame_sources)).hexdigest()

					events_sources_hashmap[frame_sources_hash] = frame_sources

					events_sources_last_lines.add(frame_sources[-1])
					events_sources_commons[frame_sources[-1]] = set(frame_sources)

					if frame_sources_hash not in events_sources_counter:
						events_sources_counter[frame_sources_hash] = 0
					events_sources_counter[frame_sources_hash] += 1

	event_sources_sorted_by_usage = sorted(events_sources_counter.iteritems(), key=lambda (k,v): (v,k))
	for hashkey, counter in event_sources_sorted_by_usage:
		logging.debug('This stacktrace caused the issue {} times:'.format(counter))
		stacktrace = events_sources_hashmap[hashkey]
		last_line = stacktrace[-1]
		for stacktrace_item in stacktrace:
			logging.debug('\t{}'.format(stacktrace_item))
		events_sources_commons[last_line] = events_sources_commons[last_line].intersection(stacktrace)

	logging.info('There are {} different paths that cause this exception.'.format(len(events_sources_hashmap)))
	logging.info('They can be separated into {} different groups.'.format(len(events_sources_commons)))
	for last_line in events_sources_commons:
		logging.debug('Group:')
		common_trace = events_sources_commons[last_line]
		for common_trace_line in common_trace:
			logging.debug('\t{}'.format(common_trace_line))

	most_used_key, most_used_count = event_sources_sorted_by_usage[-1]
	logging.info('The 1st most frequent ({} times) cause of error is:'.format(most_used_count))
	for source_line in events_sources_hashmap[most_used_key]:
		logging.info('\t{}'.format(source_line))

	most_used_key, most_used_count = event_sources_sorted_by_usage[-2]
	logging.info('The 2nd most frequent ({} times) cause of error is:'.format(most_used_count))
	for source_line in events_sources_hashmap[most_used_key]:
		logging.info('\t{}'.format(source_line))

	most_used_key, most_used_count = event_sources_sorted_by_usage[-3]
	logging.info('The 3rd most frequent ({} times) cause of error is:'.format(most_used_count))
	for source_line in events_sources_hashmap[most_used_key]:
		logging.info('\t{}'.format(source_line))



if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="Script to collect stacktraces related to a sentry error")
	parser.add_argument('query', help='String to search list of issues')
	parser.add_argument('--token', help='Sentry API token')
	parser.add_argument('--no-line-numbers', help='Omit line numbers in analysis', action='store_true')
	parser.add_argument('--trim-level', help='How many last lines of stacktrace to process', type=int, choices=[1, 2, 3, 4])
	parser.add_argument('--debug', help='Verbose output mode', action='store_true')
	args = parser.parse_args()

	if not args.token:
		raise Exception('Missing Sentry API token mandatory argument')

	sentry_api_token = args.token

	exception_query = args.query

	logging.getLogger().setLevel(logging.DEBUG if args.debug else logging.INFO)

	logging.debug('The token used is {}.'.format(sentry_api_token))

	if args.no_line_numbers:
		with_line_numbers = False

	if args.trim_level:
		trim_level = args.trim_level

	if os.path.isfile('issues.json'):
		logging.info('Loading list of issues from the file.')
		with open('issues.json', 'r') as f1:
			all_issues = json.load(f1)

		if os.path.isfile('events.json'):
			logging.info('Loading list of events from the file.')
			with open('events.json', 'r') as f2:
				all_events = json.load(f2)
			all_events_fetched();
		else:
			all_issues_fetched()
	else:
		fetch_issues_page()
